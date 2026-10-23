"""Semgrep integration wrapper for PatchPilot.

Dispatches static analysis and taint tracking to the open-source Semgrep CLI
using `subprocess.Popen`, parses Semgrep's structured JSON output format, and
normalizes the results into PatchPilot's unified `Finding` model.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .masking import redact_text
from .models import Confidence, Finding, FindingKind, Severity, SourceFile

log = logging.getLogger("patchpilot.semgrep")

SNIPPET_CONTEXT = 2


def is_semgrep_available() -> bool:
    """Check if the semgrep CLI executable is present in PATH or environment."""
    custom_bin = os.getenv("SEMGREP_BIN")
    if custom_bin and os.path.isfile(custom_bin):
        return True
    return shutil.which("semgrep") is not None


def map_semgrep_severity(raw_severity: str) -> Severity:
    """Map Semgrep's severity string (ERROR, WARNING, INFO) to PatchPilot's Severity."""
    s = raw_severity.upper()
    if s in ("ERROR", "CRITICAL"):
        return "high"  # mapped to high or critical depending on rule
    if s == "WARNING":
        return "medium"
    if s == "INFO":
        return "low"
    return "medium"


def map_semgrep_confidence(metadata: dict[str, Any]) -> Confidence:
    """Map Semgrep metadata confidence to PatchPilot's Confidence model."""
    raw = str(metadata.get("confidence", "")).lower()
    if raw in ("high", "medium", "low"):
        return raw  # type: ignore
    return "medium"


def _extract_cwe(metadata: dict[str, Any]) -> str | None:
    """Extract CWE reference from Semgrep metadata tags."""
    cwes = metadata.get("cwe")
    if isinstance(cwes, list) and cwes:
        first = str(cwes[0])
        # Format might be 'CWE-89: SQL Injection' -> 'CWE-89'
        return first.split(":")[0].strip()
    if isinstance(cwes, str) and cwes:
        return cwes.split(":")[0].strip()
    return None


def parse_semgrep_output(output_json: str | dict[str, Any], project_files: dict[str, SourceFile]) -> list[Finding]:
    """Parse Semgrep JSON output dictionary and map each result to a unified Finding."""
    if isinstance(output_json, str):
        try:
            data = json.loads(output_json)
        except Exception as e:
            log.warning("Failed parsing Semgrep output JSON: %s", e)
            return []
    else:
        data = output_json

    results = data.get("results", [])
    findings: list[Finding] = []

    for item in results:
        check_id = item.get("check_id", "SEMGREP-RULE")
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})

        # File path relative to project
        raw_path = item.get("path", "")
        norm_path = raw_path.replace("\\", "/").lstrip("./")

        # Line numbers
        start = item.get("start", {})
        line_no = start.get("line", 1)

        # Message and descriptions
        message = extra.get("message", "").strip() or check_id
        short_title = check_id.rsplit(".", 1)[-1].replace("-", " ").title()
        category = metadata.get("category", "Taint Analysis")

        # Severity & Confidence
        raw_sev = extra.get("severity", "WARNING")
        # Escalate high impact rules if marked critical
        if metadata.get("impact", "").upper() == "HIGH" and raw_sev.upper() == "ERROR":
            severity: Severity = "critical"
        else:
            severity = map_semgrep_severity(raw_sev)

        confidence = map_semgrep_confidence(metadata)
        kind: FindingKind = "confirmed" if confidence == "high" else "heuristic"

        # Code snippet and line text
        lines = extra.get("lines", "")
        source_file = project_files.get(norm_path)
        if source_file and 0 < line_no <= len(source_file.lines):
            line_text = source_file.lines[line_no - 1]
            s_start = max(0, line_no - 1 - SNIPPET_CONTEXT)
            s_end = min(len(source_file.lines), line_no + SNIPPET_CONTEXT)
            snippet = redact_text("\n".join(source_file.lines[s_start:s_end]))
        else:
            line_text = lines.splitlines()[0] if lines else ""
            snippet = redact_text(lines)

        evidence = redact_text(f"Semgrep: {message}")
        impact = metadata.get("impact", "Potential security vulnerability identified through deep taint tracking.")
        remediation = metadata.get("fix", "Review data flows from untrusted inputs and sanitize before reaching sinks.")
        cwe = _extract_cwe(metadata)

        findings.append(Finding(
            rule_id=f"SG-{check_id.rsplit('.', 1)[-1]}",
            title=f"[Semgrep] {short_title}",
            category=category,
            description=message,
            severity=severity,
            confidence=confidence,
            kind=kind,
            file=norm_path,
            line=line_no,
            snippet=snippet,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            cwe=cwe,
            origin="source",
            line_text=redact_text(line_text.strip())[:300],
        ).finalize())

    return findings


def run_semgrep_on_directory(
    directory: str | Path,
    config: str = "auto",
    project_files: dict[str, SourceFile] | None = None,
    timeout_seconds: int = 120,
) -> list[Finding]:
    """Execute Semgrep CLI using subprocess.Popen on the target source directory.

    Args:
        directory: Root path of the directory containing source files.
        config: Semgrep rule config (e.g. 'auto', 'p/security-audit', or local rules path).
        project_files: Map of relative file paths to SourceFile objects.
        timeout_seconds: Maximum execution time before terminating the process.

    Returns:
        List of findings unified into PatchPilot's schema.
    """
    semgrep_bin = os.getenv("SEMGREP_BIN") or shutil.which("semgrep") or "semgrep"

    # Validate config against argument injection
    import re
    if not re.fullmatch(r"[A-Za-z0-9_./\-:]+", config):
        log.warning("Invalid semgrep config '%s' requested; falling back to 'auto'.", config)
        config = "auto"

    cmd = [
        semgrep_bin,
        "scan",
        f"--config={config}",
        "--json",
        "--quiet",
        "--no-git-ignore",
        str(directory),
    ]

    log.info("Launching Semgrep process: %s", " ".join(cmd[:3]))

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
    except FileNotFoundError:
        log.warning("Semgrep executable not found at '%s'. Skipping Semgrep analysis.", semgrep_bin)
        return []
    except Exception as e:
        log.error("Failed to start Semgrep process: %s", e)
        return []

    try:
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        log.warning("Semgrep process timed out after %ds and was terminated.", timeout_seconds)
        return []

    if proc.returncode not in (0, 1):  # Semgrep exits with 0 (no findings) or 1 (findings detected)
        log.warning("Semgrep exited with code %d. Stderr: %s", proc.returncode, stderr[:300])

    if not stdout.strip():
        return []

    return parse_semgrep_output(stdout, project_files or {})


def run_semgrep_on_files(files: list[SourceFile], config: str = "auto") -> list[Finding]:
    """Helper to run Semgrep on an in-memory list of SourceFiles by staging them

    into a temporary directory and invoking the CLI runner.
    """
    if not is_semgrep_available():
        return []

    file_map = {f.path: f for f in files}
    with tempfile.TemporaryDirectory(prefix="patchpilot_sg_") as tmp_dir:
        root = Path(tmp_dir)
        for sf in files:
            p = (root / sf.path).resolve()
            try:
                p.relative_to(root.resolve())
            except ValueError:
                # Disallow path traversal attempts
                continue
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(sf.content, encoding="utf-8", errors="replace")

        return run_semgrep_on_directory(root, config=config, project_files=file_map)
