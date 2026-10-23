"""Scanner engine: runs every applicable rule over every file and builds findings.

Uses asyncio + ProcessPoolExecutor to dispatch CPU-bound regex work to
background processes so FastAPI's event loop stays responsive.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from typing import Literal

from .frameworks import apply_framework_extensions
from .masking import redact_text
from .models import SEVERITY_ORDER, Finding, SourceFile
from .rules import ALL_RULES, Rule
from .sca import run_sca_scan
from .semgrep import is_semgrep_available, run_semgrep_on_files

SNIPPET_CONTEXT = 2

# A module-level executor shared across requests.  ``max_workers=None``
# lets Python choose (usually ``os.cpu_count()``); callers that need a
# different pool can pass one to ``scan_files_async``.
_executor: ProcessPoolExecutor | None = None


def _get_executor() -> ProcessPoolExecutor:
    """Lazily create a module-level ProcessPoolExecutor."""
    global _executor
    if _executor is None:
        _executor = ProcessPoolExecutor()
    return _executor


def shutdown_executor(wait: bool = True) -> None:
    """Shutdown the module-level executor (call on app shutdown)."""
    global _executor
    if _executor is not None:
        _executor.shutdown(wait=wait)
        _executor = None


def _snippet(lines: list[str], line_no: int) -> str:
    start = max(0, line_no - 1 - SNIPPET_CONTEXT)
    end = min(len(lines), line_no + SNIPPET_CONTEXT)
    return redact_text("\n".join(lines[start:end]))


# ── Single-file scanner (runs in a worker process) ──────────────

def _scan_single_file(
    f: SourceFile,
    all_files: list[SourceFile],
    rules: list[Rule],
    origin: str,
) -> list[Finding]:
    """Scan one file against all applicable rules.

    This is the unit of work dispatched to a child process.  It is a
    module-level function so ``pickle`` can serialise it for the
    ProcessPoolExecutor.
    """
    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    lines = f.lines
    for rule in rules:
        if not rule.applies(f):
            continue
        for m in rule.check(f, all_files):
            key = (rule.meta.id, f.path, m.line)
            if key in seen:
                continue
            seen.add(key)
            meta = rule.meta
            line_text = lines[m.line - 1] if 0 < m.line <= len(lines) else ""
            findings.append(Finding(
                rule_id=meta.id, title=m.title or meta.title, category=meta.category,
                description=meta.description, severity=m.severity or meta.severity,
                confidence=m.confidence, kind=m.kind, file=f.path, line=m.line,
                snippet=_snippet(lines, m.line), evidence=redact_text(m.evidence),
                impact=meta.impact, remediation=meta.remediation, cwe=meta.cwe,
                origin=origin, line_text=redact_text(line_text.strip())[:300],
            ).finalize())
    return findings


# ── Synchronous entry point (unchanged public API) ──────────────

def scan_files(
    files: list[SourceFile],
    rules: list[Rule] | None = None,
    origin: str = "source",
    enable_semgrep: bool = True,
    framework_auth_action: Literal["dismiss", "lower_severity"] = "dismiss",
) -> list[Finding]:
    """Scan *files* synchronously.  Keeps the original public API so
    existing callers (tests, evaluation, demo) continue to work without
    modification.
    """
    rules = rules or ALL_RULES
    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for f in files:
        lines = f.lines
        for rule in rules:
            if not rule.applies(f):
                continue
            for m in rule.check(f, files):
                key = (rule.meta.id, f.path, m.line)
                if key in seen:
                    continue
                seen.add(key)
                meta = rule.meta
                line_text = lines[m.line - 1] if 0 < m.line <= len(lines) else ""
                findings.append(Finding(
                    rule_id=meta.id, title=m.title or meta.title, category=meta.category,
                    description=meta.description, severity=m.severity or meta.severity,
                    confidence=m.confidence, kind=m.kind, file=f.path, line=m.line,
                    snippet=_snippet(lines, m.line), evidence=redact_text(m.evidence),
                    impact=meta.impact, remediation=meta.remediation, cwe=meta.cwe,
                    origin=origin, line_text=redact_text(line_text.strip())[:300],
                ).finalize())

    if enable_semgrep and is_semgrep_available():
        sg_findings = run_semgrep_on_files(files)
        for sf in sg_findings:
            key = (sf.rule_id, sf.file, sf.line)
            if key not in seen:
                seen.add(key)
                findings.append(sf)

    # Apply framework-level protections (Next.js middleware JWT validation, Supabase RLS)
    findings = apply_framework_extensions(files, findings, action=framework_auth_action)
    findings.sort(key=lambda x: (SEVERITY_ORDER[x.severity], x.file, x.line))
    return findings


# ── Async entry point (for FastAPI routes) ──────────────────────

async def scan_files_async(
    files: list[SourceFile],
    rules: list[Rule] | None = None,
    origin: str = "source",
    *,
    executor: ProcessPoolExecutor | None = None,
    enable_semgrep: bool = True,
    enable_sca: bool = True,
    framework_auth_action: Literal["dismiss", "lower_severity"] = "dismiss",
) -> list[Finding]:
    """Scan *files* without blocking the event loop.

    Each file is dispatched to a worker process via a
    ``ProcessPoolExecutor``.  The event loop awaits completion of all
    futures concurrently, so incoming HTTP requests keep being served.

    Parameters
    ----------
    files:
        Source files to scan.
    rules:
        Rule set; defaults to ``ALL_RULES``.
    origin:
        ``"source"`` or ``"browser"``.
    executor:
        Optional custom executor.  When *None* the module-level pool is
        used (lazily created, ``os.cpu_count()`` workers).
    """
    rules = rules or ALL_RULES
    pool = executor or _get_executor()
    loop = asyncio.get_running_loop()

    # Dispatch each file to a worker process.
    futures = [
        loop.run_in_executor(
            pool,
            partial(_scan_single_file, f, files, rules, origin),
        )
        for f in files
    ]

    # Gather results from all workers concurrently.
    results = await asyncio.gather(*futures)

    # Optional Semgrep deep taint analysis execution
    sg_findings: list[Finding] = []
    if enable_semgrep and is_semgrep_available():
        sg_findings = await loop.run_in_executor(None, run_semgrep_on_files, files)

    # Optional Software Composition Analysis (SCA) via Google OSV API
    sca_findings: list[Finding] = []
    if enable_sca:
        try:
            sca_findings = await run_sca_scan(files)
        except Exception as e:
            # SCA errors (e.g. offline/network unreachable) should not fail the scan
            pass

    # Merge and deduplicate across files (same rule+file+line can't
    # appear twice because each file is scanned independently, but
    # guard against edge cases from the ``project`` parameter).
    seen: set[tuple[str, str, int]] = set()
    findings: list[Finding] = []
    for batch in results:
        for finding in batch:
            key = (finding.rule_id, finding.file, finding.line)
            if key not in seen:
                seen.add(key)
                findings.append(finding)

    for sf in sg_findings:
        key = (sf.rule_id, sf.file, sf.line)
        if key not in seen:
            seen.add(key)
            findings.append(sf)

    for sca_f in sca_findings:
        key = (sca_f.rule_id, sca_f.file, sca_f.line)
        if key not in seen:
            seen.add(key)
            findings.append(sca_f)

    # Apply framework-level protections (Next.js middleware JWT validation, Supabase RLS)
    findings = apply_framework_extensions(files, findings, action=framework_auth_action)
    findings.sort(key=lambda x: (SEVERITY_ORDER[x.severity], x.file, x.line))
    return findings
