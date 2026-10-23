"""Software Composition Analysis (SCA) module for PatchPilot.

Parses dependency lockfiles / manifests (package.json, requirements.txt)
from uploaded projects and performs asynchronous vulnerability queries
against the Google OSV (Open Source Vulnerabilities) API at https://api.osv.dev/v1/query.

Formats identified vulnerabilities into PatchPilot's unified `Finding` model.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import Any

import httpx

from .masking import redact_text
from .models import Confidence, Finding, FindingKind, Severity, SourceFile

log = logging.getLogger("patchpilot.sca")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
DEFAULT_TIMEOUT = 10.0


@dataclass
class Dependency:
    ecosystem: str   # "npm" or "PyPI"
    name: str        # e.g., "lodash", "requests"
    version: str     # e.g., "4.17.15", "2.20.0"
    file: str        # e.g., "package.json", "backend/requirements.txt"
    line: int        # 1-based line number where declared


# ---------------------------------------------------------------- parsers

def parse_package_json(sf: SourceFile) -> list[Dependency]:
    """Parse dependencies, devDependencies, and peerDependencies from a package.json file."""
    deps: list[Dependency] = []
    try:
        data = json.loads(sf.content)
    except Exception:
        return []

    lines = sf.lines
    dep_sections = ["dependencies", "devDependencies", "peerDependencies"]

    for sec in dep_sections:
        section_data = data.get(sec)
        if not isinstance(section_data, dict):
            continue

        for pkg_name, raw_version in section_data.items():
            if not isinstance(raw_version, str):
                continue
            # Strip npm semver prefixes (^, ~, >=, =, v)
            clean_ver = re.sub(r"^[~^>=<v\s]+", "", raw_version.strip())
            # Skip wildcards, commit hashes, or local path references
            if not clean_ver or clean_ver in ("*", "latest") or "/" in clean_ver:
                continue

            # Find matching line number for accurate gutter highlighting
            line_no = 1
            pattern = re.compile(rf'["\']{re.escape(pkg_name)}["\']\s*:')
            for idx, line in enumerate(lines, 1):
                if pattern.search(line):
                    line_no = idx
                    break

            deps.append(Dependency(
                ecosystem="npm",
                name=pkg_name,
                version=clean_ver,
                file=sf.path,
                line=line_no,
            ))

    return deps


def parse_requirements_txt(sf: SourceFile) -> list[Dependency]:
    """Parse pinned package versions from a Python requirements.txt file."""
    deps: list[Dependency] = []
    lines = sf.lines

    for idx, line in enumerate(lines, 1):
        clean = line.strip()
        # Skip empty lines, comments, or options flags
        if not clean or clean.startswith(("#", "-", "--", "git+")):
            continue

        # Extract pinned package and version (e.g., requests==2.20.0, django===3.2)
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*={2,3}\s*([A-Za-z0-9_.\-]+)", clean)
        if m:
            pkg_name, version = m.group(1), m.group(2)
            deps.append(Dependency(
                ecosystem="PyPI",
                name=pkg_name,
                version=version,
                file=sf.path,
                line=idx,
            ))

    return deps


def extract_dependencies(files: list[SourceFile]) -> list[Dependency]:
    """Scan uploaded project files for supported dependency manifests."""
    all_deps: list[Dependency] = []
    for f in files:
        base_name = f.name.lower()
        if base_name == "package.json":
            all_deps.extend(parse_package_json(f))
        elif base_name in ("requirements.txt", "requirements-dev.txt", "requirements.in") or base_name.endswith(".requirements.txt"):
            all_deps.extend(parse_requirements_txt(f))
    return all_deps


# ---------------------------------------------------------------- OSV API queries

def _map_osv_severity(vuln: dict[str, Any]) -> Severity:
    """Derive PatchPilot Severity from OSV database-specific ratings or CVSS score."""
    # 1. Check CVSS score if available
    severities = vuln.get("severity", [])
    for s in severities:
        score_str = s.get("score", "")
        # Try CVSS v3 vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
        cvss_match = re.search(r"/S:[UC]/C:([NLH])/I:([NLH])/A:([NLH])", score_str)
        if cvss_match and all(x == "H" for x in cvss_match.groups()):
            return "critical"

    # 2. Check ecosystem-specific severity strings
    db_spec = vuln.get("database_specific", {})
    raw_sev = str(db_spec.get("severity", "")).upper()
    if raw_sev in ("CRITICAL",):
        return "critical"
    if raw_sev in ("HIGH", "ERROR"):
        return "high"
    if raw_sev in ("MODERATE", "MEDIUM", "WARNING"):
        return "medium"
    if raw_sev in ("LOW", "INFO"):
        return "low"

    return "high"


def _extract_cwe_from_osv(vuln: dict[str, Any]) -> str | None:
    """Extract CWE ID from OSV vulnerability details."""
    db_spec = vuln.get("database_specific", {})
    cwes = db_spec.get("cwe_ids")
    if isinstance(cwes, list) and cwes:
        return str(cwes[0]).strip()
    return None


async def query_osv_package(client: httpx.AsyncClient, dep: Dependency) -> list[Finding]:
    """Asynchronously query Google OSV API for a single dependency version."""
    payload = {
        "version": dep.version,
        "package": {
            "name": dep.name,
            "ecosystem": dep.ecosystem,
        },
    }

    try:
        resp = await client.post(OSV_QUERY_URL, json=payload, timeout=DEFAULT_TIMEOUT)
        if resp.status_code != 200:
            return []
        data = resp.json()
    except Exception as e:
        log.debug("OSV query failed for %s@%s: %s", dep.name, dep.version, e)
        return []

    vulns = data.get("vulns", [])
    findings: list[Finding] = []

    for v in vulns:
        vuln_id = v.get("id", f"SCA-{dep.name.upper()}")
        summary = v.get("summary") or v.get("details", "") or f"Vulnerability detected in {dep.name}"
        clean_summary = summary.split("\n")[0][:120].strip()
        details = v.get("details", clean_summary)

        # Check for fixed version in ranges
        fixed_versions: list[str] = []
        for affected in v.get("affected", []):
            for r in affected.get("ranges", []):
                for ev in r.get("events", []):
                    if "fixed" in ev:
                        fixed_versions.append(ev["fixed"])

        fixed_str = f" Upgrade to version {', '.join(fixed_versions[:2])} or later." if fixed_versions else " Upgrade to a patched release."

        severity = _map_osv_severity(v)
        cwe = _extract_cwe_from_osv(v)

        snippet = f'"{dep.name}": "{dep.version}"' if dep.ecosystem == "npm" else f"{dep.name}=={dep.version}"
        evidence = f"Google OSV identified known vulnerability {vuln_id} affecting {dep.name}=={dep.version}."
        impact = f"Known CVE/vulnerability in third-party component {dep.name}: {clean_summary}"
        remediation = f"Update dependency `{dep.name}` in `{dep.file}`.{fixed_str}"

        findings.append(Finding(
            rule_id=f"PP-SCA-{vuln_id}",
            title=f"Vulnerable dependency: {dep.name}@{dep.version} ({vuln_id})",
            category="Software Composition",
            description=details[:300],
            severity=severity,
            confidence="high",
            kind="confirmed",
            file=dep.file,
            line=dep.line,
            snippet=redact_text(snippet),
            evidence=redact_text(evidence),
            impact=impact,
            remediation=remediation,
            cwe=cwe,
            origin="source",
            line_text=snippet,
        ).finalize())

    return findings


async def run_sca_scan(files: list[SourceFile]) -> list[Finding]:
    """Execute asynchronous Software Composition Analysis (SCA) on all uploaded project manifests."""
    dependencies = extract_dependencies(files)
    if not dependencies:
        return []

    # Deduplicate dependencies to avoid redundant network queries
    unique_deps: dict[tuple[str, str, str], Dependency] = {}
    for dep in dependencies:
        key = (dep.ecosystem, dep.name.lower(), dep.version)
        if key not in unique_deps:
            unique_deps[key] = dep

    sem = asyncio.Semaphore(10)

    async def _query_with_sem(client: httpx.AsyncClient, dep: Dependency) -> list[Finding]:
        async with sem:
            return await query_osv_package(client, dep)

    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        # Run OSV queries concurrently with bounded concurrency
        tasks = [_query_with_sem(client, dep) for dep in unique_deps.values()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: list[Finding] = []
    seen: set[str] = set()

    for res in results:
        if isinstance(res, list):
            for f in res:
                if f.rule_id not in seen:
                    seen.add(f.rule_id)
                    findings.append(f)

    return findings
