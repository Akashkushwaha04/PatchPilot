"""Scan lifecycle: create, persist, rescan/compare, report.
Supports both async and sync operations on top of aiosqlite.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

from . import db
from .ingest import IngestError, IngestResult
from .repair import build_single_remediation
from .scanner import SourceFile, scan_files, scan_files_async
from .scanner.compare import compare_findings
from .scanner.masking import redact_text
from .scanner.models import SEVERITY_ORDER
from .scanner.scoring import compute_score, severity_counts

DEMO_DIR = Path(__file__).resolve().parent.parent.parent / "demo"
MANUAL_STATUSES = {"open", "accepted_risk", "needs_review"}


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _default_status(f: dict) -> str:
    return "needs_review" if f["kind"] == "review_candidate" else "open"


async def _save_scan_record_async(
    project_name: str, ingest: IngestResult | None, source_kind: str,
    findings: list[dict], *, parent_id: str | None = None,
    label: str | None = None, is_demo: bool = False, url_result: dict | None = None,
    target_url: str | None = None, ai_model: str = "claude-3-7-sonnet"
) -> str:
    files = ingest.files if ingest else []
    if url_result:
        findings += url_result["findings"]
    findings.sort(key=lambda x: (SEVERITY_ORDER[x["severity"]], x["origin"], x["file"], x["line"]))

    scan_id = _new_id()
    score = compute_score(findings)
    counts = severity_counts(findings)
    comparison = None
    inherited: dict[str, str] = {}

    if parent_id:
        parent_rows = await db.query("SELECT id, data_json, status FROM findings WHERE scan_id=?", (parent_id,))
        before = []
        for r in parent_rows:
            d = json.loads(r["data_json"])
            d["_id"], d["_status"] = r["id"], r["status"]
            before.append(d)
        cmp = compare_findings(before, findings)
        parent_scans = await db.query("SELECT score_json FROM scans WHERE id=?", (parent_id,))
        before_score = json.loads(parent_scans[0]["score_json"])
        for pair in cmp["remaining"]:
            if pair["before"]["_status"] == "accepted_risk":
                inherited[pair["after"]["fingerprint"]] = "accepted_risk"
        comparison = {
            "parent_id": parent_id,
            "before_score": before_score["score"],
            "after_score": score["score"],
            "resolved": [{"finding": _public(x["before"]), "verification": x["verification"]} for x in cmp["resolved"]],
            "remaining": [{"before": _public(x["before"]), "after": _public(x["after"]), "matched_by": x["matched_by"]} for x in cmp["remaining"]],
            "new": [_public(x) for x in cmp["new"]],
            "severity_changes": [{"rule_id": x["before"]["rule_id"], "file": x["after"]["file"], "line": x["after"]["line"],
                                  "from": x["before"]["severity"], "to": x["after"]["severity"]} for x in cmp["severity_changes"]],
            "method": cmp["method"],
        }
        comparison["summary"] = _verification_summary(comparison)
        # Mark original findings as fixed ONLY based on the rescan result.
        for x in cmp["resolved"]:
            await db.execute("UPDATE findings SET status='fixed', verified_by=?, updated_at=? WHERE id=?", (scan_id, db.now(), x["before"]["_id"]))

    await db.execute(
        "INSERT INTO scans(id, project_name, created_at, parent_id, source_kind, label, file_count, skipped_json, score_json, counts_json, comparison_json, target_url, url_json, is_demo, ai_model) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (scan_id, project_name, db.now(), parent_id, source_kind, label, len(files),
         json.dumps(ingest.skipped if ingest else []), json.dumps(score), json.dumps(counts),
         json.dumps(comparison) if comparison else None, target_url,
         json.dumps({k: v for k, v in url_result.items() if k != "findings" and not k.startswith("_")}) if url_result else None, int(is_demo), ai_model),
    )
    await db.executemany(
        "INSERT INTO findings(id, scan_id, seq, data_json, status, updated_at) VALUES (?,?,?,?,?,?)",
        [(f"{scan_id}-{i:03d}", scan_id, i, json.dumps(f), inherited.get(f["fingerprint"], _default_status(f)), db.now()) for i, f in enumerate(findings)],
    )
    # Store only redacted copies for the code viewer.
    await db.executemany("INSERT INTO files(scan_id, path, content) VALUES (?,?,?)",
                         [(scan_id, sf.path, redact_text(sf.content)) for sf in files])
    if url_result:
        await db.executemany("INSERT OR IGNORE INTO files(scan_id, path, content) VALUES (?,?,?)",
                             [(scan_id, p, redact_text(c)) for p, c in url_result.get("_files", [])])

    if parent_id and comparison:
        await db.log("rescan", f"Rescanned {project_name}: {len(comparison['resolved'])} resolved, {len(comparison['remaining'])} remaining, {len(comparison['new'])} new", scan_id)
    else:
        await db.log("scan", f"Scanned {project_name}: {len(findings)} findings, score {score['score']}", scan_id)
    return scan_id


async def create_scan_async(
    project_name: str, ingest: IngestResult | None, source_kind: str, *, parent_id: str | None = None,
    label: str | None = None, is_demo: bool = False, url_result: dict | None = None,
    target_url: str | None = None, ai_model: str = "claude-3-7-sonnet"
) -> str:
    """Non-blocking scan and insertion via aiosqlite and process pool."""
    files = ingest.files if ingest else []
    # For synthetic demo projects, skip external network OSV queries to keep the demo evaluation benchmark exact
    enable_sca = not is_demo
    findings = [f.to_dict() for f in await scan_files_async(files, enable_sca=enable_sca)] if files else []
    return await _save_scan_record_async(
        project_name, ingest, source_kind, findings, parent_id=parent_id,
        label=label, is_demo=is_demo, url_result=url_result, target_url=target_url, ai_model=ai_model
    )


def create_scan(
    project_name: str, ingest: IngestResult | None, source_kind: str, *, parent_id: str | None = None,
    label: str | None = None, is_demo: bool = False, url_result: dict | None = None,
    target_url: str | None = None
) -> str:
    """Synchronous compatibility wrapper for CLI or test callers."""
    files = ingest.files if ingest else []
    findings = [f.to_dict() for f in scan_files(files)] if files else []
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        # Schedule in existing loop or run in a thread
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            return pool.submit(
                asyncio.run,
                _save_scan_record_async(project_name, ingest, source_kind, findings, parent_id=parent_id,
                                        label=label, is_demo=is_demo, url_result=url_result, target_url=target_url)
            ).result()
    return asyncio.run(
        _save_scan_record_async(project_name, ingest, source_kind, findings, parent_id=parent_id,
                                label=label, is_demo=is_demo, url_result=url_result, target_url=target_url)
    )


def _public(f: dict) -> dict:
    return {k: v for k, v in f.items() if not k.startswith("_") and k != "line_text"}


def _verification_summary(c: dict) -> str:
    r, rem, new = len(c["resolved"]), len(c["remaining"]), len(c["new"])
    delta = c["after_score"] - c["before_score"]
    parts = [f"{r} finding{'s' if r != 1 else ''} no longer detected", f"{rem} still present", f"{new} newly introduced"]
    s = "Rescan verified: " + ", ".join(parts) + f". Score {c['before_score']} → {c['after_score']} ({'+' if delta >= 0 else ''}{delta})."
    if new:
        s += " Review the new findings: fixes sometimes introduce new issues."
    if rem:
        s += " Remaining findings were matched to the same rule in the same place."
    return s


async def scan_row(scan_id: str):
    rows = await db.query("SELECT * FROM scans WHERE id=?", (scan_id,))
    return rows[0] if rows else None


async def scan_summary(row) -> dict:
    child = await db.query("SELECT id FROM scans WHERE parent_id=? ORDER BY created_at DESC LIMIT 1", (row["id"],))
    statuses = await db.query("SELECT status, COUNT(*) c FROM findings WHERE scan_id=? GROUP BY status", (row["id"],))
    return {
        "id": row["id"], "project_name": row["project_name"], "created_at": row["created_at"],
        "parent_id": row["parent_id"], "latest_rescan_id": child[0]["id"] if child else None,
        "source_kind": row["source_kind"], "label": row["label"], "is_demo": bool(row["is_demo"]),
        "file_count": row["file_count"], "skipped": json.loads(row["skipped_json"]),
        "score": json.loads(row["score_json"]), "counts": json.loads(row["counts_json"]),
        "status_counts": {r["status"]: r["c"] for r in statuses},
        "total_findings": sum(json.loads(row["counts_json"]).values()),
        "target_url": row["target_url"], "url_scan": db.loads(row["url_json"]),
        "comparison": db.loads(row["comparison_json"]),
        "ai_model": row["ai_model"] if "ai_model" in row.keys() and row["ai_model"] else "claude-3-7-sonnet",
    }


async def list_findings(scan_id: str) -> list[dict]:
    out = []
    rows = await db.query("SELECT * FROM findings WHERE scan_id=? ORDER BY seq", (scan_id,))
    for r in rows:
        d = _public(json.loads(r["data_json"]))
        d.update({"id": r["id"], "status": r["status"], "verified_by": r["verified_by"]})
        d["remediation_text"] = build_single_remediation(d)
        out.append(d)
    return out


async def get_finding(scan_id: str, finding_id: str) -> dict | None:
    findings = await list_findings(scan_id)
    for f in findings:
        if f["id"] == finding_id:
            return f
    return None


def load_demo(variant: str) -> IngestResult:
    from .ingest import is_supported_name
    root = DEMO_DIR / variant
    if variant not in ("vulnerable", "fixed") or not root.is_dir():
        raise IngestError("Demo project not found.", 404)
    res = IngestResult()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            if is_supported_name(rel):
                res.files.append(SourceFile(rel, p.read_text(encoding="utf-8")))
            else:
                res.skipped.append({"path": rel, "reason": "unsupported file type"})
    return res


def build_report_markdown(summary: dict, findings: list[dict]) -> str:
    s = summary
    lines = [
        f"# PatchPilot AI security report — {s['project_name']}", "",
        f"- Scan ID: `{s['id']}`", f"- Date (UTC): {s['created_at']}", f"- Files scanned: {s['file_count']}",
        f"- Security score: **{s['score']['score']}/100 (grade {s['score']['grade']})**",
        f"- Findings: " + ", ".join(f"{k} {v}" for k, v in s["counts"].items() if v) if s["total_findings"] else "- Findings: none detected",
        "", f"> Scoring: {s['score']['method']}", "",
        "> All findings come from automated pattern matching and require human review. "
        "No findings does not mean the application is secure. Detected secrets are masked.", "",
    ]
    if s["comparison"]:
        c = s["comparison"]
        lines += ["## Rescan verification", "", c["summary"], "", f"Matching method: {c['method']}", ""]
        for title, items, key in (("Resolved / no longer detected", c["resolved"], "finding"), ("Remaining", c["remaining"], "after")):
            lines.append(f"### {title} ({len(items)})")
            for it in items:
                f = it[key]
                lines.append(f"- {f['rule_id']} {f['title']} — `{f['file']}:{f['line']}`")
            lines.append("")
        lines.append(f"### Newly introduced ({len(c['new'])})")
        lines += [f"- {f['rule_id']} {f['title']} — `{f['file']}:{f['line']}`" for f in c["new"]] + [""]
    lines.append("## Findings")
    for i, f in enumerate(findings, 1):
        lines += [
            "", f"### {i}. [{f['severity'].upper()}] {f['title']}",
            f"- Rule: {f['rule_id']}" + (f" ({f['cwe']})" if f.get("cwe") else ""),
            f"- Location: `{f['file']}:{f['line']}` ({'browser-visible' if f['origin'] == 'browser' else 'source code'})",
            f"- Confidence: {f['confidence']} · Type: {f['kind'].replace('_', ' ')} · Status: {f['status'].replace('_', ' ')}",
            f"- Evidence: {f['evidence']}", "", "```", f["snippet"], "```", "",
            f"**Impact:** {f['impact']}", "", f"**Remediation:** {f['remediation']}",
        ]
    return "\n".join(lines) + "\n"
