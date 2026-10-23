"""PatchPilot AI — FastAPI application.

Run:  uvicorn app.main:app --port 8000   (from the backend/ folder)
Docs: http://localhost:8000/docs
"""
from __future__ import annotations

from contextlib import asynccontextmanager
import io
import json
import logging
import os
import zipfile
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import ai, autofix, db, service
from .evaluation import run_evaluation
from .ingest import LIMITS, MAX_ARCHIVE_BYTES, MAX_FILE_BYTES, IngestError, IngestResult, download_github_repo, ingest_files, ingest_zip, ingest_zip_stream, parse_github_repo_url
from .repair import build_repair_prompt, deterministic_explanation
from .scanner import ALL_RULES, shutdown_executor
from .scanner.scoring import METHOD
from .urlscan import UrlScanError, scan_url, scan_url_async

# Never log request bodies or source contents.
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("patchpilot")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize asynchronous DB connection and schema
    await db.init_db()
    yield
    # Graceful shutdown of thread/process workers and DB connection
    shutdown_executor()
    await db.close_db()


app = FastAPI(
    title="PatchPilot AI",
    version="1.0.0",
    description="Find vulnerabilities. Fix them with AI. Verify every fix. All findings require human review.",
    lifespan=lifespan,
)

# Dev server origins only; the production build is served from this same origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o for o in os.getenv("PATCHPILOT_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o],
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if not request.url.path.startswith("/docs"):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        )
    return resp


@app.exception_handler(IngestError)
async def ingest_error_handler(_: Request, exc: IngestError):
    return JSONResponse(status_code=exc.status, content={"detail": str(exc)})


@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):
    log.error("Unhandled error: %s", type(exc).__name__)  # no payload contents
    return JSONResponse(status_code=500, content={"detail": "Internal error while processing the request."})


# ------------------------------------------------------------------ models

class StatusUpdate(BaseModel):
    status: Literal["open", "accepted_risk", "needs_review", "fixed"]


class RepairRequest(BaseModel):
    finding_ids: list[str] = Field(default_factory=list, max_length=500)


class RepairResponse(BaseModel):
    prompt: str
    finding_count: int
    notice: str


class Explanation(BaseModel):
    what_the_code_does: str
    why_risky: str
    impact_example: str
    recommended_fix: str
    safer_code_example: str
    verification_steps: list[str]


class ExplainResponse(BaseModel):
    source: Literal["ai", "deterministic"]
    provider: str | None
    explanation: Explanation
    ai_error: str | None = None


class Health(BaseModel):
    status: str
    version: str
    rules: int
    ai_provider: str | None
    url_scanning: bool


# ------------------------------------------------------------------ helpers

async def _read_limited(up: UploadFile, limit: int) -> bytes:
    data = await up.read(limit + 1)
    if len(data) > limit:
        raise IngestError(f"`{up.filename}` exceeds the {limit // 1024} KB limit.", 413)
    return data


async def _ingest_upload(archive: UploadFile | None, files: list[UploadFile] | None) -> IngestResult | None:
    if archive is not None and archive.filename:
        if not archive.filename.lower().endswith(".zip"):
            raise IngestError("Archive must be a .zip file.", 415)
        return ingest_zip_stream(archive.file, MAX_ARCHIVE_BYTES)
    items = [f for f in (files or []) if f.filename]
    if items:
        return ingest_files([(f.filename, await _read_limited(f, MAX_FILE_BYTES)) for f in items])
    return None


async def _url_scan_async(target_url: str | None) -> dict | None:
    if not target_url:
        return None
    if os.getenv("PATCHPILOT_URL_SCAN", "1") != "1":
        raise HTTPException(400, "Deployed-URL scanning is disabled on this server. Source-code scanning is the supported workflow.")
    try:
        return await scan_url_async(target_url)
    except UrlScanError as e:
        raise HTTPException(422, f"URL scan refused or failed: {e}")


def _url_scan(target_url: str | None) -> dict | None:
    if not target_url:
        return None
    if os.getenv("PATCHPILOT_URL_SCAN", "1") != "1":
        raise HTTPException(400, "Deployed-URL scanning is disabled on this server. Source-code scanning is the supported workflow.")
    try:
        return scan_url(target_url)
    except UrlScanError as e:
        raise HTTPException(422, f"URL scan refused or failed: {e}")


async def _require_scan(scan_id: str):
    row = await service.scan_row(scan_id)
    if not row:
        raise HTTPException(404, "Scan not found.")
    return row


def _clean_name(name: str) -> str:
    name = " ".join(name.split())[:80]
    if not name:
        raise HTTPException(422, "Project name is required.")
    return name


# ------------------------------------------------------------------ routes

@app.get("/api/health", response_model=Health, tags=["system"])
def health():
    p = ai.get_provider()
    return Health(status="ok", version=app.version, rules=len(ALL_RULES), ai_provider=p.name if p else None,
                  url_scanning=os.getenv("PATCHPILOT_URL_SCAN", "1") == "1")


@app.get("/api/limits", tags=["system"])
def limits():
    return LIMITS


@app.get("/api/rules", tags=["system"])
def rules():
    return [{"id": r.meta.id, "title": r.meta.title, "category": r.meta.category, "severity": r.meta.severity, "cwe": r.meta.cwe} for r in ALL_RULES]


@app.get("/api/dashboard", tags=["scans"])
async def dashboard():
    scan_rows = await db.query("SELECT * FROM scans ORDER BY created_at DESC")
    scans = [await service.scan_summary(r) for r in scan_rows]
    latest = [s for s in scans if not s["latest_rescan_id"]]
    dist = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    open_ch = 0
    for s in latest:
        findings_rows = await db.query("SELECT data_json, status FROM findings WHERE scan_id=?", (s["id"],))
        for r in findings_rows:
            sev = json.loads(r["data_json"])["severity"]
            dist[sev] += 1
            if sev in ("critical", "high") and r["status"] in ("open", "needs_review"):
                open_ch += 1
    fixed_res = await db.query("SELECT COUNT(*) c FROM findings WHERE status='fixed'")
    resolved = fixed_res[0]["c"]
    total_res = await db.query("SELECT COUNT(*) c FROM findings")
    total = total_res[0]["c"]
    activity_rows = await db.query("SELECT at, scan_id, kind, message FROM activity ORDER BY id DESC LIMIT 12")
    activity = [dict(r) for r in activity_rows]
    return {"total_scans": len(scans), "total_findings": total, "open_critical_high": open_ch, "resolved": resolved,
            "severity_distribution": dist, "recent_scans": scans[:8], "activity": activity,
            "definitions": {
                "total_findings": "All findings detected across every scan, including rescans.",
                "open_critical_high": "Critical or high findings still open or needing review in each project's latest scan.",
                "resolved": "Findings verified as no longer detected by a rescan.",
                "severity_distribution": "Findings in each project's latest scan.",
            }}


@app.post("/api/scans", status_code=201, tags=["scans"])
async def create_scan(
    project_name: str = Form(...),
    archive: UploadFile | None = File(None, description="ZIP of the project source"),
    files: list[UploadFile] | None = File(None, description="Individual source files (use relative paths as filenames)"),
    target_url: str | None = Form(None, description="Optional deployed URL you are authorized to assess"),
):
    name = _clean_name(project_name)
    ingest = await _ingest_upload(archive, files)
    url_result = await _url_scan_async(target_url.strip() if target_url else None)
    if ingest is None and url_result is None:
        raise HTTPException(422, "Upload a ZIP, at least one source file, or a deployed URL.")
    kind = "url" if ingest is None else ("zip" if archive is not None and archive.filename else "files")
    scan_id = await service.create_scan_async(name, ingest, kind, url_result=url_result, target_url=target_url or None)
    row = await service.scan_row(scan_id)
    return await service.scan_summary(row)


# In-memory GitHub session storage (tokens are NEVER saved to the database)
_github_session_cache: dict[str, dict] = {}


class GitHubScanRequest(BaseModel):
    repo_url: str = Field(..., description="GitHub repository URL (https://github.com/owner/repo)")
    github_token: str | None = Field(None, description="Optional GitHub Personal Access Token (for private repos and PR creation)")
    branch: str | None = Field(None, description="Optional branch or tag name")
    project_name: str | None = Field(None, description="Optional custom project name")


class AutofixRequest(BaseModel):
    github_token: str | None = Field(None, description="Optional GitHub Personal Access Token with repo scope")
    branch_name: str | None = Field(None, description="Target branch name for the Pull Request")
    finding_ids: list[str] | None = Field(None, description="List of finding IDs to fix (defaults to all open findings)")


@app.post("/api/scans/github", status_code=201, tags=["scans"])
async def scan_github_repository(payload: GitHubScanRequest):
    """Safely download and scan a GitHub repository via GitHub REST API zipball."""
    try:
        zip_bytes, owner, repo_name, ref = await download_github_repo(
            payload.repo_url,
            token=payload.github_token,
            branch=payload.branch,
        )
    except IngestError as e:
        raise HTTPException(e.status, str(e))

    try:
        ingest = ingest_zip(zip_bytes)
    except IngestError as e:
        raise HTTPException(e.status, f"Repository ingestion error: {e}")

    pname = _clean_name(payload.project_name or f"{owner}/{repo_name}")
    scan_id = await service.create_scan_async(
        pname,
        ingest,
        source_kind="github",
        target_url=payload.repo_url.strip(),
        label=f"GitHub: {owner}/{repo_name} ({ref})",
    )

    # Cache token and repo info IN MEMORY ONLY for this session (never persisted to DB)
    _github_session_cache[scan_id] = {
        "token": payload.github_token.strip() if payload.github_token else None,
        "owner": owner,
        "repo": repo_name,
        "branch": ref,
        "repo_url": payload.repo_url.strip(),
    }

    row = await service.scan_row(scan_id)
    return await service.scan_summary(row)


@app.post("/api/scans/{scan_id}/autofix", tags=["scans"])
async def autofix_scan_and_create_pr(scan_id: str, payload: AutofixRequest):
    """Automatically apply security patches and open a GitHub Pull Request with resolved CWEs."""
    row = await _require_scan(scan_id)

    # 1. Resolve GitHub repository details & token
    session_info = _github_session_cache.get(scan_id, {})
    owner = session_info.get("owner")
    repo_name = session_info.get("repo")
    target_branch = payload.branch_name or session_info.get("branch")

    # If scan was not ingested via github route, attempt parsing target_url
    if not owner or not repo_name:
        target_url = row["target_url"] or ""
        try:
            owner, repo_name = parse_github_repo_url(target_url)
        except Exception:
            raise HTTPException(
                400,
                "This scan is not associated with a GitHub repository. Cannot open a Pull Request.",
            )

    token = (payload.github_token or "").strip() or session_info.get("token") or os.getenv("GITHUB_TOKEN")
    if not token:
        raise HTTPException(
            401,
            "A GitHub Personal Access Token (PAT) with 'repo' scope is required to commit changes and open a Pull Request.",
        )

    # 2. Generate security fixes
    modified_files, resolved_findings = await autofix.generate_fixes_for_scan(
        scan_id,
        finding_ids=payload.finding_ids,
    )

    if not modified_files or not resolved_findings:
        return JSONResponse(
            status_code=200,
            content={
                "success": False,
                "message": "No fixable findings found or no code modifications required.",
                "resolved_count": 0,
            },
        )

    # 3. Create branch, commit files, and open Pull Request
    try:
        pr_result = autofix.create_github_pull_request(
            owner=owner,
            repo_name=repo_name,
            token=token,
            modified_files=modified_files,
            resolved_findings=resolved_findings,
            branch_name=payload.branch_name,
            base_branch=target_branch if target_branch != "default" else None,
        )
    except ValueError as e:
        raise HTTPException(422, str(e))
    except Exception as e:
        log.error("Failed creating GitHub Pull Request: %s", e)
        raise HTTPException(500, f"Error creating GitHub Pull Request: {e}")

    await db.log("autofix", f"Created PR #{pr_result['pr_number']} on {owner}/{repo_name}: {pr_result['pr_url']}", scan_id)
    return pr_result


@app.get("/api/scans", tags=["scans"])
async def list_scans():
    rows = await db.query("SELECT * FROM scans ORDER BY created_at DESC")
    return [await service.scan_summary(r) for r in rows]


@app.delete("/api/scans", status_code=204, tags=["scans"])
async def clear_history():
    for t in ("findings", "files", "scans", "activity"):
        await db.execute(f"DELETE FROM {t}")
    return Response(status_code=204)


@app.get("/api/scans/{scan_id}", tags=["scans"])
async def get_scan(scan_id: str):
    row = await _require_scan(scan_id)
    return await service.scan_summary(row)


SEV_ORDER = ("critical", "high", "medium", "low", "info")


@app.get("/api/findings", tags=["findings"])
async def list_all_findings(
    severity: str | None = None,
    status: str | None = None,
    latest_only: bool = True,
    limit: int = Query(200, ge=1, le=1000),
):
    """Retrieve findings across scans with optional filtering by severity and latest project scan."""
    scan_rows = await db.query("SELECT * FROM scans ORDER BY created_at DESC")
    scans = [await service.scan_summary(r) for r in scan_rows]
    if latest_only:
        target_scans = [s for s in scans if not s["latest_rescan_id"]]
    else:
        target_scans = scans

    scan_map = {s["id"]: s for s in target_scans}
    if not scan_map:
        return []

    placeholders = ",".join("?" for _ in scan_map)
    rows = await db.query(
        f"SELECT scan_id, id, data_json, status FROM findings WHERE scan_id IN ({placeholders}) ORDER BY id",
        tuple(scan_map.keys()),
    )

    results = []
    wanted_sev = set(severity.split(",")) if severity else None
    for r in rows:
        try:
            d = json.loads(r["data_json"])
        except Exception:
            d = {}
        f_sev = d.get("severity")
        if wanted_sev and f_sev not in wanted_sev:
            continue
        if status and r["status"] != status:
            continue
        item = {
            **d,
            "id": r["id"],
            "scan_id": r["scan_id"],
            "project_name": scan_map[r["scan_id"]]["project_name"],
            "status": r["status"],
        }
        results.append(item)

    results.sort(
        key=lambda x: (
            SEV_ORDER.index(x.get("severity")) if x.get("severity") in SEV_ORDER else 99,
            x.get("project_name", ""),
            x.get("file", ""),
        )
    )
    return results[:limit]


@app.get("/api/scans/{scan_id}/findings", tags=["findings"])
async def get_findings(scan_id: str, severity: str | None = None, q: str | None = Query(None, max_length=200)):
    await _require_scan(scan_id)
    items = await service.list_findings(scan_id)
    if severity:
        wanted = set(severity.split(","))
        items = [f for f in items if f["severity"] in wanted]
    if q:
        ql = q.lower()
        items = [f for f in items if ql in (f["title"] + f["file"] + f["rule_id"] + f["evidence"]).lower()]
    return items


@app.patch("/api/scans/{scan_id}/findings/{finding_id}", tags=["findings"])
async def update_status(scan_id: str, finding_id: str, body: StatusUpdate):
    await _require_scan(scan_id)
    f = await service.get_finding(scan_id, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found.")
    if body.status == "fixed":
        raise HTTPException(409, "A finding can only be marked Fixed by a rescan that no longer detects it. Upload the corrected code with Rescan.")
    if f["status"] == "fixed":
        raise HTTPException(409, "This finding was verified as fixed by a rescan; its status cannot be changed.")
    await db.execute("UPDATE findings SET status=?, updated_at=? WHERE id=?", (body.status, db.now(), finding_id))
    await db.log("status", f"{f['rule_id']} in {f['file']} marked {body.status.replace('_', ' ')}", scan_id)
    return await service.get_finding(scan_id, finding_id)


@app.get("/api/scans/{scan_id}/files", tags=["files"])
async def list_files(scan_id: str):
    await _require_scan(scan_id)
    rows = await db.query("SELECT path, length(content) size FROM files WHERE scan_id=? ORDER BY path", (scan_id,))
    return [{"path": r["path"], "size": r["size"]} for r in rows]


@app.get("/api/scans/{scan_id}/file", tags=["files"])
async def get_file(scan_id: str, path: str = Query(..., max_length=500)):
    await _require_scan(scan_id)
    rows = await db.query("SELECT content FROM files WHERE scan_id=? AND path=?", (scan_id, path))
    if not rows:
        raise HTTPException(404, "File not found in this scan.")
    return {"path": path, "content": rows[0]["content"], "masked": True}


@app.post("/api/scans/{scan_id}/findings/{finding_id}/explain", response_model=ExplainResponse, tags=["ai"])
async def explain(scan_id: str, finding_id: str):
    await _require_scan(scan_id)
    f = await service.get_finding(scan_id, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found.")
    fallback = deterministic_explanation(f)
    provider = ai.get_provider()
    if provider is None:
        return ExplainResponse(source="deterministic", provider=None, explanation=Explanation(**fallback),
                               ai_error="AI explanations are disabled (no provider configured). Showing the built-in explanation.")
    try:
        exp = ai.explain_with_ai(f, provider)
        return ExplainResponse(source="ai", provider=provider.name, explanation=Explanation(**exp))
    except ai.AIError as e:
        return ExplainResponse(source="deterministic", provider=provider.name, explanation=Explanation(**fallback),
                               ai_error=f"{e} The scanner finding is unchanged; showing the built-in explanation.")


@app.post("/api/scans/{scan_id}/repair-prompt", response_model=RepairResponse, tags=["ai"])
async def repair_prompt(scan_id: str, body: RepairRequest):
    row = await _require_scan(scan_id)
    items = await service.list_findings(scan_id)
    if body.finding_ids:
        wanted = set(body.finding_ids)
        items = [f for f in items if f["id"] in wanted]
        if not items:
            raise HTTPException(404, "None of the requested findings belong to this scan.")
    else:
        items = [f for f in items if f["status"] in ("open", "needs_review")]
    if not items:
        raise HTTPException(422, "There are no open findings to include.")
    prompt = build_repair_prompt(row["project_name"], items, row["file_count"])
    await db.log("prompt", f"Generated a fix prompt for {len(items)} finding(s)", scan_id)
    return RepairResponse(prompt=prompt, finding_count=len(items),
                          notice="Review every AI-generated change before deploying. Then rescan to verify the fix.")


@app.post("/api/scans/{scan_id}/rescan", status_code=201, tags=["scans"])
async def rescan(scan_id: str, archive: UploadFile | None = File(None), files: list[UploadFile] | None = File(None)):
    row = await _require_scan(scan_id)
    ingest = await _ingest_upload(archive, files)
    if ingest is None:
        raise HTTPException(422, "Upload the updated project as a ZIP or as source files.")
    kind = "zip" if archive is not None and archive.filename else "files"
    new_id = await service.create_scan_async(row["project_name"], ingest, kind, parent_id=scan_id, label="Rescan", is_demo=bool(row["is_demo"]))
    next_row = await service.scan_row(new_id)
    return await service.scan_summary(next_row)


@app.get("/api/scans/{scan_id}/report", tags=["scans"])
async def report(scan_id: str, format: Literal["json", "md"] = "md"):
    summary = await service.scan_summary(await _require_scan(scan_id))
    findings = await service.list_findings(scan_id)
    fname = f"patchpilot-{scan_id}.{format}"
    headers = {"Content-Disposition": f'attachment; filename="{fname}"'}
    if format == "json":
        return JSONResponse({"scan": summary, "findings": findings,
                             "disclaimer": "Automated findings require human review. No findings does not mean secure. Secrets are masked."},
                            headers=headers)
    return PlainTextResponse(service.build_report_markdown(summary, findings), media_type="text/markdown", headers=headers)


# ------------------------------------------------------------------ demo & evaluation

@app.get("/api/demo", tags=["demo"])
def demo_info():
    out = {}
    for v in ("vulnerable", "fixed"):
        res = service.load_demo(v)
        out[v] = {"files": [f.path for f in res.files], "download": f"/api/demo/{v}/download"}
    out["notice"] = "Synthetic demonstration project with intentionally planted issues. All credentials are fake and inert."
    return out


@app.get("/api/demo/{variant}/download", tags=["demo"])
def demo_download(variant: Literal["vulnerable", "fixed"]):
    res = service.load_demo(variant)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in res.files:
            zf.writestr(f"campus-bazaar-{variant}/{f.path}", f.content)
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="campus-bazaar-{variant}.zip"'})


@app.post("/api/demo/scan", status_code=201, tags=["demo"])
async def demo_scan():
    sid = await service.create_scan_async(
        "Campus Bazaar (demo)", service.load_demo("vulnerable"), "demo",
        label="Vulnerable demo", is_demo=True,
    )
    row = await service.scan_row(sid)
    return await service.scan_summary(row)


@app.post("/api/scans/{scan_id}/rescan/demo", status_code=201, tags=["demo"])
async def demo_rescan(scan_id: str):
    row = await _require_scan(scan_id)
    if not row["is_demo"]:
        raise HTTPException(409, "The bundled corrected project can only be used to rescan a demo scan.")
    sid = await service.create_scan_async(
        row["project_name"], service.load_demo("fixed"), "demo", parent_id=scan_id,
        label="Corrected demo", is_demo=True,
    )
    next_row = await service.scan_row(sid)
    return await service.scan_summary(next_row)


@app.get("/api/evaluation", tags=["demo"])
def evaluation():
    return run_evaluation()


@app.get("/api/scoring", tags=["system"])
def scoring():
    return {"method": METHOD}


# ------------------------------------------------------------------ frontend

DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(404, "Not found")
        candidate = (DIST / full_path).resolve()
        if full_path and candidate.is_file() and DIST in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(DIST / "index.html")
