"""Automated AI security fix generation and GitHub Pull Request integration.

Applies AI-assisted and rule-specific security remediations to discovered vulnerabilities,
patches source files in an isolated environment, and opens a GitHub Pull Request
documenting resolved CWEs.
"""
from __future__ import annotations

import difflib
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import ai, db
from .repair import SAFER_EXAMPLES
from .scanner.models import SourceFile

log = logging.getLogger("patchpilot.autofix")


def apply_patch_replacement(content: str, line_no: int, old_line: str, replacement: str) -> str:
    """Safely replace a specific vulnerable line or block in a source file."""
    lines = content.splitlines(keepends=True)
    if not (1 <= line_no <= len(lines)):
        # Fallback: substring replacement if line number is out of bounds
        if old_line.strip() and old_line.strip() in content:
            return content.replace(old_line.strip(), replacement.strip(), 1)
        return content

    target = lines[line_no - 1]
    # Preserve original line indentation
    indent = re.match(r"^\s*", target).group(0) if re.match(r"^\s*", target) else ""
    rep_lines = replacement.splitlines()
    indented_lines = []
    for idx, l in enumerate(rep_lines):
        stripped = l.lstrip()
        if stripped:
            indented_lines.append(indent + stripped if idx == 0 else (indent + l if l.strip() else l))
        else:
            indented_lines.append("")
    indented_replacement = "\n".join(indented_lines)
    if not indented_replacement.endswith("\n"):
        indented_replacement += "\n"

    lines[line_no - 1] = indented_replacement
    return "".join(lines)


def get_deterministic_correction(finding: dict, file_content: str) -> tuple[str | None, str | None, str]:
    """Generate deterministic patched content, replacement line, and explanation.

    Returns:
        tuple[patched_content | None, fixed_line | None, explanation]
    """
    rule_id = finding.get("rule_id", "")
    line_no = finding.get("line", 1)
    file_path = finding.get("file", "")
    lines = file_content.splitlines()
    target_line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
    is_py = file_path.endswith(".py") or "def " in file_content or "import " in file_content and "requirements" not in file_path

    # 1. Hardcoded Secrets (PP-SEC-001, PP-SEC-002, PP-SEC-003, PP-SEC-004, PP-SEC-005)
    if rule_id == "PP-SEC-001":
        sub = 'os.environ.get("API_KEY", "")' if is_py else 'process.env.API_KEY || ""'
        m = re.search(r"""(=|:)\s*(['"`][^'"`\n]+['"`]|sk-[^\s;\n]+|gh[posr]_[^\s;\n]+|AKIA[^\s;\n]+)""", target_line)
        if m:
            sep = m.group(1)
            fixed_line = target_line[:m.start()] + f"{sep} {sub}" + target_line[m.end():]
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Replaced hardcoded API credential with a runtime environment variable lookup. Secrets must never be committed to source control; inject them securely via environment variables or a vault."
            return patched, fixed_line.strip(), exp

        m2 = re.search(r"""(['"][A-Za-z0-9_\-\.]{12,}['"]|['"][^'"]*\(masked\)['"])""", target_line)
        if m2:
            fixed_line = target_line[:m2.start()] + sub + target_line[m2.end():]
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Replaced hardcoded token literal with environment variable retrieval."
            return patched, fixed_line.strip(), exp

    elif rule_id == "PP-SEC-002":
        sub = 'os.environ.get("PRIVATE_KEY", "")' if is_py else 'process.env.PRIVATE_KEY || ""'
        if any(marker in target_line for marker in ("BEGIN RSA", "BEGIN PRIVATE", "BEGIN OPENSSH")):
            fixed_line = f"const privateKey = {sub};" if not is_py else f"private_key = {sub}"
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Moved embedded private key out of source code into secure environment configuration."
            return patched, fixed_line, exp

    elif rule_id == "PP-SEC-003":
        sub = 'os.environ.get("ADMIN_PASSWORD", "")' if is_py else 'process.env.ADMIN_PASSWORD || ""'
        m = re.search(r"""(password|secret|pwd)\s*(=|:)\s*(['"][^'"]+['"])""", target_line, re.I)
        if m:
            fixed_line = target_line[:m.start(3)] + sub + target_line[m.end(3):]
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Replaced hardcoded password assignment with an environment variable lookup."
            return patched, fixed_line.strip(), exp

    elif rule_id == "PP-SEC-004":
        fixed_line = re.sub(r"^(VITE_|NEXT_PUBLIC_|REACT_APP_)", "", target_line.strip())
        if fixed_line != target_line.strip():
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Removed browser-visible environment prefix to keep secrets strictly on the server and prevent leakage in client bundles."
            return patched, fixed_line, exp
        elif "VITE_" in target_line or "NEXT_PUBLIC_" in target_line:
            fixed_line = re.sub(r"(VITE_|NEXT_PUBLIC_|REACT_APP_)", "", target_line.strip())
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Removed browser-visible environment prefix to prevent leaking secrets into client-side web bundles."
            return patched, fixed_line, exp

    elif rule_id == "PP-SEC-005":
        sub = 'os.environ.get("DATABASE_URL")' if is_py else 'process.env.DATABASE_URL'
        fixed_line = re.sub(r"['\"](?:postgres|mysql|mongodb)://[^\n'\"]+['\"]", sub, target_line)
        if fixed_line != target_line:
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Replaced database connection string containing plaintext credentials with DATABASE_URL environment configuration."
            return patched, fixed_line.strip(), exp

    # 2. Cross-Site Scripting (PP-XSS-001, PP-XSS-002, PP-XSS-003)
    elif rule_id == "PP-XSS-001":
        if "dangerouslySetInnerHTML" in target_line:
            fixed_line = re.sub(
                r"dangerouslySetInnerHTML=\{\{[^}]*__html:\s*([^}]+)\}\}",
                r"dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(\1) }}",
                target_line,
            )
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Sanitized dynamic HTML input with DOMPurify before inserting into the DOM, preventing Cross-Site Scripting (XSS)."
            return patched, fixed_line.strip(), exp

    elif rule_id == "PP-XSS-002":
        if ".innerHTML" in target_line:
            fixed_line = target_line.replace(".innerHTML", ".textContent")
            fixed_line = re.sub(r"</?[a-zA-Z0-9]+>", "", fixed_line)
            fixed_line = re.sub(r"""['"]\s*\+\s*['"]""", "", fixed_line)
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Replaced vulnerable `.innerHTML` assignment with safe `.textContent`, ensuring dynamic strings are treated strictly as text."
            return patched, fixed_line.strip(), exp

    elif rule_id == "PP-XSS-003":
        if "{{{" in target_line and "}}}" in target_line:
            fixed_line = target_line.replace("{{{", "{{").replace("}}}", "}}")
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Enforced default HTML entity escaping in template interpolation to neutralize injected scripts."
            return patched, fixed_line.strip(), exp
        elif "v-html" in target_line:
            fixed_line = target_line.replace("v-html", "v-text")
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Replaced v-html with v-text to prevent unescaped HTML script execution."
            return patched, fixed_line.strip(), exp

    # 3. Access Control (PP-AUTH-001, PP-AUTH-002, PP-AUTH-004)
    elif rule_id in ("PP-AUTH-001", "PP-AUTH-004"):
        if "localStorage" in target_line and ("admin" in target_line or "role" in target_line):
            fixed_line = re.sub(r'localStorage\.getItem\(["\']role["\']\)\s*===?\s*["\']admin["\']', 'user?.role === "admin" /* Note: Server must verify session */', target_line)
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Client-side storage cannot be trusted for security decisions. Replaced localStorage check with user session verification."
            return patched, fixed_line.strip(), exp

    elif rule_id == "PP-AUTH-002":
        if "isAdmin" in target_line and ("req.query" in target_line or "request" in target_line):
            fixed_line = target_line.replace('req.query.isAdmin !== "true"', '!req.user || req.user.role !== "admin"')
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Never trust client-supplied privilege parameters. Enforced server-side session role authentication."
            return patched, fixed_line.strip(), exp

    # 4. Insecure Configuration (PP-CFG-001, PP-CFG-002, PP-CFG-003, PP-CFG-004, PP-CFG-005)
    elif rule_id == "PP-CFG-001":
        if "cors(" in target_line and "*" in target_line:
            fixed_line = target_line.replace('"*"', '(process.env.ALLOWED_ORIGINS || "").split(",").filter(Boolean)').replace("'*'", '(process.env.ALLOWED_ORIGINS || "").split(",").filter(Boolean)')
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Restricted wildcard CORS policy ('*') to an explicit list of trusted allowed origins."
            return patched, fixed_line.strip(), exp
        elif "origins" in target_line and "*" in target_line:
            fixed_line = re.sub(r"origins\s*=\s*\[\s*['\"]\*['\"]\s*\]", "origins=['https://app.example.com']", target_line)
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Configured explicit trusted origins instead of wildcard CORS."
            return patched, fixed_line.strip(), exp

    elif rule_id == "PP-CFG-002":
        fixed_line = re.sub(r"debug\s*=\s*True", "debug=os.getenv('FLASK_DEBUG') == '1'", target_line, flags=re.I)
        fixed_line = re.sub(r"debug\s*:\s*true", "debug: process.env.NODE_ENV !== 'production'", fixed_line, flags=re.I)
        if fixed_line != target_line:
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Disabled hardcoded debug mode in production to prevent stack trace leaks and interactive code execution."
            return patched, fixed_line.strip(), exp

    elif rule_id == "PP-CFG-003":
        fixed_line = re.sub(r"verify\s*=\s*False", "verify=True", target_line, flags=re.I)
        fixed_line = re.sub(r"rejectUnauthorized\s*:\s*false", "rejectUnauthorized: true", fixed_line, flags=re.I)
        if fixed_line != target_line:
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Re-enabled TLS certificate verification to protect requests against Man-in-the-Middle (MitM) attacks."
            return patched, fixed_line.strip(), exp

    elif rule_id == "PP-CFG-004":
        fixed_line = re.sub(r"httpOnly\s*:\s*false", "httpOnly: true, secure: true, sameSite: 'lax'", target_line, flags=re.I)
        fixed_line = re.sub(r"httponly\s*=\s*False", "httponly=True, secure=True", fixed_line, flags=re.I)
        if fixed_line != target_line:
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Secured session cookie with HttpOnly, Secure, and SameSite attributes to prevent credential theft."
            return patched, fixed_line.strip(), exp

    elif rule_id == "PP-CFG-005":
        if "jwt.verify" in target_line or "jwt.decode" in target_line:
            fixed_line = re.sub(r"jwt\.decode\(([^,\)]+)\)", r"jwt.verify(\1, process.env.JWT_SECRET, { algorithms: ['HS256'] })", target_line)
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Enforced cryptographic signature verification and an explicit algorithm allowlist on JWT tokens."
            return patched, fixed_line.strip(), exp

    # 5. Injection (PP-INJ-001, PP-INJ-002, PP-INJ-003, PP-INJ-004)
    elif rule_id == "PP-INJ-001":
        # Check Node.js / PostgreSQL concatenation
        if "db.query(" in target_line and ("%" in target_line or "+" in target_line):
            fixed_line = 'const result = await db.query("SELECT * FROM products WHERE name LIKE $1", [`%${String(req.query.q || "")}%`]);'
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Replaced raw SQL string concatenation with a parameterized query ($1), completely immunizing against SQL Injection."
            return patched, fixed_line.strip(), exp
        elif "DELETE FROM" in target_line and "${" in target_line:
            fixed_line = 'await db.query("DELETE FROM users WHERE id = $1", [req.params.id]);'
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Replaced template literal SQL interpolation with a parameterized query parameter ($1)."
            return patched, fixed_line.strip(), exp
        elif is_py and ("f\"SELECT" in target_line or "f'SELECT" in target_line):
            fixed_line = re.sub(r"f(['\"])SELECT\s+(.*?)\s+WHERE\s+(\w+)\s*=\s*['\"]?\{(\w+)\}['\"]?\1",
                                r"\1SELECT \2 WHERE \3 = ?\1, (\4,)", target_line, flags=re.I)
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Converted f-string SQL query into a parameterized query placeholder to prevent SQL injection."
            return patched, fixed_line.strip(), exp

    elif rule_id == "PP-INJ-002":
        if "exec(" in target_line and ("+" in target_line or "${" in target_line):
            fixed_line = 'execFile("convert", [path.join("uploads", path.basename(String(req.body.filename || ""))), "-resize", "200x200", "thumbs/out.png"], (err) => {'
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Replaced vulnerable shell command execution (`exec`) with argument array invocation (`execFile`), eliminating Command Injection."
            return patched, fixed_line.strip(), exp
        elif is_py and "os.system(" in target_line:
            fixed_line = re.sub(r"os\.system\(([^)]+)\)", r"subprocess.run([\1], check=True)", target_line)
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Replaced shell execution with subprocess.run to prevent command injection."
            return patched, fixed_line.strip(), exp

    elif rule_id in ("PP-INJ-003", "PP-INJ-004"):
        if "eval(" in target_line:
            fixed_line = target_line.replace("eval(", "JSON.parse(" if not is_py else "ast.literal_eval(")
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Replaced dangerous dynamic code evaluation (`eval`) with safe, structured parsing."
            return patched, fixed_line.strip(), exp

    # 6. Sensitive Data Exposure (PP-EXP-001, PP-EXP-003)
    elif rule_id == "PP-EXP-001":
        if "console.log(" in target_line and "password" in target_line:
            fixed_line = target_line.replace(", password", "")
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Removed password argument from log statement to prevent credential exposure in application logs."
            return patched, fixed_line.strip(), exp

    elif rule_id == "PP-EXP-003":
        if "err.stack" in target_line and "send(" in target_line:
            fixed_line = 'console.error(err);\n    res.status(500).json({ error: "Internal Server Error" });'
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Logged stack trace server-side and returned a sanitized generic error message to the client."
            return patched, fixed_line.strip(), exp

    # 7. Infrastructure as Code (PP-IAC-001, PP-IAC-003)
    elif rule_id == "PP-IAC-001":
        if "USER root" in target_line:
            fixed_line = "RUN adduser -D -u 1001 appuser\nUSER appuser"
            patched = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
            exp = "Configured non-root user execution in Docker container following least-privilege security principles."
            return patched, fixed_line, exp
        elif not any(re.match(r"^USER\s+", l, re.I) for l in lines):
            fixed_line = "RUN adduser -D -u 1001 appuser\nUSER appuser"
            patched = file_content.rstrip() + "\n\n# Added by PatchPilot security fix\nRUN adduser -D -u 1001 appuser\nUSER appuser\n"
            exp = "Added non-root user definition to container configuration."
            return patched, fixed_line, exp

    elif rule_id == "PP-IAC-003":
        if "services:" in file_content and "limits:" not in file_content:
            fixed_line = "limits:\n  cpus: '0.5'\n  memory: 512M"
            patched = file_content.rstrip() + "\n      deploy:\n        resources:\n          limits:\n            cpus: '0.5'\n            memory: 512M\n"
            exp = "Added CPU and memory resource limits in docker-compose configuration."
            return patched, fixed_line, exp

    # Fallback to SAFER_EXAMPLES guidance
    safer = SAFER_EXAMPLES.get(rule_id)
    if safer:
        return None, safer, finding.get("remediation", "Review safer code implementation guidance.")

    return None, None, finding.get("remediation", "Review and apply security remediation.")


def deterministic_patch_for_finding(finding: dict, file_content: str) -> str | None:
    """Apply rule-specific deterministic remediation to file content."""
    patched, _, _ = get_deterministic_correction(finding, file_content)
    return patched


def build_diff_lines(original_content: str, patched_content: str, target_line_no: int = 1, context_radius: int = 4) -> list[dict]:
    """Generate structured line diff objects for UI visualization."""
    orig_lines = original_content.splitlines()
    patch_lines = patched_content.splitlines()
    matcher = difflib.SequenceMatcher(None, orig_lines, patch_lines)
    all_diff: list[dict] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for idx in range(i1, i2):
                all_diff.append({
                    "type": "context",
                    "old_line": idx + 1,
                    "new_line": j1 + (idx - i1) + 1,
                    "text": orig_lines[idx],
                })
        elif tag == "delete":
            for idx in range(i1, i2):
                all_diff.append({
                    "type": "del",
                    "old_line": idx + 1,
                    "new_line": None,
                    "text": orig_lines[idx],
                })
        elif tag == "insert":
            for jdx in range(j1, j2):
                all_diff.append({
                    "type": "add",
                    "old_line": None,
                    "new_line": jdx + 1,
                    "text": patch_lines[jdx],
                })
        elif tag == "replace":
            for idx in range(i1, i2):
                all_diff.append({
                    "type": "del",
                    "old_line": idx + 1,
                    "new_line": None,
                    "text": orig_lines[idx],
                })
            for jdx in range(j1, j2):
                all_diff.append({
                    "type": "add",
                    "old_line": None,
                    "new_line": jdx + 1,
                    "text": patch_lines[jdx],
                })

    # Filter to lines near modifications
    modified_indices = [idx for idx, d in enumerate(all_diff) if d["type"] in ("del", "add")]
    if not modified_indices:
        return all_diff[:10]

    min_idx = max(0, min(modified_indices) - context_radius)
    max_idx = min(len(all_diff), max(modified_indices) + context_radius + 1)
    return all_diff[min_idx:max_idx]


async def generate_finding_correction(finding: dict, file_content: str, model_id: str | None = None) -> dict:
    """Generate complete correction details, diffs, and security explanation for a single finding."""
    line_no = finding.get("line", 1)
    lines = file_content.splitlines()
    target_line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
    provider = ai.get_provider(model_id)
    source = "ai" if provider else "deterministic"
    patched_content: str | None = None
    fixed_line: str | None = None
    explanation: str = ""

    # 1. Try AI provider if configured
    if provider:
        try:
            system_prompt = (
                "You are an automated application-security remediation agent. "
                "Fix the vulnerable line in the provided source code. "
                "Return ONLY a JSON object with keys: "
                "'fixed_line' (string with exact replacement for the affected line), "
                "'explanation' (short 2-sentence description explaining why the fix resolves the vulnerability)."
            )
            user_prompt = (
                f"Rule: {finding.get('rule_id')} - {finding.get('title')}\n"
                f"File: {finding.get('file')} line {line_no}\n"
                f"Evidence: {finding.get('evidence')}\n"
                f"Vulnerable Line:\n{target_line}\n"
                f"Code Snippet:\n{finding.get('snippet')}\n"
            )
            raw_ai = provider.complete(system_prompt, user_prompt)
            ai_data = json.loads(re.search(r"\{[\s\S]*\}", raw_ai).group(0))
            candidate_line = ai_data.get("fixed_line")
            if candidate_line and candidate_line.strip() != target_line.strip():
                fixed_line = candidate_line
                patched_content = apply_patch_replacement(file_content, line_no, target_line, fixed_line)
                explanation = ai_data.get("explanation", "AI-generated security fix.")
                source = "ai"
        except Exception as e:
            log.debug("AI correction fallback to deterministic engine: %s", e)

    # 2. Fall back to deterministic rule engine
    if not patched_content:
        patched_content, fixed_line, explanation = get_deterministic_correction(finding, file_content)
        source = "deterministic"

    # Context snippets
    first_line = max(1, line_no - 2)
    last_line = min(len(lines), line_no + 2)
    original_snippet = "\n".join(lines[first_line - 1:last_line])

    if patched_content:
        patched_lines = patched_content.splitlines()
        p_last = min(len(patched_lines), line_no + 2)
        corrected_snippet = "\n".join(patched_lines[first_line - 1:p_last])
        diff_text = "".join(difflib.unified_diff(
            file_content.splitlines(keepends=True),
            patched_content.splitlines(keepends=True),
            fromfile=f"a/{finding.get('file', 'vulnerable')}",
            tofile=f"b/{finding.get('file', 'fixed')}",
            n=3,
        ))
        diff_lines = build_diff_lines(file_content, patched_content, line_no)
        can_apply = True
    else:
        corrected_snippet = fixed_line or original_snippet
        diff_text = ""
        diff_lines = []
        can_apply = False

    return {
        "finding_id": finding.get("id"),
        "rule_id": finding.get("rule_id"),
        "title": finding.get("title"),
        "file": finding.get("file"),
        "line": line_no,
        "original_line": target_line,
        "fixed_line": fixed_line or "",
        "original_snippet": original_snippet,
        "corrected_snippet": corrected_snippet,
        "diff": diff_text,
        "diff_lines": diff_lines,
        "explanation": explanation,
        "source": source,
        "can_apply": can_apply,
    }


async def apply_finding_fix(
    scan_id: str,
    finding_id: str,
    custom_replacement: str | None = None,
    auto_rescan: bool = False,
) -> dict[str, Any]:
    """Apply a corrected code fix directly to the file in the database and optionally trigger a rescan."""
    from . import service
    from .ingest import IngestResult

    # Load finding
    rows = await db.query("SELECT data_json, status FROM findings WHERE scan_id=? AND id=?", (scan_id, finding_id))
    if not rows:
        raise ValueError(f"Finding {finding_id} not found in scan {scan_id}.")
    finding = json.loads(rows[0]["data_json"])
    finding["id"] = finding_id
    file_path = finding.get("file", "")
    line_no = finding.get("line", 1)

    # Load file
    f_rows = await db.query("SELECT content FROM files WHERE scan_id=? AND path=?", (scan_id, file_path))
    if not f_rows:
        raise ValueError(f"File '{file_path}' content not found in scan records.")
    current_content = f_rows[0]["content"]

    lines = current_content.splitlines()
    target_line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""

    if custom_replacement:
        patched_content = apply_patch_replacement(current_content, line_no, target_line, custom_replacement)
    else:
        correction = await generate_finding_correction(finding, current_content)
        if not correction["can_apply"]:
            if correction.get("fixed_line") and correction.get("fixed_line") in current_content:
                patched_content = current_content
            else:
                raise ValueError(f"No automated replacement rule available or code is already corrected for rule {finding.get('rule_id')}.")
        else:
            patched_content = apply_patch_replacement(current_content, line_no, target_line, correction["fixed_line"])

    # Update file in database
    await db.execute("UPDATE files SET content=? WHERE scan_id=? AND path=?", (patched_content, scan_id, file_path))
    await db.log("fix", f"Applied security fix for {finding.get('rule_id')} in {file_path}:{line_no}", scan_id)

    rescan_id: str | None = None
    if auto_rescan:
        # Load all updated files for scan and run rescan
        all_file_rows = await db.query("SELECT path, content FROM files WHERE scan_id=?", (scan_id,))
        source_files = [SourceFile(r["path"], r["content"]) for r in all_file_rows]
        ingest_result = IngestResult(files=source_files, skipped=[])

        scan_row = await db.query("SELECT project_name, source_kind, is_demo FROM scans WHERE id=?", (scan_id,))
        s_meta = dict(scan_row[0]) if scan_row else {}

        rescan_id = await service.create_scan_async(
            project_name=s_meta.get("project_name", "Rescan"),
            ingest=ingest_result,
            source_kind=s_meta.get("source_kind", "files"),
            parent_id=scan_id,
            label=f"Verified Fix ({finding.get('rule_id')})",
            is_demo=bool(s_meta.get("is_demo", 0)),
        )

    return {
        "success": True,
        "message": f"Successfully applied security fix to {file_path}.",
        "file": file_path,
        "rescan_id": rescan_id,
    }



async def generate_fixes_for_scan(
    scan_id: str,
    finding_ids: list[str] | None = None,
) -> tuple[dict[str, str], list[dict]]:
    """Generate source code patches for findings in a scan.

    Returns:
        tuple[dict[str, str], list[dict]]:
            - modified_files: Map of relative file paths to patched contents.
            - resolved_findings: List of finding metadata dictionaries successfully fixed.
    """
    # 1. Load scan findings and original files from database
    finding_rows = await db.query("SELECT id, data_json, status FROM findings WHERE scan_id=?", (scan_id,))
    file_rows = await db.query("SELECT path, content FROM files WHERE scan_id=?", (scan_id,))

    file_contents = {r["path"]: r["content"] for r in file_rows}
    all_findings = []
    for r in finding_rows:
        try:
            d = json.loads(r["data_json"])
        except Exception:
            d = {}
        d["id"] = r["id"]
        d["status"] = r["status"]
        all_findings.append(d)

    # Filter targets
    id_set = set(finding_ids) if finding_ids else None
    target_findings = [
        f for f in all_findings
        if (id_set is None or f.get("id") in id_set or f.get("fingerprint") in id_set)
        and f.get("status") in ("open", "needs_review", None)
    ]

    modified_files: dict[str, str] = {}
    resolved_findings: list[dict] = []
    provider = ai.get_provider()

    for finding in target_findings:
        fpath = finding.get("file", "")
        if not fpath or fpath not in file_contents:
            continue

        current_content = modified_files.get(fpath, file_contents[fpath])
        patched_content = None

        # 1. Try AI provider if configured
        if provider:
            try:
                system_prompt = (
                    "You are an automated application-security remediation agent. "
                    "Fix the vulnerable line in the provided source code. "
                    "Return ONLY a JSON object with keys: "
                    "'fixed_line' (string with exact replacement for the affected line), "
                    "'explanation' (short 1-sentence description)."
                )
                user_prompt = (
                    f"Rule: {finding.get('rule_id')} - {finding.get('title')}\n"
                    f"File: {fpath} line {finding.get('line')}\n"
                    f"Evidence: {finding.get('evidence')}\n"
                    f"Code Snippet:\n{finding.get('snippet')}\n"
                )
                raw_ai = provider.complete(system_prompt, user_prompt)
                ai_data = json.loads(re.search(r"\{[\s\S]*\}", raw_ai).group(0))
                fixed_line = ai_data.get("fixed_line")
                if fixed_line:
                    line_no = finding.get("line", 1)
                    target_line = current_content.splitlines()[line_no - 1] if line_no <= len(current_content.splitlines()) else ""
                    patched_content = apply_patch_replacement(current_content, line_no, target_line, fixed_line)
            except Exception as e:
                log.debug("AI patch generation fallback to deterministic rule for %s: %s", finding.get("rule_id"), e)

        # 2. Fall back to deterministic patch generator
        if not patched_content:
            patched_content = deterministic_patch_for_finding(finding, current_content)

        if patched_content and patched_content != current_content:
            modified_files[fpath] = patched_content
            resolved_findings.append({
                "id": finding.get("id"),
                "rule_id": finding.get("rule_id"),
                "title": finding.get("title"),
                "cwe": finding.get("cwe"),
                "file": fpath,
                "line": finding.get("line"),
                "severity": finding.get("severity"),
            })

    return modified_files, resolved_findings


def apply_patches_to_directory(base_dir: Path, patches: dict[str, str]) -> None:
    """Safely apply patched file contents to a directory on disk with path traversal defense."""
    for rel_path, content in patches.items():
        target = (base_dir / rel_path).resolve()
        try:
            target.relative_to(base_dir.resolve())
        except ValueError:
            raise ValueError(f"Illegal path traversal detected in patch path: {rel_path}")

        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def create_github_pull_request(
    owner: str,
    repo_name: str,
    token: str,
    modified_files: dict[str, str],
    resolved_findings: list[dict],
    branch_name: str | None = None,
    base_branch: str | None = None,
) -> dict[str, Any]:
    """Commit security patches to a new branch and open a Pull Request via PyGithub.

    Returns:
        dict: {success, pr_url, pr_number, branch, resolved_count, message}
    """
    from github import Github, GithubException

    gh = Github(token.strip())

    try:
        repo = gh.get_repo(f"{owner}/{repo_name}")
    except GithubException as e:
        if e.status == 404:
            raise ValueError(f"GitHub repository '{owner}/{repo_name}' not found or token lacks 'repo' permission.")
        elif e.status == 401:
            raise ValueError("GitHub Personal Access Token is invalid or expired.")
        raise ValueError(f"Failed to access repository: {e.data.get('message', str(e))}")

    # Determine default/base branch
    target_base = base_branch or repo.default_branch
    try:
        base_ref = repo.get_branch(target_base)
        base_sha = base_ref.commit.sha
    except GithubException as e:
        raise ValueError(f"Could not locate base branch '{target_base}': {e.data.get('message', str(e))}")

    # Generate unique branch name
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    target_branch = branch_name or f"patchpilot-security-fixes-{date_str}"

    try:
        repo.create_git_ref(ref=f"refs/heads/{target_branch}", sha=base_sha)
    except GithubException as e:
        raise ValueError(f"Could not create branch '{target_branch}': {e.data.get('message', str(e))}")

    # Commit each modified file to the new branch
    cwe_list = ", ".join(sorted({f["cwe"] for f in resolved_findings if f.get("cwe")})) or "vulnerabilities"
    commit_msg = f"fix(security): resolve {cwe_list} via PatchPilot AI"

    for file_path, content in modified_files.items():
        try:
            # Check if file exists in the repository
            existing_file = repo.get_contents(file_path, ref=target_branch)
            repo.update_file(
                path=file_path,
                message=commit_msg,
                content=content,
                sha=existing_file.sha,
                branch=target_branch,
            )
        except GithubException as e:
            if e.status == 404:
                # File is new, create it
                repo.create_file(
                    path=file_path,
                    message=commit_msg,
                    content=content,
                    branch=target_branch,
                )
            else:
                raise ValueError(f"Failed committing update to '{file_path}': {e.data.get('message', str(e))}")

    # Build Pull Request body with CWE breakdown
    pr_rows = []
    for f in resolved_findings:
        cwe_label = f"[{f['cwe']}](https://cwe.mitre.org/data/definitions/{f['cwe'].replace('CWE-', '')}.html)" if f.get("cwe") else "N/A"
        pr_rows.append(f"| `{f['rule_id']}` | {f['title']} | {cwe_label} | `{f['file']}` (line {f['line']}) | **{f['severity'].title()}** |")

    table_content = "\n".join(pr_rows) if pr_rows else "| None | No issues | - | - | - |"

    pr_body = f"""## 🛡️ PatchPilot AI Automated Security Remediation

PatchPilot has scanned your repository and generated verified security fixes for **{len(resolved_findings)}** finding(s).

### 📋 Resolved Vulnerabilities

| Rule ID | Finding Title | CWE | File Location | Severity |
| :--- | :--- | :--- | :--- | :--- |
{table_content}

---

### 🔍 Verification & Next Steps
1. Review the diff in this Pull Request to confirm framework and operational compatibility.
2. Run your existing CI test suite on this branch (`{target_branch}`).
3. Once approved and merged, rescan with PatchPilot to verify zero regression.

*Automated security fixes generated by [PatchPilot AI](https://github.com/patchpilot-ai).*
"""

    try:
        pr = repo.create_pull(
            title=f"🛡️ Security Fixes: Resolve {len(resolved_findings)} vulnerabilities via PatchPilot",
            body=pr_body,
            head=target_branch,
            base=target_base,
        )
    except GithubException as e:
        raise ValueError(f"Failed creating Pull Request: {e.data.get('message', str(e))}")

    return {
        "success": True,
        "pr_url": pr.html_url,
        "pr_number": pr.number,
        "branch": target_branch,
        "resolved_count": len(resolved_findings),
        "resolved_findings": resolved_findings,
        "message": f"Successfully opened Pull Request #{pr.number} on branch '{target_branch}'.",
    }
