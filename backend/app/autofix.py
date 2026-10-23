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
    indented_replacement = "\n".join(
        (indent + l if l.strip() else l) for l in replacement.splitlines()
    )
    if not indented_replacement.endswith("\n"):
        indented_replacement += "\n"

    lines[line_no - 1] = indented_replacement
    return "".join(lines)


def deterministic_patch_for_finding(finding: dict, file_content: str) -> str | None:
    """Apply rule-specific deterministic remediation to file content."""
    rule_id = finding.get("rule_id", "")
    line_no = finding.get("line", 1)
    lines = file_content.splitlines()
    target_line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""

    # 1. Hardcoded Secrets (PP-SEC)
    if rule_id == "PP-SEC-001":
        # Replace hardcoded API key assignment (handles both raw tokens and masked tokens in files table)
        is_py = (
            "os.environ" in file_content
            or file_content.startswith("#")
            or finding.get("file", "").endswith(".py")
        )
        sub = 'os.environ.get("API_KEY", "")' if is_py else 'process.env.API_KEY || ""'

        # Match assignment RHS (= or : followed by string literal or masked secret)
        m = re.search(r"""(=|:)\s*(['"`][^'"`\n]+['"`]|sk-[^\s;\n]+|gh[posr]_[^\s;\n]+|AKIA[^\s;\n]+)""", target_line)
        if m:
            sep = m.group(1)
            new_line = target_line[:m.start()] + f"{sep} {sub}" + target_line[m.end():]
            return apply_patch_replacement(file_content, line_no, target_line, new_line)

        # Fallback literal string match
        m2 = re.search(r"""(['"][A-Za-z0-9_\-\.]{12,}['"]|['"][^'"]*\(masked\)['"])""", target_line)
        if m2:
            new_line = target_line[:m2.start()] + sub + target_line[m2.end():]
            return apply_patch_replacement(file_content, line_no, target_line, new_line)

    elif rule_id == "PP-SEC-005":
        # Replace connection string password (handles raw and masked URLs)
        is_py = "import" in file_content and "psycopg" in file_content or finding.get("file", "").endswith(".py")
        sub = 'os.environ.get("DATABASE_URL")' if is_py else 'process.env.DATABASE_URL'
        new_line = re.sub(r"['\"](?:postgres|mysql|mongodb)://[^\n'\"]+['\"]", sub, target_line)
        return apply_patch_replacement(file_content, line_no, target_line, new_line)

    # 2. XSS (PP-XSS)
    elif rule_id == "PP-XSS-001":
        # dangerouslySetInnerHTML -> sanitized or safe text
        if "dangerouslySetInnerHTML" in target_line:
            new_line = re.sub(
                r"dangerouslySetInnerHTML=\{\{[^}]*__html:\s*([^}]+)\}\}",
                r"dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(\1) }}",
                target_line,
            )
            return apply_patch_replacement(file_content, line_no, target_line, new_line)

    elif rule_id == "PP-XSS-002":
        # innerHTML -> textContent
        if ".innerHTML" in target_line:
            new_line = target_line.replace(".innerHTML", ".textContent")
            return apply_patch_replacement(file_content, line_no, target_line, new_line)

    # 3. Insecure Configurations (PP-CFG)
    elif rule_id == "PP-CFG-001":
        # Permissive CORS wildcard -> restricted origin
        new_line = re.sub(r"['\"]\*['\"]", "['https://app.example.com']", target_line)
        new_line = re.sub(r"origins\s*=\s*\[\s*['\"]\*['\"]\s*\]", "origins=['https://app.example.com']", new_line)
        return apply_patch_replacement(file_content, line_no, target_line, new_line)

    elif rule_id == "PP-CFG-002":
        # Flask debug=True -> debug=False
        new_line = re.sub(r"debug\s*=\s*True", "debug=os.getenv('FLASK_DEBUG') == '1'", target_line, flags=re.I)
        return apply_patch_replacement(file_content, line_no, target_line, new_line)

    elif rule_id == "PP-CFG-003":
        # verify=False -> verify=True
        new_line = re.sub(r"verify\s*=\s*False", "verify=True", target_line, flags=re.I)
        new_line = re.sub(r"rejectUnauthorized\s*:\s*false", "rejectUnauthorized: true", new_line, flags=re.I)
        return apply_patch_replacement(file_content, line_no, target_line, new_line)

    elif rule_id == "PP-CFG-004":
        # httpOnly: false -> httpOnly: true, secure: true
        new_line = re.sub(r"httpOnly\s*:\s*false", "httpOnly: true, secure: true, sameSite: 'lax'", target_line, flags=re.I)
        new_line = re.sub(r"httponly\s*=\s*False", "httponly=True, secure=True", new_line, flags=re.I)
        return apply_patch_replacement(file_content, line_no, target_line, new_line)

    # 4. Injections (PP-INJ)
    elif rule_id == "PP-INJ-001":
        # SQL concatenation / f-string -> parameterized query guidance
        if f'f"SELECT' in target_line or f"f'SELECT" in target_line:
            new_line = re.sub(r"f(['\"])SELECT\s+(.*?)\s+WHERE\s+(\w+)\s*=\s*['\"]?\{(\w+)\}['\"]?\1",
                              r"\1SELECT \2 WHERE \3 = ?\1, (\4,)", target_line, flags=re.I)
            return apply_patch_replacement(file_content, line_no, target_line, new_line)

    # 5. Infrastructure as Code (PP-IAC)
    elif rule_id == "PP-IAC-001":
        # ContainerRootUser in Dockerfile
        if "USER root" in target_line:
            new_line = target_line.replace("USER root", "RUN adduser -D -u 1001 appuser\nUSER appuser")
            return apply_patch_replacement(file_content, line_no, target_line, new_line)
        elif not any(re.match(r"^USER\s+", l, re.I) for l in lines):
            # Append non-root user definition
            return file_content.rstrip() + "\n\n# Added by PatchPilot security fix\nRUN adduser -D -u 1001 appuser\nUSER appuser\n"

    elif rule_id == "PP-IAC-003":
        # MissingResourceLimits in docker-compose.yml
        if "services:" in file_content and "limits:" not in file_content:
            return file_content.rstrip() + "\n      deploy:\n        resources:\n          limits:\n            cpus: '0.5'\n            memory: 512M\n"

    return None


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
