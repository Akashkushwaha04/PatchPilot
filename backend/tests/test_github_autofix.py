"""Unit and integration tests for GitHub URL Ingestion and AI Auto-Fix PR workflow."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from app import db
from app.autofix import (
    apply_patch_replacement,
    apply_patches_to_directory,
    create_github_pull_request,
    deterministic_patch_for_finding,
    generate_fixes_for_scan,
)
from app.ingest import IngestError, download_github_repo, parse_github_repo_url
from app.main import app


@pytest.fixture
def client(tmp_path):
    test_db = tmp_path / "test_gh.db"
    db.reset_for_tests(str(test_db))
    with TestClient(app) as c:
        yield c


# ----------------------------------------------------------------
# 1. GitHub URL Parsing & SSRF Validation
# ----------------------------------------------------------------

def test_parse_valid_github_repo_urls():
    assert parse_github_repo_url("https://github.com/octocat/Hello-World") == ("octocat", "Hello-World")
    assert parse_github_repo_url("https://github.com/octocat/Hello-World.git") == ("octocat", "Hello-World")
    assert parse_github_repo_url("http://github.com/owner/my-repo/") == ("owner", "my-repo")
    assert parse_github_repo_url("github.com/facebook/react") == ("facebook", "react")
    assert parse_github_repo_url("https://www.github.com/django/django") == ("django", "django")


def test_parse_github_repo_url_ssrf_and_invalid_formats():
    # Non-github domain
    with pytest.raises(IngestError) as exc:
        parse_github_repo_url("https://gitlab.com/owner/repo")
    assert "not a valid GitHub" in str(exc.value)

    # Embedded credentials in URL
    with pytest.raises(IngestError) as exc:
        parse_github_repo_url("https://user:password@github.com/owner/repo")
    assert "credentials are not allowed" in str(exc.value)

    # IP address / internal domain
    with pytest.raises(IngestError):
        parse_github_repo_url("http://127.0.0.1/owner/repo")

    # Incomplete URL
    with pytest.raises(IngestError):
        parse_github_repo_url("https://github.com/")


# ----------------------------------------------------------------
# 2. GitHub Archive Download API
# ----------------------------------------------------------------

@pytest.mark.anyio
async def test_download_github_repo_success():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("repo-main/index.js", "console.log('hi');")
    mock_zip_bytes = buf.getvalue()

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = mock_zip_bytes
        mock_get.return_value = mock_resp

        data, owner, repo, ref = await download_github_repo("https://github.com/octocat/Hello-World")
        assert owner == "octocat"
        assert repo == "Hello-World"
        assert len(data) > 0


@pytest.mark.anyio
async def test_download_github_repo_not_found_404():
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        with pytest.raises(IngestError) as exc:
            await download_github_repo("https://github.com/octocat/Private-Repo")
        assert exc.value.status == 404
        assert "private" in str(exc.value).lower()


@pytest.mark.anyio
async def test_download_github_repo_unauthorized_401():
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp

        with pytest.raises(IngestError) as exc:
            await download_github_repo("https://github.com/octocat/Private-Repo", token="bad_token")
        assert exc.value.status == 401
        assert "authentication failed" in str(exc.value).lower()


# ----------------------------------------------------------------
# 3. Code Patching & Autofix Engine
# ----------------------------------------------------------------

def test_apply_patch_replacement():
    code = "function test() {\n    const x = 1;\n    const y = 2;\n}"
    patched = apply_patch_replacement(code, 2, "const x = 1;", "const x = 100;")
    assert "const x = 100;" in patched
    assert "const y = 2;" in patched


def test_deterministic_patch_for_hardcoded_secret():
    code = "const apiKey = 'sk-proj-Zt4qN8vR2mX7kL9pW3sB6yH1jF5dC0aEuG2rT8wQ';\n"
    finding = {
        "rule_id": "PP-SEC-001",
        "line": 1,
        "file": "config.js",
    }
    patched = deterministic_patch_for_finding(finding, code)
    assert patched is not None
    assert "process.env.API_KEY" in patched
    assert "sk-proj-" not in patched


def test_deterministic_patch_for_tls_disabled():
    code = "response = requests.get(url, verify=False)\n"
    finding = {
        "rule_id": "PP-CFG-003",
        "line": 1,
        "file": "client.py",
    }
    patched = deterministic_patch_for_finding(finding, code)
    assert patched is not None
    assert "verify=True" in patched


def test_apply_patches_to_directory_disallows_path_traversal(tmp_path):
    patches = {
        "../../escaped.js": "console.log('malicious');",
    }
    with pytest.raises(ValueError) as exc:
        apply_patches_to_directory(tmp_path, patches)
    assert "path traversal" in str(exc.value).lower()


# ----------------------------------------------------------------
# 4. PyGithub Pull Request Creation
# ----------------------------------------------------------------

def test_create_github_pull_request_success():
    with patch("github.Github") as mock_gh_class:
        mock_gh = MagicMock()
        mock_repo = MagicMock()
        mock_repo.default_branch = "main"

        mock_branch = MagicMock()
        mock_branch.commit.sha = "abc123sha"
        mock_repo.get_branch.return_value = mock_branch

        mock_file = MagicMock()
        mock_file.sha = "filesha123"
        mock_repo.get_contents.return_value = mock_file

        mock_pr = MagicMock()
        mock_pr.number = 42
        mock_pr.html_url = "https://github.com/octocat/Hello-World/pull/42"
        mock_repo.create_pull.return_value = mock_pr

        mock_gh.get_repo.return_value = mock_repo
        mock_gh_class.return_value = mock_gh

        res = create_github_pull_request(
            owner="octocat",
            repo_name="Hello-World",
            token="ghp_mocktoken12345678901234567890123456",
            modified_files={"config.js": "const apiKey = process.env.API_KEY;"},
            resolved_findings=[{
                "id": "f-1",
                "rule_id": "PP-SEC-001",
                "title": "Hardcoded Secret",
                "cwe": "CWE-798",
                "file": "config.js",
                "line": 1,
                "severity": "critical",
            }],
        )

        assert res["success"] is True
        assert res["pr_number"] == 42
        assert "pull/42" in res["pr_url"]
        mock_repo.create_git_ref.assert_called_once()
        mock_repo.update_file.assert_called_once()
        mock_repo.create_pull.assert_called_once()


# ----------------------------------------------------------------
# 5. Integration: API Endpoints (POST /api/scans/github & autofix)
# ----------------------------------------------------------------

def test_api_scan_github_and_autofix_flow(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "repo-main/config.js",
            "const apiKey = 'sk-proj-Zt4qN8vR2mX7kL9pW3sB6yH1jF5dC0aEuG2rT8wQ';\n",
        )
    mock_zip = buf.getvalue()

    with patch("app.main.download_github_repo") as mock_dl:
        mock_dl.return_value = (mock_zip, "testowner", "testrepo", "main")

        # 1. Ingest via GitHub endpoint
        resp = client.post("/api/scans/github", json={
            "repo_url": "https://github.com/testowner/testrepo",
            "github_token": "ghp_mocktoken12345678901234567890123456",
        })
        assert resp.status_code == 201
        data = resp.json()
        scan_id = data["id"]
        assert data["source_kind"] == "github"

        # 2. Run autofix and create Pull Request
        with patch("app.autofix.create_github_pull_request") as mock_pr:
            mock_pr.return_value = {
                "success": True,
                "pr_url": "https://github.com/testowner/testrepo/pull/1",
                "pr_number": 1,
                "branch": "patchpilot-security-fixes-test",
                "resolved_count": 1,
                "resolved_findings": [{"rule_id": "PP-SEC-001", "file": "config.js", "cwe": "CWE-798"}],
                "message": "PR created",
            }

            fix_resp = client.post(f"/api/scans/{scan_id}/autofix", json={
                "branch_name": "patchpilot-security-fixes-test",
            })
            assert fix_resp.status_code == 200
            fix_data = fix_resp.json()
            assert fix_data["success"] is True
            assert fix_data["pr_number"] == 1
            assert "pull/1" in fix_data["pr_url"]
