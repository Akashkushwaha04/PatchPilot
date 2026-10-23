"""Comprehensive test suite for PatchPilot backend features, concurrency, and security controls.

Covers:
1. Malformed ZIP files during streaming & cleanup.
2. Concurrency and WAL mode in aiosqlite database.
3. Unexpected AST structures & circular AST graphs in ast_parser.
4. Network timeout resilience and error handling in SCA.
5. Dynamic secret verification (active vs revoked tokens, timeouts, SSRF defense).
6. Security validation & SSRF defense in Playwright DAST scanner.
7. Path traversal and argument injection prevention in Semgrep wrapper.
"""
from __future__ import annotations

import asyncio
import io
import json
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app import db
from app.ingest import IngestError, ingest_zip, ingest_zip_stream
from app.scanner import (
    Finding,
    SourceFile,
    extract_dependencies,
    query_osv_package,
    run_sca_scan,
    verify_finding_secret,
    verify_token_active,
)
from app.scanner.ast_parser import _is_py_literal, _walk_js, parse_python_ast
from app.scanner.semgrep import run_semgrep_on_directory, run_semgrep_on_files
from app.urlscan import UrlScanError, check_ip, validate_url


# ----------------------------------------------------------------
# 1. Malformed ZIP files during streaming
# ----------------------------------------------------------------

def test_streaming_corrupt_zip_header_raises_ingest_error():
    corrupt_stream = io.BytesIO(b"PK\x03\x04CORRUPTDATA1234567890NOTAZIP")
    with pytest.raises(IngestError) as exc_info:
        ingest_zip_stream(corrupt_stream)
    assert "not a valid ZIP archive" in str(exc_info.value)


def test_streaming_truncated_member_raises_ingest_error():
    # Construct a ZIP file with a truncated stream
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app.js", "console.log('hello world');" * 100)
    data = buf.getvalue()

    # Truncate file bytes abruptly in the middle
    truncated_data = data[:len(data) - 40]
    with pytest.raises(IngestError):
        ingest_zip_stream(io.BytesIO(truncated_data))


def test_streaming_oversized_upload_raises_413():
    # Stream exceeding max_upload_size limit
    dummy_data = io.BytesIO(b"x" * 1024)
    with pytest.raises(IngestError) as exc_info:
        ingest_zip_stream(dummy_data, max_upload_size=500)
    assert exc_info.value.status == 413
    assert "exceeds" in str(exc_info.value)


def test_streaming_path_traversal_entry_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0:::")
    buf.seek(0)
    with pytest.raises(IngestError) as exc_info:
        ingest_zip_stream(buf)
    assert "path traversal" in str(exc_info.value)


# ----------------------------------------------------------------
# 2. Concurrency and SQLite WAL operations
# ----------------------------------------------------------------

@pytest.mark.anyio
async def test_concurrent_aiosqlite_operations(tmp_path):
    test_db = tmp_path / "test_concurrent.db"
    db.reset_for_tests(str(test_db))
    await db.init_db()

    # Perform 50 concurrent async database operations
    async def insert_worker(i: int):
        await db.execute(
            "INSERT INTO scans(id, project_name, created_at, source_kind, file_count, skipped_json, score_json, counts_json) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (f"scan-{i}", f"proj-{i}", db.now(), "zip", 1, "[]", '{"score": 100}', "{}"),
        )
        rows = await db.query("SELECT id FROM scans WHERE id=?", (f"scan-{i}",))
        assert len(rows) == 1
        assert rows[0]["id"] == f"scan-{i}"

    tasks = [insert_worker(i) for i in range(50)]
    await asyncio.gather(*tasks)

    # Verify all 50 scans were saved cleanly
    total = await db.query("SELECT COUNT(*) as c FROM scans")
    assert total[0]["c"] == 50

    await db.close_db()


# ----------------------------------------------------------------
# 3. Unexpected AST structures & circular AST graphs
# ----------------------------------------------------------------

def test_ast_parser_handles_circular_js_ast():
    # Create circular AST structure
    class MockNode:
        def __init__(self, ntype):
            self.type = ntype
            self.child = None

    node_a = MockNode("Program")
    node_b = MockNode("BlockStatement")
    node_a.child = node_b
    node_b.child = node_a  # Direct cycle!

    visited_count = 0

    def visitor(node):
        nonlocal visited_count
        visited_count += 1

    # Should walk without raising RecursionError
    _walk_js(node_a, visitor)
    assert visited_count == 2


def test_ast_parser_handles_node_without_dict():
    class SlottedNode:
        __slots__ = ("type", "value")

        def __init__(self):
            self.type = "Custom"
            self.value = 123

    node = SlottedNode()
    visited = []
    _walk_js(node, lambda n: visited.append(n.type))
    assert visited == ["Custom"]


def test_ast_parser_recognizes_unary_literals():
    tree = parse_python_ast("x = -42\ny = +100\nz = -3.14")
    assert tree is not None
    # Verify unary negative numbers are recognized as literals
    assigns = [node.value for node in tree.body]
    assert all(_is_py_literal(val) for val in assigns)


def test_ast_parser_syntax_error_returns_none():
    assert parse_python_ast("def broken_syntax(:::") is None


# ----------------------------------------------------------------
# 4. SCA network timeouts and resilience
# ----------------------------------------------------------------

@pytest.mark.anyio
async def test_sca_network_timeout_handles_gracefully():
    dep = extract_dependencies([SourceFile("requirements.txt", "requests==2.20.0\n")])[0]

    # Mock client that raises TimeoutException
    mock_client = AsyncMock()
    mock_client.post.side_effect = httpx.TimeoutException("Connection timed out after 10.0s")

    findings = await query_osv_package(mock_client, dep)
    # Should handle timeout and return empty list without crashing
    assert findings == []


@pytest.mark.anyio
async def test_sca_http_error_handles_gracefully():
    dep = extract_dependencies([SourceFile("package.json", '{"dependencies": {"lodash": "4.17.15"}}')])[0]

    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 503  # Service Unavailable
    mock_client.post.return_value = mock_resp

    findings = await query_osv_package(mock_client, dep)
    assert findings == []


@pytest.mark.anyio
async def test_sca_successful_vulnerability_mapping():
    dep = extract_dependencies([SourceFile("requirements.txt", "urllib3==1.24.1\n")])[0]

    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "vulns": [{
            "id": "GHSA-v845-jxx5-vc9f",
            "summary": "CRLF injection in urllib3",
            "details": "urllib3 versions before 1.24.2 are vulnerable to CRLF injection.",
            "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-93"]},
            "affected": [{"ranges": [{"events": [{"fixed": "1.24.2"}]}]}],
        }]
    }
    mock_client.post.return_value = mock_resp

    findings = await query_osv_package(mock_client, dep)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "PP-SCA-GHSA-v845-jxx5-vc9f"
    assert f.severity == "high"
    assert f.cwe == "CWE-93"
    assert "Upgrade to version 1.24.2" in f.remediation


# ----------------------------------------------------------------
# 5. Dynamic secret verification (Active vs Revoked, Timeouts, SSRF)
# ----------------------------------------------------------------

@pytest.mark.anyio
async def test_dynamic_secret_active_github_token():
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"login": "octocat", "id": 1}
    mock_client.get.return_value = mock_resp

    res = await verify_token_active("ghp_123456789012345678901234567890123456", client=mock_client)
    assert res.status == "active"
    assert res.recommended_severity == "critical"
    assert "octocat" in res.detail


@pytest.mark.anyio
async def test_dynamic_secret_revoked_github_token():
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.json.return_value = {"message": "Bad credentials"}
    mock_client.get.return_value = mock_resp

    res = await verify_token_active("ghp_123456789012345678901234567890123456", client=mock_client)
    assert res.status == "revoked"
    assert res.recommended_severity == "info"
    assert "revoked" in res.detail.lower()


@pytest.mark.anyio
async def test_dynamic_secret_aws_active_signature_mismatch():
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = "<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>"
    mock_client.get.return_value = mock_resp

    res = await verify_token_active("AKIAIOSFODNN7EXAMPLE", provider="aws", client=mock_client)
    assert res.status == "active"
    assert res.recommended_severity == "critical"


@pytest.mark.anyio
async def test_dynamic_secret_aws_invalid_client_token():
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = "<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>"
    mock_client.get.return_value = mock_resp

    res = await verify_token_active("AKIA9999999999EXAMPLE", provider="aws", client=mock_client)
    assert res.status == "revoked"
    assert res.recommended_severity == "info"


@pytest.mark.anyio
async def test_dynamic_secret_timeout_handling():
    mock_client = AsyncMock()
    mock_client.get.side_effect = httpx.TimeoutException("Connection timed out")

    res = await verify_token_active("ghp_123456789012345678901234567890123456", client=mock_client)
    assert res.status == "timeout"
    assert res.recommended_severity is None


@pytest.mark.anyio
async def test_dynamic_secret_ssrf_disallowed_provider():
    res = await verify_token_active("secret_token_123", provider="evil-internal-host.com")
    assert res.status == "unverified"
    assert "whitelist" in res.detail


@pytest.mark.anyio
async def test_verify_finding_secret_promotes_severity():
    f = Finding(
        rule_id="PP-SEC-001",
        title="Hardcoded GitHub Token",
        category="Secrets",
        description="A GitHub token was found.",
        severity="high",
        confidence="medium",
        kind="heuristic",
        file="src/client.ts",
        line=10,
        snippet="const token = 'ghp_123456789012345678901234567890123456';",
        evidence="Token ghp_123456789012345678901234567890123456 found",
        impact="Compromises repo access.",
        remediation="Rotate token.",
        line_text="ghp_123456789012345678901234567890123456",
    )

    with patch("app.scanner.secret_verify.verify_token_active") as mock_v:
        from app.scanner.secret_verify import TokenVerificationResult
        mock_v.return_value = TokenVerificationResult(
            token_masked="ghp_...3456",
            provider="github",
            status="active",
            recommended_severity="critical",
            detail="Active GitHub token verified via API",
            http_status=200,
        )
        updated = await verify_finding_secret(f)
        assert updated.severity == "critical"
        assert "ACTIVE" in updated.evidence


# ----------------------------------------------------------------
# 6. Security validation & SSRF defense in URL scanner
# ----------------------------------------------------------------

def test_urlscan_blocks_loopback_and_internal_ips():
    with pytest.raises(UrlScanError) as exc:
        validate_url("http://127.0.0.1/api")
    assert "non-public" in str(exc.value)

    with pytest.raises(UrlScanError) as exc:
        validate_url("http://localhost:80/")
    assert "blocked" in str(exc.value)

    with pytest.raises(UrlScanError) as exc:
        validate_url("http://192.168.1.1/admin")
    assert "non-public" in str(exc.value)


def test_urlscan_blocks_cloud_metadata_endpoints():
    with pytest.raises(UrlScanError) as exc:
        check_ip("169.254.169.254")
    assert "metadata" in str(exc.value).lower() or "non-public" in str(exc.value).lower()


def test_urlscan_blocks_disallowed_ports():
    with pytest.raises(UrlScanError) as exc:
        validate_url("http://example.com:22/")
    assert "standard web ports" in str(exc.value)


# ----------------------------------------------------------------
# 7. Semgrep argument injection & file staging safety
# ----------------------------------------------------------------

def test_semgrep_invalid_config_falls_back_to_auto():
    with patch("subprocess.Popen") as mock_popen:
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("{}", "")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        # Injection attempt in config parameter
        run_semgrep_on_directory(".", config="p/audit; rm -rf /")

        cmd = mock_popen.call_args[0][0]
        # Must fall back to 'auto' to prevent flag/subcommand injection
        assert "--config=auto" in cmd


def test_semgrep_staging_disallows_path_traversal():
    malicious_file = SourceFile("../../evil.py", "import os; os.system('ls')")
    with patch("app.scanner.semgrep.run_semgrep_on_directory") as mock_run:
        mock_run.return_value = []
        with patch("app.scanner.semgrep.is_semgrep_available", return_value=True):
            run_semgrep_on_files([malicious_file])
            # The staged directory must not contain the escaped path
            staged_root = mock_run.call_args[0][0]
            assert not (Path(staged_root).parent / "evil.py").exists()
