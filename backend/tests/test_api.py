"""API, ingestion, AI-fallback and end-to-end demo tests."""
import io
import zipfile

import pytest

from app import ai
from app.ingest import MAX_ARCHIVE_BYTES, IngestError, ingest_zip, normalize_path

SYNTH_KEY = "sk-proj-Zt4qN8vR2mX7kL9pW3sB6yH1jF5dC0aEuG2rT8wQ"


def make_zip(entries: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


# --- ingestion ---------------------------------------------------------------

@pytest.mark.parametrize("name", ["../evil.js", "a/../../evil.js", "/etc/passwd.js", "C:/x.js", "..\\win.js"])
def test_zip_path_traversal_rejected(name):
    with pytest.raises(IngestError):
        normalize_path(name)
    with pytest.raises(IngestError):
        ingest_zip(make_zip({"ok.js": "a", name: "b"}))


def test_oversized_archive_rejected():
    with pytest.raises(IngestError) as e:
        ingest_zip(b"PK" + b"0" * (MAX_ARCHIVE_BYTES + 1))
    assert e.value.status == 413


def test_zip_bomb_ratio_rejected():
    with pytest.raises(IngestError) as e:
        ingest_zip(make_zip({"big.js": "a" * 900_000}))
    assert "compression ratio" in str(e.value)


def test_binary_and_unsupported_skipped():
    res = ingest_zip(make_zip({"p/app.js": "let a = 1;", "p/logo.png": b"\x89PNG\x00\x00", "p/fake.js": b"\x00\x01\x02", "p/node_modules/x.js": "y"}))
    assert [f.path for f in res.files] == ["app.js"]  # common root stripped
    reasons = {s["path"]: s["reason"] for s in res.skipped}
    assert reasons["p/logo.png"] == "unsupported file type" and reasons["p/fake.js"] == "binary content"


def test_api_upload_errors(client):
    r = client.post("/api/scans", data={"project_name": "x"}, files={"archive": ("x.zip", make_zip({"../a.js": "1"}), "application/zip")})
    assert r.status_code == 400 and "traversal" in r.json()["detail"]
    r = client.post("/api/scans", data={"project_name": "x"}, files={"files": ("img.png", b"\x89PNG", "image/png")})
    assert r.status_code == 415
    r = client.post("/api/scans", data={"project_name": "x"})
    assert r.status_code == 422


# --- scanning through the API --------------------------------------------------

def test_scan_never_returns_full_secret(client):
    z = make_zip({"src/config.js": f'export const K = "{SYNTH_KEY}";\n', ".env": "VITE_X_SECRET=paysec_9fK2mQ7xR4tV8wZ1\n"})
    r = client.post("/api/scans", data={"project_name": "Leaky"}, files={"archive": ("p.zip", z, "application/zip")})
    assert r.status_code == 201
    sid = r.json()["id"]
    blobs = [
        client.get(f"/api/scans/{sid}/findings").text,
        client.get(f"/api/scans/{sid}/file", params={"path": "src/config.js"}).text,
        client.get(f"/api/scans/{sid}/report?format=md").text,
        client.get(f"/api/scans/{sid}/report?format=json").text,
        client.post(f"/api/scans/{sid}/repair-prompt", json={}).text,
    ]
    for b in blobs:
        assert SYNTH_KEY not in b and "paysec_9fK2mQ7xR4tV8wZ1" not in b


def test_individual_file_upload(client):
    r = client.post("/api/scans", data={"project_name": "Files"},
                    files=[("files", ("server/app.py", b"app.run(debug=True)\n", "text/plain")),
                           ("files", ("src/C.jsx", b"<div dangerouslySetInnerHTML={{ __html: c.body }} />\n", "text/plain"))])
    assert r.status_code == 201
    rules = {f["rule_id"] for f in client.get(f"/api/scans/{r.json()['id']}/findings").json()}
    assert rules == {"PP-CFG-002", "PP-XSS-001"}


def test_cannot_mark_fixed_manually(client):
    sid = client.post("/api/demo/scan").json()["id"]
    fid = client.get(f"/api/scans/{sid}/findings").json()[0]["id"]
    assert client.patch(f"/api/scans/{sid}/findings/{fid}", json={"status": "fixed"}).status_code == 409
    r = client.patch(f"/api/scans/{sid}/findings/{fid}", json={"status": "accepted_risk"})
    assert r.status_code == 200 and r.json()["status"] == "accepted_risk"


# --- AI fallback -------------------------------------------------------------

class BrokenProvider:
    name = "broken"

    def complete(self, system, user):
        raise ai.AIError("Provider timed out.")


class GarbageProvider:
    name = "garbage"

    def complete(self, system, user):
        return "Sure! Here is not JSON."


class CapturingProvider:
    name = "capture"

    def __init__(self):
        self.seen = ""

    def complete(self, system, user):
        self.seen = system + user
        return ('{"what_the_code_does":"a","why_risky":"b","impact_example":"c","recommended_fix":"d",'
                f'"safer_code_example":"use {SYNTH_KEY}","verification_steps":["e","f"]}}')


@pytest.mark.parametrize("provider", [BrokenProvider(), GarbageProvider()])
def test_ai_failure_falls_back_to_deterministic(client, monkeypatch, provider):
    sid = client.post("/api/demo/scan").json()["id"]
    finding = client.get(f"/api/scans/{sid}/findings").json()[0]
    monkeypatch.setattr(ai, "get_provider", lambda: provider)
    r = client.post(f"/api/scans/{sid}/findings/{finding['id']}/explain").json()
    assert r["source"] == "deterministic" and r["ai_error"]
    assert r["explanation"]["recommended_fix"] == finding["remediation"]
    # Scanner finding is unchanged.
    assert client.get(f"/api/scans/{sid}/findings").json()[0] == finding


def test_ai_receives_only_masked_code_and_output_is_masked(client, monkeypatch):
    sid = client.post("/api/demo/scan").json()["id"]
    sec = [f for f in client.get(f"/api/scans/{sid}/findings").json() if f["rule_id"] == "PP-SEC-001"][0]
    cap = CapturingProvider()
    monkeypatch.setattr(ai, "get_provider", lambda: cap)
    r = client.post(f"/api/scans/{sid}/findings/{sec['id']}/explain").json()
    assert r["source"] == "ai"
    assert SYNTH_KEY not in cap.seen and "<untrusted_code>" in cap.seen
    assert SYNTH_KEY not in r["explanation"]["safer_code_example"]


def test_ai_disabled_uses_builtin(client):
    sid = client.post("/api/demo/scan").json()["id"]
    fid = client.get(f"/api/scans/{sid}/findings").json()[0]["id"]
    r = client.post(f"/api/scans/{sid}/findings/{fid}/explain").json()
    assert r["source"] == "deterministic" and r["explanation"]["verification_steps"]


# --- full demo journey ---------------------------------------------------------

def test_demo_end_to_end(client):
    scan = client.post("/api/demo/scan").json()
    sid = scan["id"]
    findings = client.get(f"/api/scans/{sid}/findings").json()
    rules = {f["rule_id"] for f in findings}
    for expected in ("PP-SEC-001", "PP-XSS-001", "PP-CFG-001", "PP-AUTH-002", "PP-INJ-001", "PP-INJ-002"):
        assert expected in rules
    assert all(f["file"] and f["line"] > 0 and f["evidence"] for f in findings)

    prompt = client.post(f"/api/scans/{sid}/repair-prompt", json={"finding_ids": [f["id"] for f in findings[:5]]}).json()
    assert "ROTATE OR REVOKE" in prompt["prompt"] and "server/index.js" in prompt["prompt"]
    auth = [f["id"] for f in findings if f["rule_id"].startswith("PP-AUTH")]
    p2 = client.post(f"/api/scans/{sid}/repair-prompt", json={"finding_ids": auth}).json()["prompt"]
    assert "ON THE SERVER" in p2 and "Hiding buttons" in p2
    xss = [f["id"] for f in findings if f["rule_id"].startswith("PP-XSS")]
    assert "DOMPurify" in client.post(f"/api/scans/{sid}/repair-prompt", json={"finding_ids": xss}).json()["prompt"]

    re = client.post(f"/api/scans/{sid}/rescan/demo").json()
    cmp = re["comparison"]
    assert len(cmp["resolved"]) == len(findings) - len(cmp["remaining"])
    assert len(cmp["remaining"]) == 2 and len(cmp["new"]) == 1
    assert cmp["after_score"] > cmp["before_score"]
    # Originals resolved by the rescan are now verified Fixed.
    statuses = [f["status"] for f in client.get(f"/api/scans/{sid}/findings").json()]
    assert statuses.count("fixed") == len(cmp["resolved"])
    dash = client.get("/api/dashboard").json()
    assert dash["total_scans"] == 2 and dash["resolved"] == len(cmp["resolved"])

    # Deterministic: running the demo again yields identical results.
    again = client.post("/api/demo/scan").json()
    assert again["counts"] == scan["counts"] and again["score"] == scan["score"]


def test_rescan_with_uploaded_zip(client):
    sid = client.post("/api/scans", data={"project_name": "Mine"},
                      files={"archive": ("a.zip", make_zip({"app.py": "app.run(debug=True)\nrequests.get(u, verify=False)\n"}), "application/zip")}).json()["id"]
    r = client.post(f"/api/scans/{sid}/rescan", files={"archive": ("b.zip", make_zip({"app.py": "app.run(debug=False)\nrequests.get(u, verify=False)\n"}), "application/zip")})
    cmp = r.json()["comparison"]
    assert [x["finding"]["rule_id"] for x in cmp["resolved"]] == ["PP-CFG-002"]
    assert [x["after"]["rule_id"] for x in cmp["remaining"]] == ["PP-CFG-003"]


def test_health_and_evaluation(client):
    assert client.get("/api/health").json()["status"] == "ok"
    ev = client.get("/api/evaluation").json()
    assert ev["planted"] > 0 and "synthetic" in ev["note"]


# --- URL scanning safety ---------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://localhost/", "http://127.0.0.1/", "http://10.0.0.5/", "http://192.168.1.1/", "http://169.254.169.254/latest/meta-data",
    "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://100.64.0.1/", "file:///etc/passwd", "ftp://example.com/",
    "http://user:pass@example.com/", "http://example.com:22/", "http://metadata.google.internal/", "http://printer.local/",
])
def test_url_validation_blocks_unsafe_targets(url):
    from app.urlscan import UrlScanError, validate_url
    with pytest.raises(UrlScanError):
        validate_url(url)


def test_url_scan_api_refuses_private(client):
    r = client.post("/api/scans", data={"project_name": "u", "target_url": "http://127.0.0.1:8000/"})
    assert r.status_code == 422 and "refused" in r.json()["detail"]


def test_list_all_findings_api(client):
    # Scan demo project
    r = client.post("/api/demo/scan")
    assert r.status_code == 201
    
    # Query all findings across latest scans
    f_all = client.get("/api/findings").json()
    assert len(f_all) > 0
    assert "project_name" in f_all[0]
    assert "severity" in f_all[0]

    # Query filtered by critical
    f_crit = client.get("/api/findings?severity=critical").json()
    assert len(f_crit) > 0
    assert all(x["severity"] == "critical" for x in f_crit)
