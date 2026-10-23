"""Unit tests for Semgrep integration."""
import json
from app.scanner import SourceFile
from app.scanner.semgrep import parse_semgrep_output, map_semgrep_severity

MOCK_SEMGREP_JSON = {
    "version": "1.0.0",
    "results": [
        {
            "check_id": "rules.security.taint.sql-injection",
            "path": "server/routes/users.js",
            "start": {"line": 42, "col": 5},
            "end": {"line": 42, "col": 40},
            "extra": {
                "message": "User tainted data flows into SQL query concatenation.",
                "severity": "ERROR",
                "metadata": {
                    "category": "security",
                    "confidence": "HIGH",
                    "impact": "HIGH",
                    "cwe": ["CWE-89: SQL Injection"],
                    "fix": "Use parameterized queries with $1 placeholders."
                },
                "lines": "db.query('SELECT * FROM users WHERE id = ' + req.query.id);"
            }
        },
        {
            "check_id": "rules.security.xss.dom-xss",
            "path": "src/components/Search.jsx",
            "start": {"line": 15, "col": 3},
            "end": {"line": 15, "col": 25},
            "extra": {
                "message": "Untrusted search parameter assigned to innerHTML without sanitization.",
                "severity": "WARNING",
                "metadata": {
                    "category": "security",
                    "confidence": "MEDIUM",
                    "cwe": "CWE-79"
                },
                "lines": "el.innerHTML = new URLSearchParams(location.search).get('q');"
            }
        }
    ]
}


def test_map_semgrep_severity():
    assert map_semgrep_severity("ERROR") == "high"
    assert map_semgrep_severity("WARNING") == "medium"
    assert map_semgrep_severity("INFO") == "low"


def test_parse_semgrep_json_to_patchpilot_schema():
    files = {
        "server/routes/users.js": SourceFile("server/routes/users.js", "line1\n" * 41 + "db.query('SELECT * FROM users WHERE id = ' + req.query.id);\n"),
        "src/components/Search.jsx": SourceFile("src/components/Search.jsx", "line1\n" * 14 + "el.innerHTML = new URLSearchParams(location.search).get('q');\n")
    }

    findings = parse_semgrep_output(MOCK_SEMGREP_JSON, files)
    assert len(findings) == 2

    f1 = findings[0]
    assert f1.rule_id == "SG-sql-injection"
    assert "[Semgrep]" in f1.title
    assert f1.file == "server/routes/users.js"
    assert f1.line == 42
    assert f1.severity == "critical"  # escalated because ERROR + impact HIGH
    assert f1.confidence == "high"
    assert f1.cwe == "CWE-89"
    assert f1.fingerprint != ""

    f2 = findings[1]
    assert f2.rule_id == "SG-dom-xss"
    assert f2.file == "src/components/Search.jsx"
    assert f2.line == 15
    assert f2.severity == "medium"
    assert f2.confidence == "medium"
    assert f2.cwe == "CWE-79"
