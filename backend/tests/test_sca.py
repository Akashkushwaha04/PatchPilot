"""Unit tests for Software Composition Analysis (SCA) & OSV parser."""
import pytest
from app.scanner import SourceFile
from app.scanner.sca import (
    Dependency,
    extract_dependencies,
    parse_package_json,
    parse_requirements_txt,
    _map_osv_severity,
    _extract_cwe_from_osv,
)

PACKAGE_JSON = """{
  "name": "sample-app",
  "dependencies": {
    "lodash": "^4.17.15",
    "express": "4.17.1"
  },
  "devDependencies": {
    "mocha": "~8.0.0"
  }
}"""

REQUIREMENTS_TXT = """# Core requirements
requests==2.20.0
flask==0.12.2
--extra-index-url https://example.com/pypi
# Ignored items:
django
"""


def test_parse_package_json():
    sf = SourceFile("package.json", PACKAGE_JSON)
    deps = parse_package_json(sf)
    dep_map = {d.name: d for d in deps}

    assert "lodash" in dep_map
    assert dep_map["lodash"].version == "4.17.15"
    assert dep_map["lodash"].ecosystem == "npm"
    assert dep_map["lodash"].line == 4

    assert "express" in dep_map
    assert dep_map["express"].version == "4.17.1"

    assert "mocha" in dep_map
    assert dep_map["mocha"].version == "8.0.0"


def test_parse_requirements_txt():
    sf = SourceFile("backend/requirements.txt", REQUIREMENTS_TXT)
    deps = parse_requirements_txt(sf)
    dep_map = {d.name: d for d in deps}

    assert "requests" in dep_map
    assert dep_map["requests"].version == "2.20.0"
    assert dep_map["requests"].ecosystem == "PyPI"
    assert dep_map["requests"].line == 2

    assert "flask" in dep_map
    assert dep_map["flask"].version == "0.12.2"
    assert dep_map["flask"].line == 3

    # Unpinned django and comments are excluded
    assert "django" not in dep_map


def test_extract_dependencies_across_files():
    files = [
        SourceFile("frontend/package.json", PACKAGE_JSON),
        SourceFile("backend/requirements.txt", REQUIREMENTS_TXT),
        SourceFile("src/index.js", "console.log('test');")
    ]
    deps = extract_dependencies(files)
    assert len(deps) == 5


def test_osv_mapping_helpers():
    vuln_cvss = {
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-89", "CWE-79"]}
    }
    assert _map_osv_severity(vuln_cvss) == "critical"
    assert _extract_cwe_from_osv(vuln_cvss) == "CWE-89"

    vuln_db = {
        "database_specific": {"severity": "MODERATE"}
    }
    assert _map_osv_severity(vuln_db) == "medium"
