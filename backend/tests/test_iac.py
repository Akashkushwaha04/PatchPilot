"""Unit tests for Infrastructure as Code (IaC) rules."""
import pytest
from app.scanner import SourceFile, scan_files


def rules_for(path: str, content: str) -> list:
    return scan_files([SourceFile(path, content)])


def rule_ids(path: str, content: str) -> set[str]:
    return {f.rule_id for f in scan_files([SourceFile(path, content)])}


# ----------------------------------------------------------------
# PP-IAC-001: ContainerRootUser (CWE-250)
# ----------------------------------------------------------------

def test_dockerfile_explicit_user_root():
    content = """
FROM node:18-alpine
WORKDIR /app
COPY . .
USER root
CMD ["node", "server.js"]
"""
    findings = rules_for("Dockerfile", content)
    assert any(f.rule_id == "PP-IAC-001" and f.severity == "high" for f in findings)
    iac_finding = next(f for f in findings if f.rule_id == "PP-IAC-001")
    assert iac_finding.cwe == "CWE-250"
    assert "USER root" in iac_finding.evidence


def test_dockerfile_missing_user_directive():
    content = """
FROM python:3.11-slim
WORKDIR /workspace
COPY requirements.txt .
RUN pip install -r requirements.txt
CMD ["uvicorn", "app:app"]
"""
    findings = rules_for("Dockerfile", content)
    assert any(f.rule_id == "PP-IAC-001" for f in findings)
    iac_finding = next(f for f in findings if f.rule_id == "PP-IAC-001")
    assert iac_finding.cwe == "CWE-250"
    assert "root by default" in iac_finding.evidence


def test_dockerfile_safe_non_root_user():
    content = """
FROM python:3.11-slim
WORKDIR /workspace
RUN useradd -m -u 1000 appuser
COPY . .
USER appuser
CMD ["python", "main.py"]
"""
    ids = rule_ids("Dockerfile", content)
    assert "PP-IAC-001" not in ids


# ----------------------------------------------------------------
# PP-IAC-002: ExposedSensitivePort (CWE-668)
# ----------------------------------------------------------------

def test_dockerfile_exposed_docker_daemon_port():
    content = """
FROM alpine:latest
RUN apk add --no-cache docker-cli
EXPOSE 2375
"""
    findings = rules_for("Dockerfile", content)
    assert any(f.rule_id == "PP-IAC-002" and f.severity == "critical" for f in findings)
    finding = next(f for f in findings if f.rule_id == "PP-IAC-002")
    assert finding.cwe == "CWE-668"
    assert "2375" in finding.evidence


def test_dockerfile_exposed_database_port():
    content = """
FROM redis:7-alpine
EXPOSE 6379
USER redis
"""
    findings = rules_for("Dockerfile", content)
    assert any(f.rule_id == "PP-IAC-002" and f.severity == "high" for f in findings)
    finding = next(f for f in findings if f.rule_id == "PP-IAC-002")
    assert "6379" in finding.evidence


def test_dockerfile_safe_standard_port():
    content = """
FROM node:18-alpine
USER node
EXPOSE 8080
"""
    ids = rule_ids("Dockerfile", content)
    assert "PP-IAC-002" not in ids


def test_docker_compose_exposed_sensitive_ports():
    content = """
version: '3.8'
services:
  app:
    image: my-app:latest
    ports:
      - "2375:2375"
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
"""
    findings = rules_for("docker-compose.yml", content)
    assert any(f.rule_id == "PP-IAC-002" and f.severity == "critical" for f in findings)
    finding = next(f for f in findings if f.rule_id == "PP-IAC-002")
    assert finding.cwe == "CWE-668"


def test_docker_compose_safe_ports():
    content = """
version: '3.8'
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
      - "8443:443"
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 256M
"""
    ids = rule_ids("docker-compose.yml", content)
    assert "PP-IAC-002" not in ids


# ----------------------------------------------------------------
# PP-IAC-003: MissingResourceLimits (CWE-400)
# ----------------------------------------------------------------

def test_docker_compose_missing_resource_limits():
    content = """
version: '3.8'
services:
  web:
    image: nginx:alpine
    ports:
      - "80:80"
  worker:
    image: python-worker:latest
"""
    findings = rules_for("docker-compose.yml", content)
    assert any(f.rule_id == "PP-IAC-003" and f.severity == "medium" for f in findings)
    finding = next(f for f in findings if f.rule_id == "PP-IAC-003")
    assert finding.cwe == "CWE-400"
    assert "limits" in finding.evidence


def test_docker_compose_with_resource_limits():
    content = """
version: '3.8'
services:
  web:
    image: nginx:alpine
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
"""
    ids = rule_ids("docker-compose.yml", content)
    assert "PP-IAC-003" not in ids
