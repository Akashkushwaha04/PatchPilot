"""Core data types for the PatchPilot scanner."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]
# confirmed       – a precise pattern match (e.g. a known key format, verify=False)
# heuristic       – a pattern that is usually risky but depends on context
# review_candidate– insufficient evidence; a human must check (e.g. route w/o visible auth)
FindingKind = Literal["confirmed", "heuristic", "review_candidate"]
Origin = Literal["source", "browser"]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class RuleMeta:
    id: str
    title: str
    category: str
    description: str
    severity: Severity
    impact: str
    remediation: str
    cwe: str | None = None


@dataclass
class SourceFile:
    path: str  # normalized, relative, forward slashes
    content: str

    @property
    def lines(self) -> list[str]:
        return self.content.splitlines()

    @property
    def ext(self) -> str:
        name = self.path.rsplit("/", 1)[-1].lower()
        if name.startswith(".env"):
            return ".env"
        if name == "dockerfile" or name.endswith(".dockerfile"):
            return "dockerfile"
        return "." + name.rsplit(".", 1)[-1] if "." in name else ""

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str
    description: str
    severity: Severity
    confidence: Confidence
    kind: FindingKind
    file: str
    line: int
    snippet: str  # masked, may span a few lines
    evidence: str
    impact: str
    remediation: str
    cwe: str | None = None
    origin: Origin = "source"
    line_text: str = ""  # masked text of the matched line, used for fingerprinting
    fingerprint: str = field(default="")

    def finalize(self) -> "Finding":
        norm = re.sub(r"\s+", " ", self.line_text).strip()
        raw = f"{self.rule_id}|{self.file.lower()}|{norm}"
        self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return self

    def to_dict(self) -> dict:
        return asdict(self)
