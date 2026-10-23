"""Secret detection primitives and redaction.

Every string that leaves the scanner (snippets, code previews, reports, AI
payloads) passes through `redact_text`, so a detected credential is never
returned or forwarded in full.
"""
from __future__ import annotations

import math
import re
from collections import Counter

# Well-known credential formats. Each tuple: (label, compiled regex).
KNOWN_KEY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Stripe secret key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{40,}\b")),
    ("OpenAI-style secret key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b")),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("Twilio API key", re.compile(r"\bSK[0-9a-f]{32}\b")),
]

PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")
PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
    r"[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)"
)

CONN_STRING_RE = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://([^:\s/'\"@]+):([^@\s'\"]{3,})@"
)

SECRET_NAME = r"(?:[A-Za-z0-9_]*?(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|pwd|passwd|private[_-]?key|access[_-]?key|auth[_-]?key|client[_-]?secret|credential)s?[A-Za-z0-9_]*)"

# name = "literal"  |  name: "literal"  |  NAME=literal (env files)
ASSIGN_RE = re.compile(
    r"""(?P<name>\b""" + SECRET_NAME + r""")\b["']?\s*(?:=|:|:=|=>)\s*(?P<q>["'`])(?P<value>[^"'`\n]{4,})(?P=q)""",
    re.IGNORECASE,
)
ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>.*?)\s*$")

PLACEHOLDER_WORDS = (
    "your", "example", "sample", "changeme", "change_me", "placeholder", "dummy", "xxxx",
    "replace", "insert", "todo", "redacted", "<", "${", "{{", "process.env", "import.meta",
    "os.environ", "getenv", "env(", "*****", "...", "fake_", "test_key", "not-a-real", "notreal",
    "enter_", "put_your", "secret_here", "key_here", "here",
)

FRONTEND_ENV_PREFIXES = ("VITE_", "NEXT_PUBLIC_", "REACT_APP_", "NUXT_PUBLIC_", "PUBLIC_", "EXPO_PUBLIC_", "GATSBY_")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'`").lower()
    if not v:
        return True
    if any(w in v for w in PLACEHOLDER_WORDS):
        return True
    if len(set(v)) <= 2:  # "xxxxxxxx", "00000000", "********"
        return True
    if v in {"password", "passwd", "pass", "user", "username", "secret", "token", "apikey", "api_key", "key", "value", "test", "pw"}:
        return True
    if re.fullmatch(r"(?:true|false|null|none|undefined|\d{1,5})", v):
        return True
    return False


def looks_like_secret_value(name: str, value: str) -> bool:
    """Decide whether a literal assigned to a secret-sounding name is a real-looking secret."""
    v = value.strip().strip("\"'`")
    if is_placeholder(v):
        return False
    if " " in v and not re.search(r"passw|pwd", name, re.I):
        return False  # prose / UI labels such as "Enter your token"
    if re.fullmatch(r"[a-z]+(?:[_\-.][a-z]+)*", v) and len(v) < 16:
        return False  # identifiers like "auth_token", "session-key", "api.key"
    if re.search(r"passw|pwd", name, re.I):
        return len(v) >= 6
    return len(v) >= 12 and shannon_entropy(v) >= 3.0


def mask_value(value: str) -> str:
    v = value
    if len(v) <= 6:
        return "•" * len(v)
    keep = 4 if len(v) >= 16 else 2
    return f"{v[:keep]}{'•' * 6}[masked {len(v)} chars]"


def find_secret_spans(text: str) -> list[tuple[int, int, str]]:
    """Return (start, end, label) spans of secret values in text."""
    spans: list[tuple[int, int, str]] = []
    for label, rx in KNOWN_KEY_PATTERNS:
        for m in rx.finditer(text):
            spans.append((m.start(), m.end(), label))
    for m in PRIVATE_KEY_BLOCK_RE.finditer(text):
        body_start = text.find("-----", m.start() + 10)
        body_start = text.find("\n", m.start())
        if body_start != -1 and body_start < m.end():
            spans.append((body_start + 1, m.end(), "private key"))
    for m in CONN_STRING_RE.finditer(text):
        spans.append((m.start(2), m.end(2), "connection password"))
    for m in ASSIGN_RE.finditer(text):
        if looks_like_secret_value(m.group("name"), m.group("value")):
            spans.append((m.start("value"), m.end("value"), "credential"))
    for line_match in re.finditer(r"^.*$", text, re.M):
        em = ENV_LINE_RE.match(line_match.group(0))
        if em and re.search(SECRET_NAME, em.group("name"), re.I):
            val = em.group("value").strip().strip("\"'")
            if val and looks_like_secret_value(em.group("name"), val):
                start = line_match.start() + line_match.group(0).find(val, line_match.group(0).find("="))
                spans.append((start, start + len(val), "credential"))
    return _merge(spans)


def _merge(spans: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    spans.sort()
    out: list[tuple[int, int, str]] = []
    for s in spans:
        if out and s[0] < out[-1][1]:
            prev = out[-1]
            out[-1] = (prev[0], max(prev[1], s[1]), prev[2])
        else:
            out.append(s)
    return out


def redact_text(text: str) -> str:
    """Mask every detected secret value inside text."""
    spans = find_secret_spans(text)
    if not spans:
        return text
    parts, last = [], 0
    for start, end, label in spans:
        parts.append(text[last:start])
        secret = text[start:end]
        if label == "private key":
            parts.append("[private key material masked]\n")
        else:
            parts.append(mask_value(secret))
        last = end
    parts.append(text[last:])
    return "".join(parts)
