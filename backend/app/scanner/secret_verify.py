"""Dynamic secret verification module for PatchPilot.

Performs safe, read-only outbound verification for discovered API tokens and secrets
against trusted official provider endpoints (GitHub, AWS STS, Slack).

SSRF and Security Controls:
- All outbound requests are strictly hardcoded to trusted official provider hosts
  (api.github.com, sts.amazonaws.com, slack.com). No user-controlled endpoints are permitted.
- Enforces strict network timeouts (default 5.0s) to prevent blocking or event loop starvation.
- Unhandled network errors, connection drops, or timeouts fail closed safely without crashing.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Literal

import httpx

from .models import Finding, Severity

log = logging.getLogger("patchpilot.secret_verify")

DEFAULT_VERIFY_TIMEOUT = 5.0

# Known provider token patterns
GITHUB_TOKEN_RE = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{40,}\b")
AWS_KEY_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
SLACK_TOKEN_RE = re.compile(r"\b(xox[abprs]-[0-9A-Za-z\-]{10,})\b")

# Whitelisted official provider endpoints (SSRF defense)
ALLOWED_PROVIDER_HOSTS = {
    "github": "api.github.com",
    "aws": "sts.amazonaws.com",
    "slack": "slack.com",
}


@dataclass
class TokenVerificationResult:
    token_masked: str
    provider: str
    status: Literal["active", "revoked", "unverified", "timeout", "error"]
    recommended_severity: Severity | None
    detail: str
    http_status: int | None = None


async def verify_token_active(
    token: str,
    provider: str | None = None,
    timeout: float = DEFAULT_VERIFY_TIMEOUT,
    client: httpx.AsyncClient | None = None,
) -> TokenVerificationResult:
    """Safely verify if an extracted token is active via read-only provider APIs.

    Returns:
        TokenVerificationResult indicating active (critical), revoked (info), or unverified.
    """
    clean_token = token.strip()
    masked = clean_token[:4] + "..." + clean_token[-4:] if len(clean_token) > 8 else "****"

    # Identify provider
    if not provider:
        if GITHUB_TOKEN_RE.search(clean_token):
            provider = "github"
        elif AWS_KEY_RE.search(clean_token):
            provider = "aws"
        elif SLACK_TOKEN_RE.search(clean_token):
            provider = "slack"
        else:
            return TokenVerificationResult(
                token_masked=masked,
                provider="unknown",
                status="unverified",
                recommended_severity=None,
                detail="No supported dynamic verification provider pattern matched.",
            )

    provider = provider.lower()
    if provider not in ALLOWED_PROVIDER_HOSTS:
        return TokenVerificationResult(
            token_masked=masked,
            provider=provider,
            status="unverified",
            recommended_severity=None,
            detail=f"Provider '{provider}' is not in the allowed verification whitelist.",
        )

    headers = {"User-Agent": "PatchPilotAI-SecretVerification/1.0"}

    # Execute read-only API check
    try:
        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=timeout)
            should_close = True

        try:
            if provider == "github":
                # GitHub /user returns 200 with user profile on valid token; 401 on bad credentials
                resp = await client.get(
                    "https://api.github.com/user",
                    headers={**headers, "Authorization": f"Bearer {clean_token}"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    login = data.get("login", "valid user")
                    return TokenVerificationResult(
                        token_masked=masked,
                        provider="github",
                        status="active",
                        recommended_severity="critical",
                        detail=f"Active GitHub token confirmed (account: {login}).",
                        http_status=200,
                    )
                elif resp.status_code == 401:
                    return TokenVerificationResult(
                        token_masked=masked,
                        provider="github",
                        status="revoked",
                        recommended_severity="info",
                        detail="GitHub token returned 401 Bad credentials (token revoked or disabled).",
                        http_status=401,
                    )
                elif resp.status_code in (403, 429):
                    return TokenVerificationResult(
                        token_masked=masked,
                        provider="github",
                        status="unverified",
                        recommended_severity=None,
                        detail="GitHub API rate limit exceeded or access forbidden.",
                        http_status=resp.status_code,
                    )

            elif provider == "aws":
                # Safe STS call: passing access key in standard STS request
                resp = await client.get(
                    f"https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&AWSAccessKeyId={clean_token}",
                    headers=headers,
                )
                # AWS returns InvalidClientTokenId if the key does not exist or was deleted
                text = resp.text
                if "InvalidClientTokenId" in text or resp.status_code == 403 and "is not valid" in text:
                    return TokenVerificationResult(
                        token_masked=masked,
                        provider="aws",
                        status="revoked",
                        recommended_severity="info",
                        detail="AWS reported InvalidClientTokenId (key is inactive or deleted).",
                        http_status=resp.status_code,
                    )
                elif "SignatureDoesNotMatch" in text or "MissingParameter" in text or resp.status_code == 403:
                    # Signature error means the Access Key ID DOES exist in AWS
                    return TokenVerificationResult(
                        token_masked=masked,
                        provider="aws",
                        status="active",
                        recommended_severity="critical",
                        detail="AWS recognized valid Access Key ID (returned SignatureDoesNotMatch).",
                        http_status=resp.status_code,
                    )

            elif provider == "slack":
                resp = await client.post(
                    "https://slack.com/api/auth.test",
                    headers={**headers, "Authorization": f"Bearer {clean_token}"},
                )
                data = resp.json()
                if data.get("ok"):
                    team = data.get("team", "workspace")
                    return TokenVerificationResult(
                        token_masked=masked,
                        provider="slack",
                        status="active",
                        recommended_severity="critical",
                        detail=f"Active Slack token confirmed (workspace: {team}).",
                        http_status=200,
                    )
                elif data.get("error") in ("invalid_auth", "account_inactive", "token_revoked"):
                    return TokenVerificationResult(
                        token_masked=masked,
                        provider="slack",
                        status="revoked",
                        recommended_severity="info",
                        detail=f"Slack token rejected: {data.get('error')}.",
                        http_status=200,
                    )

            return TokenVerificationResult(
                token_masked=masked,
                provider=provider,
                status="unverified",
                recommended_severity=None,
                detail=f"Provider returned HTTP {resp.status_code} without conclusive auth status.",
                http_status=resp.status_code,
            )

        finally:
            if should_close:
                await client.aclose()

    except httpx.TimeoutException:
        log.debug("Verification request timed out for %s token", provider)
        return TokenVerificationResult(
            token_masked=masked,
            provider=provider,
            status="timeout",
            recommended_severity=None,
            detail=f"Verification request to {provider} timed out after {timeout}s.",
        )
    except Exception as e:
        log.debug("Verification error for %s token: %s", provider, e)
        return TokenVerificationResult(
            token_masked=masked,
            provider=provider,
            status="error",
            recommended_severity=None,
            detail=f"Network error contacting {provider}: {type(e).__name__}.",
        )


async def verify_finding_secret(finding: Finding, timeout: float = DEFAULT_VERIFY_TIMEOUT) -> Finding:
    """Inspect finding for secrets, verify active status, and adjust finding severity accordingly."""
    text_to_search = f"{finding.line_text} {finding.snippet} {finding.evidence}"

    # Extract potential token
    token = None
    provider = None

    m_gh = GITHUB_TOKEN_RE.search(text_to_search)
    if m_gh:
        token = m_gh.group(0)
        provider = "github"
    else:
        m_aws = AWS_KEY_RE.search(text_to_search)
        if m_aws:
            token = m_aws.group(0)
            provider = "aws"
        else:
            m_slack = SLACK_TOKEN_RE.search(text_to_search)
            if m_slack:
                token = m_slack.group(0)
                provider = "slack"

    if not token or not provider:
        return finding

    res = await verify_token_active(token, provider=provider, timeout=timeout)
    if res.status == "active":
        finding.severity = "critical"
        finding.confidence = "high"
        finding.evidence = f"{finding.evidence}\n[Dynamic Verification: ACTIVE] {res.detail}"
    elif res.status == "revoked":
        finding.severity = "info"
        finding.evidence = f"{finding.evidence}\n[Dynamic Verification: REVOKED/INACTIVE] {res.detail}"

    return finding
