"""Browser-visible scanning of a deployed URL, with SSRF defences and Playwright headless browser.

Features:
- SSRF prevention (IP validation, blocking local, private, metadata IPs).
- Playwright headless Chromium navigation for Single Page Applications (SPAs).
- Waits for networkidle to capture client-side DOM rendering.
- Intercepts outbound network requests to catch exposed internal API routes/endpoints.
- Listens to console events to capture errors, exceptions, or sensitive trace leaks.
- Fallback to safe HTTP GET socket if Playwright browser binaries are not installed.
"""
from __future__ import annotations

import asyncio
import http.client
import ipaddress
import logging
import re
import socket
import ssl
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .scanner import SourceFile, scan_files
from .scanner.models import Finding

log = logging.getLogger("patchpilot.urlscan")

TIMEOUT = 8
MAX_BYTES = 1_500_000
MAX_REDIRECTS = 3
MAX_SCRIPTS = 8
ALLOWED_PORTS = {80, 443}
ALLOWED_TYPES = ("text/html", "application/javascript", "text/javascript", "application/x-javascript", "text/plain", "application/json")
BLOCKED_HOSTS = re.compile(r"(?:^|\.)(?:localhost|local|internal|intranet|corp|home|lan)$|^metadata\.google\.internal$", re.I)
USER_AGENT = "PatchPilotAI-PublicAssetCheck/1.0 (+authorized passive scan)"

# Regex matching suspicious internal network endpoints in requests or console
INTERNAL_URL_PATTERN = re.compile(
    r"https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|[a-z0-9-]+\.(?:internal|local|corp|intranet))\b",
    re.I,
)


class UrlScanError(Exception):
    pass


def check_ip(ip_str: str) -> None:
    ip = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local or ip.is_private:
        raise UrlScanError(f"Target resolves to a non-public address ({ip}). Only public, internet-facing sites can be scanned.")
    if str(ip) in {"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}:
        raise UrlScanError("Cloud metadata endpoints are blocked.")


def validate_url(url: str) -> tuple[str, str, int, str, str]:
    """Return (scheme, host, port, pinned_ip, path_with_query) or raise UrlScanError."""
    if len(url) > 2048:
        raise UrlScanError("URL is too long.")
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise UrlScanError("Only http:// and https:// URLs are supported.")
    if parts.username or parts.password:
        raise UrlScanError("URLs containing credentials are not allowed.")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise UrlScanError("URL has no hostname.")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise UrlScanError("URL has an invalid port.")
    if port not in ALLOWED_PORTS:
        raise UrlScanError("Only the standard web ports 80 and 443 are allowed.")
    if BLOCKED_HOSTS.search(host):
        raise UrlScanError("Local and internal hostnames are blocked.")
    try:
        ipaddress.ip_address(host)
        addrs = [host]
    except ValueError:
        if not re.fullmatch(r"[a-z0-9.-]+", host) or "." not in host:
            raise UrlScanError("Hostname is not a valid public domain.")
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise UrlScanError("Hostname could not be resolved.")
        addrs = sorted({i[4][0] for i in infos})
    if not addrs:
        raise UrlScanError("Hostname did not resolve to any address.")
    for a in addrs:
        check_ip(a)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return scheme, host, port, addrs[0], path


# ---------------------------------------------------------------- Playwright Scanner

async def scan_with_playwright(target_url: str) -> dict[str, Any] | None:
    """Launch headless Chromium via Playwright, wait for networkidle, and intercept requests/console."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return None

    intercepted_requests: list[str] = []
    console_errors: list[str] = []
    internal_endpoints_found: list[dict[str, Any]] = []
    resources: list[dict[str, Any]] = []

    try:
        async with async_playwright() as p:
            # Launch headless browser
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
            )
            context = await browser.new_context(
                user_agent=USER_AGENT,
                viewport={"width": 1280, "height": 800},
            )
            page = await context.new_page()

            # Listen for browser console errors/warnings
            def on_console(msg):
                if msg.type in ("error", "warning"):
                    text = msg.text
                    console_errors.append(f"[{msg.type.upper()}] {text}")
                    # Check for leaked internal addresses in console output
                    m = INTERNAL_URL_PATTERN.search(text)
                    if m:
                        internal_endpoints_found.append({
                            "type": "console",
                            "endpoint": m.group(0),
                            "detail": text[:200],
                        })

            page.on("console", on_console)

            # Intercept outbound network requests
            def on_request(req):
                r_url = req.url
                intercepted_requests.append(r_url)
                m = INTERNAL_URL_PATTERN.search(r_url)
                if m:
                    internal_endpoints_found.append({
                        "type": "network_request",
                        "endpoint": m.group(0),
                        "detail": f"{req.method} {r_url[:150]}",
                    })

            page.on("request", on_request)

            # Protect Chromium from SSRF: abort any outbound requests to private/internal IPs
            async def on_route(route):
                req_url = route.request.url
                try:
                    p = urlsplit(req_url)
                    host = (p.hostname or "").lower()
                    if host and BLOCKED_HOSTS.search(host):
                        await route.abort("blockedbyclient")
                        return
                    try:
                        ip = ipaddress.ip_address(host)
                        if not ip.is_global or ip.is_private or ip.is_loopback:
                            await route.abort("blockedbyclient")
                            return
                    except ValueError:
                        pass
                    await route.continue_()
                except Exception:
                    await route.continue_()

            try:
                await page.route("**/*", on_route)
            except Exception:
                pass

            try:
                # Navigate and wait for SPA networkidle state
                try:
                    await page.goto(target_url, wait_until="networkidle", timeout=15000)
                except Exception as e:
                    # If networkidle times out, proceed with current DOM
                    log.debug("Playwright networkidle timeout or warning: %s", e)

                final_url = page.url
                rendered_html = await page.content()

                # Record rendered DOM as primary resource
                resources.append({
                    "url": final_url,
                    "type": "html (rendered SPA)",
                    "bytes": len(rendered_html),
                })

                return {
                    "final_url": final_url,
                    "html": rendered_html,
                    "resources": resources,
                    "intercepted_requests": intercepted_requests,
                    "console_errors": console_errors,
                    "internal_endpoints": internal_endpoints_found,
                }
            finally:
                try:
                    await context.close()
                except Exception:
                    pass
                try:
                    await browser.close()
                except Exception:
                    pass
    except Exception as e:
        log.warning("Playwright rendering unavailable or encountered an error (%s). Falling back to HTTP socket scanner.", e)
        return None


# ---------------------------------------------------------------- HTTP Fallback

class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, **kw):
        super().__init__(host, port, timeout=TIMEOUT, context=ssl.create_default_context(), **kw)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, port, **kw):
        super().__init__(host, port, timeout=TIMEOUT, **kw)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


def safe_get(url: str) -> tuple[str, str]:
    """GET a public URL safely via raw socket with DNS pinning."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        scheme, host, port, ip, path = validate_url(current)
        conn_cls = _PinnedHTTPS if scheme == "https" else _PinnedHTTP
        conn = conn_cls(host, ip, port)
        try:
            conn.request("GET", path, headers={"Host": host, "User-Agent": USER_AGENT, "Accept": "text/html,application/javascript,*/*;q=0.1"})
            resp = conn.getresponse()
            if resp.status in (301, 302, 303, 307, 308):
                loc = resp.getheader("Location")
                if not loc:
                    raise UrlScanError("Redirect without a Location header.")
                current = urljoin(current, loc)
                continue
            if resp.status != 200:
                raise UrlScanError(f"Target returned HTTP {resp.status}.")
            ctype = (resp.getheader("Content-Type") or "").split(";")[0].strip().lower()
            if not ctype.startswith(ALLOWED_TYPES):
                raise UrlScanError(f"Unsupported content type '{ctype}'.")
            body = resp.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise UrlScanError("Response is larger than the 1.5 MB limit.")
            return current, body.decode("utf-8", errors="replace")
        except (OSError, http.client.HTTPException, ssl.SSLError) as e:
            raise UrlScanError(f"Could not fetch the page ({type(e).__name__}).")
        finally:
            conn.close()
    raise UrlScanError("Too many redirects.")


class _ScriptParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.srcs: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            src = dict(attrs).get("src")
            if src:
                self.srcs.append(src)


# ---------------------------------------------------------------- Main Entry Point

async def scan_url_async(url: str) -> dict:
    """Scan a deployed URL asynchronously with Playwright SPA rendering and network inspection."""
    # 1. Enforce SSRF validation on target
    validate_url(url)

    notes: list[str] = []
    files: list[SourceFile] = []
    resources: list[dict] = []
    additional_findings: list[dict] = []

    # 2. Attempt dynamic SPA analysis with Playwright
    pw_result = await scan_with_playwright(url)

    if pw_result:
        final_url = pw_result["final_url"]
        html = pw_result["html"]
        resources = pw_result["resources"]
        notes.append("Executed headless Chromium via Playwright: captured SPA rendered DOM and intercepted network traffic.")

        # Flag any discovered internal network endpoints
        for item in pw_result["internal_endpoints"]:
            detail = item["detail"]
            endpoint = item["endpoint"]
            additional_findings.append({
                "rule_id": "PP-EXP-004",
                "title": f"Exposed internal endpoint: {endpoint}",
                "category": "Sensitive data exposure",
                "description": f"Browser client attempted communication with internal network resource ({item['type']}): {detail}",
                "severity": "medium",
                "confidence": "high",
                "kind": "confirmed",
                "file": "browser/network-traffic",
                "line": 1,
                "snippet": detail,
                "evidence": f"Request/Console intercepted during SPA render: {detail}",
                "impact": "Reveals internal service architectures and private IP ranges to unauthorized visitors.",
                "remediation": "Route client communications through public API gateways and remove internal hostnames.",
                "cwe": "CWE-200",
                "origin": "browser",
                "line_text": detail[:300],
                "fingerprint": f"PP-EXP-004|browser/network-traffic|{endpoint}",
            })

        files.append(SourceFile("browser/index.html", html))
    else:
        # Fallback to synchronous safe socket fetch
        final_url, html = safe_get(url)
        files.append(SourceFile("browser/index.html", html))
        resources.append({"url": final_url, "type": "html", "bytes": len(html)})
        notes.append("Standard HTTP fetch performed (Playwright browser was not available).")

    # 3. Analyze scripts on the same origin
    base_host = urlsplit(final_url).hostname
    parser = _ScriptParser()
    try:
        parser.feed(html)
    except Exception:
        notes.append("HTML could not be fully parsed; only inline content was analyzed.")

    for src in parser.srcs[:MAX_SCRIPTS]:
        abs_url = urljoin(final_url, src)
        if urlsplit(abs_url).hostname != base_host:
            notes.append(f"Skipped third-party script on another host: {urlsplit(abs_url).hostname}")
            continue
        try:
            _, js = safe_get(abs_url)
        except UrlScanError as e:
            notes.append(f"Skipped {urlsplit(abs_url).path}: {e}")
            continue
        name = re.sub(r"[^\w.\-/]", "_", urlsplit(abs_url).path.lstrip("/")) or "script.js"
        if not name.endswith(".js"):
            name += ".js"
        files.append(SourceFile(f"browser/{name}", js))
        resources.append({"url": abs_url, "type": "script", "bytes": len(js)})

    # Run PatchPilot rule suite over captured browser assets
    findings = [f.to_dict() for f in scan_files(files, origin="browser")]
    findings.extend(additional_findings)

    notes.append("Browser-visible scanning only sees what any visitor can download. It cannot assess the backend.")

    return {
        "findings": findings,
        "resources": resources,
        "notes": notes,
        "final_url": final_url,
        "_files": [(sf.path, sf.content) for sf in files],
    }


def scan_url(url: str) -> dict:
    """Synchronous compatibility wrapper for scan_url_async."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            return pool.submit(asyncio.run, scan_url_async(url)).result()
    return asyncio.run(scan_url_async(url))
