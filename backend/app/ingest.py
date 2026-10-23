"""Safe ingestion of uploaded ZIP archives and individual files.

Streams file uploads directly and extracts members safely chunk-by-chunk
into an isolated temporary directory (using tempfile), checking security
constraints (path traversal, size limits, compression ratios, and symlinks)
on the fly.
"""
from __future__ import annotations

import io
import os
import posixpath
import re
import shutil
import stat
import tempfile
import zipfile
import zlib
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from .scanner.models import SourceFile

CHUNK_SIZE = 64 * 1024                       # 64 KB streaming chunk
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024        # 100 MB compressed upload limit
MAX_FILES = 2000                             # scanned files per project
MAX_ENTRIES = 10000                          # total entries inspected in an archive
MAX_FILE_BYTES = 5 * 1024 * 1024             # 5 MB per source file
MAX_TOTAL_BYTES = 200 * 1024 * 1024          # 200 MB decompressed in total
MAX_COMPRESSION_RATIO = 100                  # zip-bomb guard

ALLOWED_EXT = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".htm",
    ".py", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".sql",
}
ENV_NAME = re.compile(r"^\.env(?:\.[A-Za-z0-9_-]+)?$")
SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", ".nuxt", "__pycache__", ".venv", "venv", "coverage", ".cache", ".turbo"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}


class IngestError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


@dataclass
class IngestResult:
    files: list[SourceFile] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)


def normalize_path(raw: str) -> str:
    """Return a safe relative POSIX path or raise IngestError for traversal attempts."""
    if not raw or "\x00" in raw:
        raise IngestError("Archive contains an entry with an invalid name.")
    p = raw.replace("\\", "/")
    if p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        raise IngestError(f"Archive entry uses an absolute path and was rejected: {raw[:80]}")
    parts = p.split("/")
    if any(part == ".." for part in parts):
        raise IngestError(f"Archive entry tries to escape the project folder (path traversal) and was rejected: {raw[:80]}")
    norm = posixpath.normpath(p)
    if norm.startswith("..") or norm == ".":
        raise IngestError(f"Archive entry has an unsafe path: {raw[:80]}")
    return norm


DOCKERFILE_NAME = re.compile(r"^(?:.*\.)?dockerfile$", re.I)


def is_supported_name(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if ENV_NAME.match(name) or DOCKERFILE_NAME.match(name):
        return True
    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return ext in ALLOWED_EXT and name not in SKIP_FILES


def decode_text(data: bytes) -> str | None:
    if b"\x00" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("latin-1")
        except UnicodeDecodeError:
            return None
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text[:4096])
        return text if printable / max(1, min(len(text), 4096)) > 0.95 else None


def _strip_common_root(files: list[SourceFile]) -> None:
    if not files:
        return
    firsts = {f.path.split("/", 1)[0] for f in files}
    if len(firsts) == 1 and all("/" in f.path for f in files):
        root = firsts.pop() + "/"
        for f in files:
            f.path = f.path[len(root):]


def _safe_extract_member_to_disk(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    dest_path: Path,
    base_dir: Path,
) -> tuple[int, bool]:
    """Stream and extract a ZIP entry to disk chunk-by-chunk with size verification.

    Returns:
        (bytes_written, exceeded_limit_flag)
    """
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    bytes_written = 0
    exceeded = False

    try:
        with zf.open(info) as src, open(dest_path, "wb") as dst:
            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > MAX_FILE_BYTES:
                    exceeded = True
                    break
                dst.write(chunk)
    except (zipfile.BadZipFile, zlib.error, EOFError, OSError) as e:
        dest_path.unlink(missing_ok=True)
        raise IngestError(f"Archive entry '{info.filename}' is corrupt or malformed.") from e

    if exceeded:
        try:
            dest_path.unlink(missing_ok=True)
        except OSError:
            pass

    return bytes_written, exceeded


def ingest_zip_stream(stream: BinaryIO, max_upload_size: int = MAX_ARCHIVE_BYTES) -> IngestResult:
    """Stream an archive into a temporary file, extract chunk-by-chunk to a temp directory,

    and inspect source files with strict security validations.
    """
    tmp_zip_path: Path | None = None
    temp_dir: Path | None = None
    zf: zipfile.ZipFile | None = None

    try:
        # 1. Stream the archive upload chunk-by-chunk into a secure temporary archive file
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp_zip:
            tmp_zip_path = Path(tmp_zip.name)
            total_uploaded = 0
            while True:
                chunk = stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                total_uploaded += len(chunk)
                if total_uploaded > max_upload_size:
                    raise IngestError(
                        f"Archive exceeds the {max_upload_size // (1024 * 1024)} MB limit.",
                        413,
                    )
                tmp_zip.write(chunk)

        # 2. Extract into an isolated temporary directory
        temp_dir = Path(tempfile.mkdtemp(prefix="patchpilot_ingest_"))
        try:
            zf = zipfile.ZipFile(tmp_zip_path)
        except zipfile.BadZipFile:
            raise IngestError("The uploaded file is not a valid ZIP archive.")

        result = IngestResult()
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise IngestError(f"Archive has {len(infos)} entries; the limit is {MAX_ENTRIES}.", 413)

        total_extracted_bytes = 0

        for info in infos:
            # Enforce path traversal prevention on the relative path
            path = normalize_path(info.filename)
            if info.is_dir():
                continue

            # Prevent symlink attacks
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                result.skipped.append({"path": path, "reason": "symbolic link (not followed)"})
                continue

            # Prevent encrypted zip payloads
            if info.flag_bits & 0x1:
                raise IngestError("Encrypted archives are not supported.")

            # Ignore dependency and build artifacts
            if any(part in SKIP_DIRS for part in path.split("/")[:-1]):
                continue

            # Check supported file names
            if not is_supported_name(path):
                result.skipped.append({"path": path, "reason": "unsupported file type"})
                continue

            # Zip bomb compression ratio check
            if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                raise IngestError("Archive has a suspicious compression ratio (possible zip bomb) and was rejected.", 413)

            # Prevent excessive source files count
            if len(result.files) >= MAX_FILES:
                raise IngestError(f"Archive contains more than {MAX_FILES} supported source files.", 413)

            # Resolve extraction target and ensure it remains strictly inside temp_dir
            target_file = (temp_dir / path).resolve()
            try:
                target_file.relative_to(temp_dir.resolve())
            except ValueError:
                raise IngestError(f"Archive entry tries to escape destination directory: {path}")

            # Stream extract to disk chunk-by-chunk
            written, file_too_large = _safe_extract_member_to_disk(zf, info, target_file, temp_dir)
            if file_too_large:
                result.skipped.append({"path": path, "reason": f"larger than {MAX_FILE_BYTES // 1024} KB"})
                continue

            total_extracted_bytes += written
            if total_extracted_bytes > MAX_TOTAL_BYTES:
                raise IngestError(f"Archive expands to more than {MAX_TOTAL_BYTES // (1024 * 1024)} MB of source.", 413)

            # Read decoded text content from disk
            try:
                raw_bytes = target_file.read_bytes()
            except OSError:
                result.skipped.append({"path": path, "reason": "failed reading extracted file"})
                continue

            text = decode_text(raw_bytes)
            if text is None:
                result.skipped.append({"path": path, "reason": "binary content"})
                continue

            result.files.append(SourceFile(path=path, content=text))

        if not result.files:
            raise IngestError("No supported source files were found in the archive.")

        _strip_common_root(result.files)
        return result

    finally:
        if zf is not None:
            try:
                zf.close()
            except Exception:
                pass
        # Clean up temporary archive and extraction directory
        if tmp_zip_path is not None:
            try:
                tmp_zip_path.unlink(missing_ok=True)
            except OSError:
                pass
        if temp_dir is not None:
            shutil.rmtree(temp_dir, ignore_errors=True)


def ingest_zip(data: bytes) -> IngestResult:
    """Convenience wrapper for raw bytes (tests, legacy callers) using streaming ingestion."""
    return ingest_zip_stream(io.BytesIO(data))


def ingest_files(items: list[tuple[str, bytes]]) -> IngestResult:
    """Ingest individually uploaded files. Unsupported or binary files are rejected outright."""
    if not items:
        raise IngestError("No files were uploaded.")
    if len(items) > MAX_FILES:
        raise IngestError(f"Too many files: {len(items)} (limit {MAX_FILES}).", 413)
    result = IngestResult()
    total, seen = 0, set()
    for raw_name, data in items:
        path = normalize_path(raw_name)
        if not is_supported_name(path):
            raise IngestError(f"`{path}` is not a supported source file type.", 415)
        if len(data) > MAX_FILE_BYTES:
            raise IngestError(f"`{path}` is larger than the {MAX_FILE_BYTES // 1024} KB per-file limit.", 413)
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise IngestError("Uploaded files exceed the total size limit.", 413)
        text = decode_text(data)
        if text is None:
            raise IngestError(f"`{path}` looks like a binary file and was rejected.", 415)
        if path in seen:
            raise IngestError(f"Duplicate file path `{path}`.")
        seen.add(path)
        result.files.append(SourceFile(path=path, content=text))
    return result


GITHUB_REPO_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?$",
    re.I,
)


def parse_github_repo_url(url: str) -> tuple[str, str]:
    """Validate and parse a GitHub repository URL into (owner, repo).

    SSRF Protection:
    - Enforces strictly github.com hostname.
    - Disallows embedded credentials, IP addresses, and path traversal.
    """
    clean = url.strip()
    if not clean:
        raise IngestError("GitHub repository URL cannot be empty.", 422)

    # SSRF guard: check scheme and host if scheme is present
    if "://" in clean:
        parts = urlsplit(clean)
        if parts.scheme.lower() not in ("http", "https"):
            raise IngestError("Only http:// and https:// GitHub URLs are supported.", 422)
        if parts.username or parts.password:
            raise IngestError("GitHub URLs containing credentials are not allowed.", 422)
        host = (parts.hostname or "").lower()
        if host not in ("github.com", "www.github.com"):
            raise IngestError(f"Host '{host}' is not a valid GitHub repository host.", 422)

    m = GITHUB_REPO_URL_RE.match(clean)
    if not m:
        raise IngestError(
            "Invalid GitHub repository URL format. Please provide a URL like 'https://github.com/owner/repo'.",
            422,
        )

    owner, repo = m.group(1), m.group(2)
    if owner.lower() in ("login", "join", "settings", "explore", "trending"):
        raise IngestError(f"Invalid repository owner '{owner}'.", 422)

    return owner, repo


async def download_github_repo(
    repo_url: str,
    token: str | None = None,
    branch: str | None = None,
    timeout: float = 60.0,
) -> tuple[bytes, str, str, str]:
    """Download a GitHub repository as a ZIP archive using the GitHub REST API.

    Uses `https://api.github.com/repos/{owner}/{repo}/zipball/{branch}` instead of
    `git clone` to eliminate malicious git hook execution risks.

    Returns:
        tuple[bytes, str, str, str]: (zip_bytes, owner, repo, ref)
    """
    import httpx

    owner, repo = parse_github_repo_url(repo_url)
    ref = branch.strip() if branch and branch.strip() else ""

    zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{ref}" if ref else f"https://api.github.com/repos/{owner}/{repo}/zipball"

    headers = {
        "User-Agent": "PatchPilotAI-GitHubIngest/1.0",
        "Accept": "application/vnd.github+json",
    }
    if token and token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
            resp = await client.get(zip_url, headers=headers)

            if resp.status_code == 404:
                raise IngestError(
                    f"GitHub repository '{owner}/{repo}' was not found. If this repository is private, please provide a GitHub Personal Access Token.",
                    404,
                )
            elif resp.status_code == 401:
                raise IngestError(
                    "GitHub authentication failed. Please check that your Personal Access Token is valid and has 'repo' scope.",
                    401,
                )
            elif resp.status_code in (403, 429):
                raise IngestError(
                    "GitHub API rate limit exceeded or access forbidden. Supply a valid Personal Access Token with 'repo' scope to authenticate.",
                    403,
                )
            elif resp.status_code != 200:
                raise IngestError(
                    f"GitHub API returned error HTTP {resp.status_code} while downloading repository.",
                    resp.status_code,
                )

            zip_bytes = resp.content
            if len(zip_bytes) > MAX_ARCHIVE_BYTES:
                raise IngestError(
                    f"Downloaded repository archive ({len(zip_bytes) // (1024 * 1024)} MB) exceeds the {MAX_ARCHIVE_BYTES // (1024 * 1024)} MB limit.",
                    413,
                )

            return zip_bytes, owner, repo, ref or "default"

    except httpx.TimeoutException:
        raise IngestError(f"Downloading repository from GitHub timed out after {int(timeout)}s.", 504)
    except httpx.RequestError as e:
        raise IngestError(f"Network error contacting GitHub API: {type(e).__name__}.", 502)


LIMITS = {
    "max_archive_mb": MAX_ARCHIVE_BYTES // (1024 * 1024),
    "max_files": MAX_FILES,
    "max_file_kb": MAX_FILE_BYTES // 1024,
    "max_total_mb": MAX_TOTAL_BYTES // (1024 * 1024),
    "extensions": sorted(ALLOWED_EXT) + [".env", ".env.example"],
}
