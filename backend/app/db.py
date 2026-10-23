"""Asynchronous SQLite persistence using aiosqlite.
Only masked file contents and masked findings are stored.
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

DB_PATH = Path(os.getenv("PATCHPILOT_DB", Path(__file__).resolve().parent.parent / "data" / "patchpilot.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY, project_name TEXT NOT NULL, created_at TEXT NOT NULL,
  parent_id TEXT, source_kind TEXT NOT NULL, label TEXT, file_count INTEGER NOT NULL,
  skipped_json TEXT NOT NULL, score_json TEXT NOT NULL, counts_json TEXT NOT NULL,
  comparison_json TEXT, target_url TEXT, url_json TEXT, is_demo INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, seq INTEGER NOT NULL, data_json TEXT NOT NULL,
  status TEXT NOT NULL, verified_by TEXT, updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE TABLE IF NOT EXISTS files (
  scan_id TEXT NOT NULL, path TEXT NOT NULL, content TEXT NOT NULL, PRIMARY KEY (scan_id, path)
);
CREATE TABLE IF NOT EXISTS activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, scan_id TEXT, kind TEXT NOT NULL, message TEXT NOT NULL
);
"""

_conn: aiosqlite.Connection | None = None
_lock: asyncio.Lock | None = None


def _get_lock() -> asyncio.Lock:
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def loads(s: str | None) -> Any:
    return json.loads(s) if s else None


async def get_db() -> aiosqlite.Connection:
    """Return the shared asynchronous database connection, initializing tables if needed."""
    global _conn
    if _conn is None:
        async with _get_lock():
            if _conn is None:
                DB_PATH.parent.mkdir(parents=True, exist_ok=True)
                conn = await aiosqlite.connect(DB_PATH)
                conn.row_factory = aiosqlite.Row
                # Optimize concurrency and eliminate database-locked errors
                await conn.execute("PRAGMA journal_mode=WAL;")
                await conn.execute("PRAGMA synchronous=NORMAL;")
                await conn.execute("PRAGMA busy_timeout=5000;")
                await conn.executescript(SCHEMA)
                await conn.commit()
                _conn = conn
    return _conn


async def init_db() -> None:
    """Explicitly initialize the database connection and schema on startup."""
    await get_db()


async def close_db() -> None:
    """Close the database connection on shutdown."""
    global _conn
    if _conn is not None:
        async with _get_lock():
            if _conn is not None:
                await _conn.close()
                _conn = None


def reset_for_tests(path: str) -> None:
    """Synchronous reset helper for test fixtures."""
    global _conn, DB_PATH, _lock
    if _conn is not None:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(_conn.close())
            else:
                loop.run_until_complete(_conn.close())
        except Exception:
            pass
    _conn = None
    _lock = None
    DB_PATH = Path(path)


# ---------------------------------------------------------------- async operations

async def execute(sql: str, params: tuple | list = ()) -> None:
    """Execute a single query asynchronously and commit."""
    db = await get_db()
    await db.execute(sql, params)
    await db.commit()


async def executemany(sql: str, rows: list[tuple]) -> None:
    """Execute many rows asynchronously and commit."""
    db = await get_db()
    await db.executemany(sql, rows)
    await db.commit()


async def query(sql: str, params: tuple | list = ()) -> list[aiosqlite.Row]:
    """Execute a select query asynchronously and return rows as list of Row objects."""
    db = await get_db()
    async with db.execute(sql, params) as cursor:
        return await cursor.fetchall()


async def log(kind: str, message: str, scan_id: str | None = None) -> None:
    """Append to the activity log asynchronously."""
    await execute(
        "INSERT INTO activity(at, scan_id, kind, message) VALUES (?,?,?,?)",
        (now(), scan_id, kind, message),
    )
