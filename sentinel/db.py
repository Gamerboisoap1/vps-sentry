"""SQLite storage: raw events, derived alerts, and tail bookkeeping.

Design notes worth knowing before changing anything here:

* Raw events and alerts are kept separate. Events are the evidence; alerts are
  a derived view over them. The username breakdown stat is computed from
  events, not alerts, so it survives changes to the alerting rules.
* Every event carries (inode, byte_offset). That pair is unique for a physical
  line on disk and changes when the file rotates, which gives idempotent
  ingestion for free -- re-reading a region can never double-count.
* All timestamps are stored as ISO-8601 UTC strings. Syslog writes server
  local time; converting at the parser boundary keeps every comparison here
  timezone-free.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS tail_state (
    source        TEXT PRIMARY KEY,
    path          TEXT NOT NULL,
    inode         INTEGER,
    byte_offset   INTEGER NOT NULL DEFAULT 0,
    last_read_at  TEXT,
    last_error    TEXT
);

CREATE TABLE IF NOT EXISTS ssh_events (
    id          INTEGER PRIMARY KEY,
    ts          TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    username    TEXT,
    kind        TEXT    NOT NULL,
    inode       INTEGER NOT NULL,
    byte_offset INTEGER NOT NULL,
    UNIQUE (inode, byte_offset)
);
CREATE INDEX IF NOT EXISTS idx_ssh_ip_ts ON ssh_events (ip, ts);
CREATE INDEX IF NOT EXISTS idx_ssh_ts    ON ssh_events (ts);

CREATE TABLE IF NOT EXISTS scan_events (
    id          INTEGER PRIMARY KEY,
    ts          TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    dst_port    INTEGER NOT NULL,
    proto       TEXT,
    inode       INTEGER NOT NULL,
    byte_offset INTEGER NOT NULL,
    UNIQUE (inode, byte_offset)
);
CREATE INDEX IF NOT EXISTS idx_scan_ip_ts ON scan_events (ip, ts);
CREATE INDEX IF NOT EXISTS idx_scan_ts    ON scan_events (ts);

CREATE TABLE IF NOT EXISTS alerts (
    id                  INTEGER PRIMARY KEY,
    kind                TEXT    NOT NULL,
    ip                  TEXT    NOT NULL,
    first_seen          TEXT    NOT NULL,
    last_seen           TEXT    NOT NULL,
    event_count         INTEGER NOT NULL,
    detail              TEXT,
    country             TEXT,
    country_code        TEXT,
    banned_at_detection INTEGER,
    created_at          TEXT    NOT NULL,
    updated_at          TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_kind_seen ON alerts (kind, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_ip        ON alerts (ip);
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """Serialise to a lexicographically sortable UTC string."""
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: Path) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


@contextmanager
def transaction(db_path: Path) -> Iterator[sqlite3.Connection]:
    conn = connect(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Tail bookkeeping
# --------------------------------------------------------------------------

def get_tail_state(conn: sqlite3.Connection, source: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM tail_state WHERE source = ?", (source,)
    ).fetchone()


def save_tail_state(
    conn: sqlite3.Connection,
    source: str,
    path: str,
    inode: int | None,
    byte_offset: int,
    last_error: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO tail_state (source, path, inode, byte_offset, last_read_at, last_error)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(source) DO UPDATE SET
            path         = excluded.path,
            inode        = excluded.inode,
            byte_offset  = excluded.byte_offset,
            last_read_at = excluded.last_read_at,
            last_error   = excluded.last_error
        """,
        (source, path, inode, byte_offset, iso(utcnow()), last_error),
    )


def record_tail_error(db_path: Path, source: str, path: str, message: str) -> None:
    """Persist a read failure without disturbing the saved offset."""
    with transaction(db_path) as conn:
        existing = get_tail_state(conn, source)
        conn.execute(
            """
            INSERT INTO tail_state (source, path, inode, byte_offset, last_read_at, last_error)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(source) DO UPDATE SET last_error = excluded.last_error
            """,
            (
                source,
                path,
                existing["inode"] if existing else None,
                existing["byte_offset"] if existing else 0,
                existing["last_read_at"] if existing else None,
                message,
            ),
        )


# --------------------------------------------------------------------------
# Event insertion
# --------------------------------------------------------------------------

def insert_ssh_events(conn: sqlite3.Connection, rows: Iterable[dict[str, Any]]) -> int:
    payload = [
        (r["ts"], r["ip"], r.get("username"), r["kind"], r["inode"], r["byte_offset"])
        for r in rows
    ]
    if not payload:
        return 0
    cur = conn.executemany(
        """
        INSERT OR IGNORE INTO ssh_events (ts, ip, username, kind, inode, byte_offset)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        payload,
    )
    return cur.rowcount


def insert_scan_events(conn: sqlite3.Connection, rows: Iterable[dict[str, Any]]) -> int:
    payload = [
        (r["ts"], r["ip"], r["dst_port"], r.get("proto"), r["inode"], r["byte_offset"])
        for r in rows
    ]
    if not payload:
        return 0
    cur = conn.executemany(
        """
        INSERT OR IGNORE INTO scan_events (ts, ip, dst_port, proto, inode, byte_offset)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        payload,
    )
    return cur.rowcount


# --------------------------------------------------------------------------
# Alert upsert (escalate-in-place rather than emitting a storm)
# --------------------------------------------------------------------------

def find_open_alert(
    conn: sqlite3.Connection, kind: str, ip: str, cooldown_cutoff: str
) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT * FROM alerts
        WHERE kind = ? AND ip = ? AND last_seen >= ?
        ORDER BY last_seen DESC LIMIT 1
        """,
        (kind, ip, cooldown_cutoff),
    ).fetchone()


def upsert_alert(
    conn: sqlite3.Connection,
    *,
    kind: str,
    ip: str,
    first_seen: str,
    last_seen: str,
    event_count: int,
    detail: dict[str, Any],
    country: str | None,
    country_code: str | None,
    banned: bool | None,
    cooldown_cutoff: str,
) -> tuple[int, bool]:
    """Create or escalate an alert. Returns (alert_id, was_created)."""
    now = iso(utcnow())
    existing = find_open_alert(conn, kind, ip, cooldown_cutoff)

    if existing is None:
        cur = conn.execute(
            """
            INSERT INTO alerts (
                kind, ip, first_seen, last_seen, event_count, detail,
                country, country_code, banned_at_detection, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                kind, ip, first_seen, last_seen, event_count, json.dumps(detail),
                country, country_code,
                None if banned is None else int(banned),
                now, now,
            ),
        )
        return int(cur.lastrowid), True

    conn.execute(
        """
        UPDATE alerts SET
            first_seen  = MIN(first_seen, ?),
            last_seen   = MAX(last_seen, ?),
            event_count = ?,
            detail      = ?,
            country     = COALESCE(?, country),
            country_code= COALESCE(?, country_code),
            updated_at  = ?
        WHERE id = ?
        """,
        (
            first_seen, last_seen, event_count, json.dumps(detail),
            country, country_code, now, existing["id"],
        ),
    )
    return int(existing["id"]), False


# --------------------------------------------------------------------------
# Retention
# --------------------------------------------------------------------------

def prune(db_path: Path, retention_days: int) -> dict[str, int]:
    """Drop events and alerts older than the retention horizon.

    A public VPS can log tens of thousands of auth lines a day; without this
    the events tables grow without bound.
    """
    cutoff = iso(utcnow() - timedelta(days=retention_days))
    removed: dict[str, int] = {}
    with transaction(db_path) as conn:
        for table, column in (
            ("ssh_events", "ts"),
            ("scan_events", "ts"),
            ("alerts", "last_seen"),
        ):
            cur = conn.execute(f"DELETE FROM {table} WHERE {column} < ?", (cutoff,))
            removed[table] = cur.rowcount
    return removed
