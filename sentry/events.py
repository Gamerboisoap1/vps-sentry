"""The unified event stream.

Every detector, collector and state change writes here. The dashboard's
Security Events panel and its Activity Log are two filtered views of this one
table rather than two separate stores -- Security Events is the high-severity
slice, the Activity Log is everything. Keeping one table means an event cannot
appear in one view and be missing from the other.

Events are append-only and idempotent. Anything that could be observed twice
(the same log line re-read, the same port seen on the next cycle) supplies a
``dedupe_key``; the UNIQUE constraint then makes a repeat insert a no-op
instead of a duplicate feed entry.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .db import iso, utcnow

# Ordered most severe first. The dashboard's Security Events panel shows
# everything at MEDIUM and above; the Activity Log shows all of it.
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

CATEGORIES = ("ssh", "network", "system")

# Kind -> (category, default severity, human label)
KINDS: dict[str, tuple[str, str, str]] = {
    "SSH_BRUTE_FORCE":        ("ssh",     "high",     "SSH brute force"),
    "SSH_LOGIN":              ("ssh",     "info",     "SSH login"),
    # A successful login from an address that was attacking moments ago is the
    # single most consequential thing this tool can report, so it is its own
    # kind rather than an ordinary login.
    "SSH_LOGIN_AFTER_ATTACK": ("ssh",     "critical", "SSH login from attacking IP"),
    "PORT_SCAN":              ("network", "medium",   "Port scan"),
    "NEW_PORT":               ("network", "medium",   "New listening port"),
    "PORT_CLOSED":            ("network", "info",     "Port stopped listening"),
    "MONITOR_START":          ("system",  "info",     "Monitoring started"),
    "SOURCE_UNREADABLE":      ("system",  "high",     "Log source unreadable"),
}


def label_for(kind: str) -> str:
    return KINDS.get(kind, ("system", "info", kind))[2]


def emit(
    conn: sqlite3.Connection,
    kind: str,
    description: str,
    *,
    ts: str | None = None,
    severity: str | None = None,
    ip: str | None = None,
    subject: str | None = None,
    detail: dict[str, Any] | None = None,
    dedupe_key: str | None = None,
) -> bool:
    """Record one event. Returns True if it was newly stored.

    An unknown ``kind`` is accepted and filed under system/info rather than
    raising: losing an event because a caller used a new name would be a worse
    failure than filing it imprecisely.
    """
    category, default_severity, _ = KINDS.get(kind, ("system", "info", kind))
    cur = conn.execute(
        """
        INSERT OR IGNORE INTO events
            (ts, kind, category, severity, ip, subject, description, detail, dedupe_key)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ts or iso(utcnow()),
            kind,
            category,
            severity or default_severity,
            ip,
            subject,
            description,
            json.dumps(detail) if detail else None,
            dedupe_key,
        ),
    )
    return cur.rowcount > 0


def recent(
    conn: sqlite3.Connection,
    *,
    limit: int = 100,
    category: str | None = None,
    min_severity: str | None = None,
    search: str | None = None,
) -> list[dict[str, Any]]:
    """Read the feed, newest first, with the dashboard's filters applied."""
    sql = "SELECT * FROM events"
    clauses: list[str] = []
    params: list[Any] = []

    if category:
        clauses.append("category = ?")
        params.append(category)

    if min_severity:
        allowed = [s for s in SEVERITIES if SEVERITY_RANK[s] <= SEVERITY_RANK[min_severity]]
        clauses.append(f"severity IN ({','.join('?' * len(allowed))})")
        params.extend(allowed)

    if search:
        # Parameterised LIKE: the term is attacker-influenced (it can match a
        # username lifted straight out of a log line), so it never reaches SQL
        # as text.
        clauses.append("(description LIKE ? OR ip LIKE ? OR subject LIKE ?)")
        term = f"%{search}%"
        params.extend([term, term, term])

    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY ts DESC, id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def counts_by_category(conn: sqlite3.Connection) -> dict[str, int]:
    rows = conn.execute(
        "SELECT category, COUNT(*) AS n FROM events GROUP BY category"
    ).fetchall()
    counts = {c: 0 for c in CATEGORIES}
    for row in rows:
        counts[row["category"]] = row["n"]
    counts["all"] = sum(counts.values())
    return counts


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    try:
        detail = json.loads(row["detail"]) if row["detail"] else {}
    except json.JSONDecodeError:
        detail = {}
    return {
        "id": row["id"],
        "ts": row["ts"],
        "kind": row["kind"],
        "label": label_for(row["kind"]),
        "category": row["category"],
        "severity": row["severity"],
        "ip": row["ip"],
        "subject": row["subject"],
        "description": row["description"],
        "detail": detail,
    }
