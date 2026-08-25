"""Threshold-and-window detection rules.

Both detectors share one shape: group events by source IP, count something
distinct inside a sliding time window, fire when the count crosses a
threshold. No models, no training, no scoring -- every alert can be traced to
specific rows in the events table and explained line by line.

Three decisions that are easy to get wrong and are made explicitly here:

**The window is anchored to the newest event, not to wall-clock now.** That
keeps the rules correct when backfilling an existing log or replaying a
capture, where "now" bears no relation to the timestamps being examined.

**A firing rule escalates an open alert instead of creating another one.**
Without this, a brute force that keeps going emits a fresh alert on every new
log line and buries the operator in duplicates.

**The trigger span and the reporting span are different.** The rule fires on
the window (5 failures in 10 minutes), but the alert reports totals across the
whole incident, from ``first_seen`` to now -- otherwise a two-hour attack
would forever read "5 attempts" no matter how long it ran.
"""

from __future__ import annotations

import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .config import Config
from .db import iso, upsert_alert
from .enrich.fail2ban import Fail2BanClient
from .enrich.geoip import GeoIPResolver
from .parsers.ssh import COUNTING_KINDS

SSH_BRUTEFORCE = "ssh_bruteforce"
PORT_SCAN = "port_scan"

_COUNTING_KINDS_SQL = ",".join(f"'{kind}'" for kind in sorted(COUNTING_KINDS))


@dataclass
class AlertOutcome:
    alert_id: int
    kind: str
    ip: str
    created: bool
    event_count: int


def _open_alert_first_seen(
    conn: sqlite3.Connection, kind: str, ip: str, cooldown_cutoff: str
) -> str | None:
    row = conn.execute(
        """
        SELECT first_seen FROM alerts
        WHERE kind = ? AND ip = ? AND last_seen >= ?
        ORDER BY last_seen DESC LIMIT 1
        """,
        (kind, ip, cooldown_cutoff),
    ).fetchone()
    return row["first_seen"] if row else None


def detect_ssh_bruteforce(
    conn: sqlite3.Connection,
    config: Config,
    candidate_ips: set[str],
    geoip: GeoIPResolver,
    fail2ban: Fail2BanClient,
) -> list[AlertOutcome]:
    """Fire on N failed authentications from one IP inside the window."""
    outcomes: list[AlertOutcome] = []
    rule = config.ssh

    for ip in sorted(candidate_ips):
        anchor_row = conn.execute(
            f"""
            SELECT MAX(ts) AS anchor FROM ssh_events
            WHERE ip = ? AND kind IN ({_COUNTING_KINDS_SQL})
            """,
            (ip,),
        ).fetchone()
        if not anchor_row or not anchor_row["anchor"]:
            continue

        anchor = datetime.fromisoformat(anchor_row["anchor"])
        window_start = iso(anchor - timedelta(seconds=rule.window_seconds))
        anchor_iso = iso(anchor)

        window_count = conn.execute(
            f"""
            SELECT COUNT(*) AS n FROM ssh_events
            WHERE ip = ? AND kind IN ({_COUNTING_KINDS_SQL}) AND ts >= ? AND ts <= ?
            """,
            (ip, window_start, anchor_iso),
        ).fetchone()["n"]

        if window_count < rule.threshold:
            continue

        cooldown_cutoff = iso(anchor - timedelta(seconds=rule.cooldown_seconds))
        incident_start = _open_alert_first_seen(conn, SSH_BRUTEFORCE, ip, cooldown_cutoff)
        report_from = min(incident_start, window_start) if incident_start else window_start

        rows = conn.execute(
            f"""
            SELECT ts, username, kind FROM ssh_events
            WHERE ip = ? AND kind IN ({_COUNTING_KINDS_SQL}) AND ts >= ? AND ts <= ?
            ORDER BY ts
            """,
            (ip, report_from, anchor_iso),
        ).fetchall()
        if not rows:
            continue

        usernames = Counter(r["username"] or "(unknown)" for r in rows)
        kinds = Counter(r["kind"] for r in rows)
        country, code = geoip.lookup(ip)

        detail: dict[str, Any] = {
            "usernames": dict(usernames.most_common()),
            "kinds": dict(kinds.most_common()),
            "window_count": window_count,
            "window_seconds": rule.window_seconds,
            "threshold": rule.threshold,
        }

        alert_id, created = upsert_alert(
            conn,
            kind=SSH_BRUTEFORCE,
            ip=ip,
            first_seen=rows[0]["ts"],
            last_seen=rows[-1]["ts"],
            event_count=len(rows),
            detail=detail,
            country=country,
            country_code=code,
            banned=fail2ban.is_banned(ip),
            cooldown_cutoff=cooldown_cutoff,
        )
        outcomes.append(
            AlertOutcome(alert_id, SSH_BRUTEFORCE, ip, created, len(rows))
        )

    return outcomes


def detect_port_scan(
    conn: sqlite3.Connection,
    config: Config,
    candidate_ips: set[str],
    geoip: GeoIPResolver,
    fail2ban: Fail2BanClient,
) -> list[AlertOutcome]:
    """Fire on N *distinct* destination ports from one IP inside the window."""
    outcomes: list[AlertOutcome] = []
    rule = config.scan

    for ip in sorted(candidate_ips):
        anchor_row = conn.execute(
            "SELECT MAX(ts) AS anchor FROM scan_events WHERE ip = ?", (ip,)
        ).fetchone()
        if not anchor_row or not anchor_row["anchor"]:
            continue

        anchor = datetime.fromisoformat(anchor_row["anchor"])
        window_start = iso(anchor - timedelta(seconds=rule.window_seconds))
        anchor_iso = iso(anchor)

        distinct_ports = conn.execute(
            """
            SELECT COUNT(DISTINCT dst_port) AS n FROM scan_events
            WHERE ip = ? AND ts >= ? AND ts <= ?
            """,
            (ip, window_start, anchor_iso),
        ).fetchone()["n"]

        if distinct_ports < rule.distinct_ports:
            continue

        cooldown_cutoff = iso(anchor - timedelta(seconds=rule.cooldown_seconds))
        incident_start = _open_alert_first_seen(conn, PORT_SCAN, ip, cooldown_cutoff)
        report_from = min(incident_start, window_start) if incident_start else window_start

        rows = conn.execute(
            """
            SELECT ts, dst_port, proto FROM scan_events
            WHERE ip = ? AND ts >= ? AND ts <= ?
            ORDER BY ts
            """,
            (ip, report_from, anchor_iso),
        ).fetchall()
        if not rows:
            continue

        ports = sorted({int(r["dst_port"]) for r in rows})
        protos = Counter(r["proto"] or "(unknown)" for r in rows)
        country, code = geoip.lookup(ip)

        detail: dict[str, Any] = {
            "ports": ports[:64],          # cap the payload on a wide sweep
            "port_count": len(ports),
            "protocols": dict(protos.most_common()),
            "window_distinct_ports": distinct_ports,
            "window_seconds": rule.window_seconds,
            "threshold": rule.distinct_ports,
        }

        alert_id, created = upsert_alert(
            conn,
            kind=PORT_SCAN,
            ip=ip,
            first_seen=rows[0]["ts"],
            last_seen=rows[-1]["ts"],
            event_count=len(rows),
            detail=detail,
            country=country,
            country_code=code,
            banned=fail2ban.is_banned(ip),
            cooldown_cutoff=cooldown_cutoff,
        )
        outcomes.append(AlertOutcome(alert_id, PORT_SCAN, ip, created, len(rows)))

    return outcomes
