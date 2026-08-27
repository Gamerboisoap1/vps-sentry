"""FastAPI application: JSON endpoints plus the static dashboard.

Binds to loopback by default (see :mod:`sentry.config`). Exposing this on a
public interface would publish your log data and an unauthenticated endpoint
on the machine you are trying to protect; reach it over an SSH tunnel instead.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import Config, load_config
from .db import connect, init_db, iso, utcnow
from .detect import PORT_SCAN, SSH_BRUTEFORCE
from .enrich.fail2ban import Fail2BanClient
from .enrich.geoip import GeoIPResolver
from .ingest import Ingestor
from .parsers.ssh import COUNTING_KINDS
from .services import service_for

log = logging.getLogger("sentry.api")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
_COUNTING_KINDS_SQL = ",".join(f"'{k}'" for k in sorted(COUNTING_KINDS))


class NoCacheStaticFiles(StaticFiles):
    """Serve the dashboard assets without caching.

    Sentry is a single-host tool reached over a loopback tunnel, so there is
    nothing to gain from caching and a great deal to lose: a stale app.js
    silently showing old rendering logic is indistinguishable from a bug.
    """

    def is_not_modified(self, response_headers, request_headers) -> bool:  # noqa: D102
        return False

    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-store, must-revalidate"
        return response


class AppState:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.geoip = GeoIPResolver(config.geoip_db)
        self.fail2ban = Fail2BanClient(
            jail=config.fail2ban_jail, enabled=config.fail2ban_enabled
        )
        self.ingestor: Ingestor | None = None
        self.worker: threading.Thread | None = None
        self.stop_event = threading.Event()


def _row_to_alert(row: sqlite3.Row, banned_now: frozenset[str], f2b_ok: bool) -> dict[str, Any]:
    try:
        detail = json.loads(row["detail"]) if row["detail"] else {}
    except json.JSONDecodeError:
        detail = {}

    # Port numbers alone are data; naming the service is what makes a scan
    # report legible. Resolved here so services.py stays the only table.
    if row["kind"] == PORT_SCAN and detail.get("ports"):
        detail["port_services"] = [
            {
                "port": int(p),
                "service": service_for(int(p)).name,
                "category": service_for(int(p)).category,
            }
            for p in detail["ports"][:12]
        ]

    banned_at_detection = row["banned_at_detection"]
    return {
        "id": row["id"],
        "kind": row["kind"],
        "ip": row["ip"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "event_count": row["event_count"],
        "country": row["country"],
        "country_code": row["country_code"],
        # Two different questions: was it banned when detected, and is it
        # banned right now. Stock fail2ban bans expire after 10 minutes.
        "banned_at_detection": None if banned_at_detection is None else bool(banned_at_detection),
        "banned_now": (row["ip"] in banned_now) if f2b_ok else None,
        "detail": detail,
    }


def create_app(config: Config | None = None) -> FastAPI:
    cfg = config or load_config()
    state = AppState(cfg)
    init_db(cfg.db_path)

    run_ingest = os.environ.get("SENTRY_INGEST_IN_APP", "1").strip().lower() not in {
        "0", "false", "no", "off",
    }

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if run_ingest:
            state.ingestor = Ingestor(cfg)
            state.worker = threading.Thread(
                target=state.ingestor.run_forever,
                kwargs={"stop": state.stop_event.is_set},
                daemon=True,
                name="sentry-ingest",
            )
            state.worker.start()
            log.info("ingest worker started (every %ds)", cfg.poll_seconds)
        yield
        state.stop_event.set()

    app = FastAPI(title="VPS Sentry", version="1.0", lifespan=lifespan)
    app.state.sentry = state

    # ---------------------------------------------------------------- alerts
    @app.get("/api/alerts")
    def alerts(
        kind: str | None = Query(default=None, pattern="^(ssh_bruteforce|port_scan)$"),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> dict[str, Any]:
        sql = "SELECT * FROM alerts"
        params: list[Any] = []
        if kind:
            sql += " WHERE kind = ?"
            params.append(kind)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        banned_now = state.fail2ban.banned_ips()
        f2b_ok = state.fail2ban.status == "ready"

        conn = connect(cfg.db_path)
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()

        return {
            "alerts": [_row_to_alert(r, banned_now, f2b_ok) for r in rows],
            "count": len(rows),
        }

    # ----------------------------------------------------------------- stats
    @app.get("/api/stats")
    def stats() -> dict[str, Any]:
        conn = connect(cfg.db_path)
        try:
            day_ago = iso(utcnow() - timedelta(days=1))

            totals = {
                "ssh_alerts": conn.execute(
                    "SELECT COUNT(*) n FROM alerts WHERE kind = ?", (SSH_BRUTEFORCE,)
                ).fetchone()["n"],
                "scan_alerts": conn.execute(
                    "SELECT COUNT(*) n FROM alerts WHERE kind = ?", (PORT_SCAN,)
                ).fetchone()["n"],
                "unique_attackers": conn.execute(
                    "SELECT COUNT(DISTINCT ip) n FROM alerts"
                ).fetchone()["n"],
                "ssh_events_24h": conn.execute(
                    f"""SELECT COUNT(*) n FROM ssh_events
                        WHERE ts >= ? AND kind IN ({_COUNTING_KINDS_SQL})""",
                    (day_ago,),
                ).fetchone()["n"],
                "scan_events_24h": conn.execute(
                    "SELECT COUNT(*) n FROM scan_events WHERE ts >= ?", (day_ago,)
                ).fetchone()["n"],
            }

            # Username breakdown -- computed over counting kinds only, so the
            # precursor "Invalid user" lines cannot inflate the denominator.
            username_rows = conn.execute(
                f"""
                SELECT COALESCE(username, '(unknown)') AS username, COUNT(*) AS n
                FROM ssh_events
                WHERE kind IN ({_COUNTING_KINDS_SQL})
                GROUP BY username ORDER BY n DESC LIMIT 12
                """
            ).fetchall()
            username_total = conn.execute(
                f"SELECT COUNT(*) n FROM ssh_events WHERE kind IN ({_COUNTING_KINDS_SQL})"
            ).fetchone()["n"]

            usernames = [
                {
                    "username": r["username"],
                    "count": r["n"],
                    "share": round(r["n"] * 100.0 / username_total, 1) if username_total else 0.0,
                }
                for r in username_rows
            ]

            country_rows = conn.execute(
                """
                SELECT COALESCE(country, 'Unknown') AS country,
                       country_code, COUNT(DISTINCT ip) AS n
                FROM alerts GROUP BY country, country_code
                ORDER BY n DESC LIMIT 10
                """
            ).fetchall()

            port_rows = conn.execute(
                """
                SELECT dst_port, COUNT(*) AS n FROM scan_events
                WHERE ts >= ? GROUP BY dst_port ORDER BY n DESC LIMIT 10
                """,
                (day_ago,),
            ).fetchall()

            # Posture is a plain count of alerts still moving in the last
            # quarter hour -- no scoring model, so the number on screen can
            # always be traced back to specific rows.
            recent_cutoff = iso(utcnow() - timedelta(minutes=15))
            active_now = conn.execute(
                "SELECT COUNT(*) n FROM alerts WHERE last_seen >= ?", (recent_cutoff,)
            ).fetchone()["n"]
        finally:
            conn.close()

        if active_now == 0:
            level, label = 0, "quiet"
        elif active_now <= 2:
            level, label = 1, "elevated"
        elif active_now <= 5:
            level, label = 2, "high"
        else:
            level, label = 3, "severe"
        threat = {
            "level": level,
            "label": label,
            "active_alerts_15m": active_now,
            "basis": "alerts with activity in the last 15 minutes",
        }

        return {
            "totals": totals,
            "usernames": usernames,
            "username_total": username_total,
            "countries": [
                {"country": r["country"], "code": r["country_code"], "attackers": r["n"]}
                for r in country_rows
            ],
            "top_ports": [
                {
                    "port": r["dst_port"],
                    "hits": r["n"],
                    "service": service_for(int(r["dst_port"])).name,
                    "category": service_for(int(r["dst_port"])).category,
                }
                for r in port_rows
            ],
            "threat": threat,
        }

    # -------------------------------------------------------------- timeline
    @app.get("/api/timeline")
    def timeline(hours: int = Query(default=24, ge=1, le=168)) -> dict[str, Any]:
        """Hourly event counts, so bursts are visible rather than averaged away.

        Buckets are keyed on the first 13 characters of the stored ISO
        timestamp ("2026-08-25T06"), which is exact because every timestamp is
        normalised to UTC on the way in.
        """
        start = utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(hours=hours - 1)
        start_iso = iso(start)

        conn = connect(cfg.db_path)
        try:
            ssh_rows = conn.execute(
                f"""SELECT substr(ts, 1, 13) AS bucket, COUNT(*) AS n
                    FROM ssh_events
                    WHERE ts >= ? AND kind IN ({_COUNTING_KINDS_SQL})
                    GROUP BY bucket""",
                (start_iso,),
            ).fetchall()
            scan_rows = conn.execute(
                """SELECT substr(ts, 1, 13) AS bucket, COUNT(*) AS n
                   FROM scan_events WHERE ts >= ? GROUP BY bucket""",
                (start_iso,),
            ).fetchall()
        finally:
            conn.close()

        ssh_by_bucket = {r["bucket"]: r["n"] for r in ssh_rows}
        scan_by_bucket = {r["bucket"]: r["n"] for r in scan_rows}

        buckets = []
        for offset in range(hours):
            moment = start + timedelta(hours=offset)
            key = iso(moment)[:13]
            buckets.append(
                {
                    "hour": key,
                    "label": moment.strftime("%H:%M"),
                    "ssh": ssh_by_bucket.get(key, 0),
                    "scan": scan_by_bucket.get(key, 0),
                }
            )

        peak = max((b["ssh"] + b["scan"] for b in buckets), default=0)
        return {"hours": hours, "peak": peak, "buckets": buckets}

    # ---------------------------------------------------------------- health
    @app.get("/api/health")
    def health() -> dict[str, Any]:
        """Freshness and subsystem status.

        The most important field on the whole dashboard: a monitor that has
        silently stopped reading looks identical to a quiet network unless
        staleness is surfaced explicitly.
        """
        conn = connect(cfg.db_path)
        try:
            rows = conn.execute("SELECT * FROM tail_state").fetchall()
        finally:
            conn.close()

        now = utcnow()
        sources = []
        by_source = {r["source"]: r for r in rows}
        for name, path in (("ssh", cfg.auth_log), ("ufw", cfg.ufw_log)):
            row = by_source.get(name)
            age = None
            if row and row["last_read_at"]:
                last = datetime.fromisoformat(row["last_read_at"])
                age = int((now - last).total_seconds())
            sources.append(
                {
                    "source": name,
                    "path": str(path),
                    "last_read_at": row["last_read_at"] if row else None,
                    "seconds_since_read": age,
                    "stale": age is None or age > cfg.stale_after_seconds,
                    "error": row["last_error"] if row else "never read",
                    "byte_offset": row["byte_offset"] if row else 0,
                }
            )

        healthy = all(s["error"] is None and not s["stale"] for s in sources)
        return {
            "healthy": healthy,
            "server_time": iso(now),
            "stale_after_seconds": cfg.stale_after_seconds,
            "poll_seconds": cfg.poll_seconds,
            "sources": sources,
            "enrichment": {
                "geoip": state.geoip.status,
                "fail2ban": state.fail2ban.status,
                "fail2ban_jail": cfg.fail2ban_jail,
            },
            "rules": {
                "ssh": {
                    "threshold": cfg.ssh.threshold,
                    "window_seconds": cfg.ssh.window_seconds,
                    "cooldown_seconds": cfg.ssh.cooldown_seconds,
                },
                "port_scan": {
                    "distinct_ports": cfg.scan.distinct_ports,
                    "window_seconds": cfg.scan.window_seconds,
                    "cooldown_seconds": cfg.scan.cooldown_seconds,
                },
            },
        }

    # ------------------------------------------------------------- dashboard
    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    if STATIC_DIR.is_dir():
        app.mount("/static", NoCacheStaticFiles(directory=str(STATIC_DIR)), name="static")

    return app


app = create_app()
