"""The ingest cycle: tail -> parse -> store -> detect.

Event insertion and the tail-offset advance happen inside a single
transaction. That is what makes ingestion idempotent: either a batch of lines
is stored and the offset moves past them, or neither happens and the same
region is re-read next cycle. Committing the offset separately would open a
window where a crash loses events silently.
"""

from __future__ import annotations

import argparse
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from . import events
from .collect import firewall, ports as ports_collect, users as users_collect
from .collect.host import HostCollector
from .config import Config, load_config
from .db import (
    get_tail_state,
    init_db,
    insert_scan_events,
    insert_ssh_events,
    iso,
    prune,
    record_tail_error,
    save_tail_state,
    transaction,
    utcnow,
)
from .detect import detect_port_scan, detect_ssh_bruteforce
from .enrich.fail2ban import Fail2BanClient
from .enrich.geoip import GeoIPResolver
from .parsers import ssh as ssh_parser
from .parsers import ufw as ufw_parser
from .tailer import TailPosition, read_new_lines

log = logging.getLogger("sentry.ingest")


@dataclass
class SourceReport:
    source: str
    path: str
    lines_read: int = 0
    events_stored: int = 0
    rotated: bool = False
    error: str | None = None


@dataclass
class IngestReport:
    started_at: str
    duration_ms: int = 0
    sources: list[SourceReport] = field(default_factory=list)
    alerts_created: int = 0
    alerts_escalated: int = 0
    logins_recorded: int = 0
    ports_opened: int = 0
    ports_closed: int = 0
    host_sampled: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "alerts_created": self.alerts_created,
            "alerts_escalated": self.alerts_escalated,
            "sources": [vars(s) for s in self.sources],
        }


class Ingestor:
    def __init__(self, config: Config) -> None:
        self.config = config
        init_db(config.db_path)
        self.geoip = GeoIPResolver(config.geoip_db)
        self.host = HostCollector(disk_path=config.disk_path)
        self.fail2ban = Fail2BanClient(
            jail=config.fail2ban_jail, enabled=config.fail2ban_enabled
        )

    # -- one source -------------------------------------------------------
    def _process_source(
        self,
        source: str,
        path: Path,
        parse_line: Callable[..., dict[str, Any] | None],
        now: datetime,
    ) -> tuple[SourceReport, set[str], list[dict[str, Any]], TailPosition | None]:
        report = SourceReport(source=source, path=str(path))

        try:
            with transaction(self.config.db_path) as conn:
                state_row = get_tail_state(conn, source)
                previous = TailPosition(
                    inode=state_row["inode"] if state_row else None,
                    byte_offset=state_row["byte_offset"] if state_row else 0,
                )
        except Exception as exc:  # pragma: no cover - storage failure
            report.error = f"state read failed: {exc}"
            return report, set(), [], None

        try:
            result = read_new_lines(path, previous)
        except FileNotFoundError:
            message = f"log not found: {path}"
            record_tail_error(self.config.db_path, source, str(path), message)
            report.error = message
            return report, set(), [], None
        except PermissionError:
            message = f"permission denied reading {path} (needs root or adm group)"
            record_tail_error(self.config.db_path, source, str(path), message)
            report.error = message
            return report, set(), [], None
        except OSError as exc:
            message = f"read failed: {exc}"
            record_tail_error(self.config.db_path, source, str(path), message)
            report.error = message
            return report, set(), [], None

        report.lines_read = len(result.lines)
        report.rotated = result.rotated

        events: list[dict[str, Any]] = []
        for line in result.lines:
            try:
                parsed = parse_line(line.text, now=now)
            except Exception as exc:  # a malformed line must not stop the batch
                log.warning("parse error in %s at offset %d: %s", source, line.byte_offset, exc)
                continue
            if parsed is None:
                continue
            parsed["ts"] = iso(parsed["ts"])
            parsed["inode"] = line.inode
            parsed["byte_offset"] = line.byte_offset
            events.append(parsed)

        candidate_ips = {e["ip"] for e in events}
        return report, candidate_ips, events, result.position

    # -- full cycle -------------------------------------------------------
    def run_once(self) -> IngestReport:
        started = time.monotonic()
        now = utcnow()
        report = IngestReport(started_at=iso(now))

        ssh_report, ssh_ips, ssh_events, ssh_pos = self._process_source(
            "ssh", self.config.auth_log, ssh_parser.parse_line, now
        )
        ufw_report, ufw_ips, ufw_events, ufw_pos = self._process_source(
            "ufw", self.config.ufw_log, ufw_parser.parse_line, now
        )
        report.sources = [ssh_report, ufw_report]

        # Re-read positions inside the write transaction so the offset advance
        # commits atomically with the events it accounts for.
        with transaction(self.config.db_path) as conn:
            if ssh_report.error is None and ssh_pos is not None:
                ssh_report.events_stored = insert_ssh_events(conn, ssh_events)
                save_tail_state(
                    conn, "ssh", str(self.config.auth_log),
                    ssh_pos.inode, ssh_pos.byte_offset, last_error=None,
                )
            if ufw_report.error is None and ufw_pos is not None:
                ufw_report.events_stored = insert_scan_events(conn, ufw_events)
                save_tail_state(
                    conn, "ufw", str(self.config.ufw_log),
                    ufw_pos.inode, ufw_pos.byte_offset, last_error=None,
                )

            for source in (ssh_report, ufw_report):
                if source.error:
                    events.emit(
                        conn, "SOURCE_UNREADABLE",
                        f"{source.source} log unreadable: {source.error}",
                        subject=source.source,
                        # One per hour per source, or a broken path would emit
                        # an event on every single cycle.
                        dedupe_key=f"src_err:{source.source}:{iso(now)[:13]}",
                    )

            if self.config.collect_host:
                report.host_sampled = self._sample_host(conn)
            if self.config.collect_ports:
                report.ports_opened, report.ports_closed = self._sync_ports(conn)

            outcomes = []
            if ssh_ips:
                outcomes += detect_ssh_bruteforce(
                    conn, self.config, ssh_ips, self.geoip, self.fail2ban
                )
            if ufw_ips:
                outcomes += detect_port_scan(
                    conn, self.config, ufw_ips, self.geoip, self.fail2ban
                )

            # Deliberately after detection. Classifying a login depends on
            # knowing whether that IP has an alert, and on a first ingest the
            # alert is created in this very cycle -- running earlier would file
            # the breach that matters as a routine login.
            report.logins_recorded = self._record_logins(conn, ssh_events)

        report.alerts_created = sum(1 for o in outcomes if o.created)
        report.alerts_escalated = sum(1 for o in outcomes if not o.created)
        report.duration_ms = int((time.monotonic() - started) * 1000)
        return report

    # -- login events -----------------------------------------------------
    def _record_logins(self, conn, ssh_events: list[dict[str, Any]]) -> int:
        """Turn successful logins into events, flagging the dangerous case.

        A login from an address that tripped an alert within the last hour is
        the sequence that matters: the brute force stopped because it worked.
        """
        recorded = 0
        cutoff = iso(utcnow() - timedelta(hours=1))
        for event in ssh_events:
            if event.get("kind") != "accepted_login":
                continue
            ip = event["ip"]
            attacking = conn.execute(
                "SELECT COUNT(*) AS n FROM alerts WHERE ip = ? AND last_seen >= ?",
                (ip, cutoff),
            ).fetchone()["n"]

            user = event.get("username") or "unknown"
            method = event.get("method") or "unknown method"
            kind = "SSH_LOGIN_AFTER_ATTACK" if attacking else "SSH_LOGIN"
            description = (
                f"{user} logged in from {ip} via {method}"
                if not attacking
                else f"{user} logged in from {ip} via {method} — this IP has an active alert"
            )
            if events.emit(
                conn, kind, description,
                ts=event["ts"], ip=ip, subject=user,
                detail={"method": method, "had_active_alert": bool(attacking)},
                # Byte position makes the same line idempotent across re-reads.
                dedupe_key=f"login:{event['inode']}:{event['byte_offset']}",
            ):
                recorded += 1
        return recorded

    # -- host metrics -----------------------------------------------------
    def _sample_host(self, conn) -> bool:
        sample = self.host.sample()
        conn.execute(
            """
            INSERT INTO host_samples (
                ts, cpu_percent, mem_percent, mem_total, mem_used,
                disk_percent, disk_total, disk_used, net_rx_bps, net_tx_bps,
                uptime_secs, load1
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                iso(utcnow()), sample.cpu_percent, sample.mem_percent,
                sample.mem_total, sample.mem_used, sample.disk_percent,
                sample.disk_total, sample.disk_used, sample.net_rx_bps,
                sample.net_tx_bps, sample.uptime_secs, sample.load1,
            ),
        )
        return True

    # -- listening ports --------------------------------------------------
    def _sync_ports(self, conn) -> tuple[int, int]:
        """Diff current listeners against the known set; emit the changes."""
        current = ports_collect.collect()
        if not current:
            return 0, 0

        known = {
            (r["proto"], r["port"]): r
            for r in conn.execute("SELECT * FROM port_state").fetchall()
        }
        # First run has nothing to compare against. Emitting NEW_PORT for every
        # existing listener would bury the feed on startup, so the initial set
        # is recorded as a baseline instead.
        baseline = not known
        now = iso(utcnow())
        opened = closed = 0

        for entry in current:
            key = (entry.proto, entry.port)
            if key not in known:
                conn.execute(
                    """INSERT OR REPLACE INTO port_state
                       (proto, port, address, process, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (entry.proto, entry.port, entry.address, entry.process, now, now),
                )
                if not baseline:
                    opened += 1
                    events.emit(
                        conn, "NEW_PORT",
                        f"Port {entry.port}/{entry.proto} ({entry.service}) started listening"
                        f" on {entry.address}",
                        subject=str(entry.port),
                        severity="high" if entry.exposure == "public" else "medium",
                        detail={"port": entry.port, "proto": entry.proto,
                                "service": entry.service, "exposure": entry.exposure,
                                "process": entry.process},
                        dedupe_key=f"port_open:{entry.proto}:{entry.port}:{now[:13]}",
                    )
            else:
                conn.execute(
                    "UPDATE port_state SET last_seen = ?, address = ?, process = ? "
                    "WHERE proto = ? AND port = ?",
                    (now, entry.address, entry.process, entry.proto, entry.port),
                )

        seen = {(e.proto, e.port) for e in current}
        for key, row in known.items():
            if key in seen:
                continue
            conn.execute(
                "DELETE FROM port_state WHERE proto = ? AND port = ?", key
            )
            closed += 1
            events.emit(
                conn, "PORT_CLOSED",
                f"Port {row['port']}/{row['proto']} stopped listening",
                subject=str(row["port"]),
                detail={"port": row["port"], "proto": row["proto"]},
                dedupe_key=f"port_closed:{row['proto']}:{row['port']}:{now[:13]}",
            )

        if baseline:
            events.emit(
                conn, "MONITOR_START",
                f"Port monitoring started; {len(current)} listening sockets recorded as baseline",
                detail={"count": len(current)},
            )
        return opened, closed

    def run_forever(self, stop: Callable[[], bool] | None = None) -> None:
        prune_every = max(1, int(3600 / max(self.config.poll_seconds, 1)))
        cycle = 0
        while not (stop and stop()):
            try:
                report = self.run_once()
                log.info(
                    "cycle: %d lines, %d events, %d new alerts",
                    sum(s.lines_read for s in report.sources),
                    sum(s.events_stored for s in report.sources),
                    report.alerts_created,
                )
            except Exception:
                log.exception("ingest cycle failed")
            cycle += 1
            if cycle % prune_every == 0:
                try:
                    prune(self.config.db_path, self.config.retention_days)
                except Exception:
                    log.exception("prune failed")
            time.sleep(self.config.poll_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="VPS Sentry log ingestion")
    parser.add_argument("--once", action="store_true", help="run a single cycle and exit")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    config = load_config()
    ingestor = Ingestor(config)
    if args.once:
        report = ingestor.run_once()
        for source in report.sources:
            status = source.error or f"{source.lines_read} lines, {source.events_stored} events"
            print(f"  {source.source:4s} {source.path}: {status}")
        print(f"  alerts: {report.alerts_created} new, {report.alerts_escalated} escalated")
    else:
        ingestor.run_forever()


if __name__ == "__main__":
    main()
