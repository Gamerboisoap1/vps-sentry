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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

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

log = logging.getLogger("sentinel.ingest")


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

            outcomes = []
            if ssh_ips:
                outcomes += detect_ssh_bruteforce(
                    conn, self.config, ssh_ips, self.geoip, self.fail2ban
                )
            if ufw_ips:
                outcomes += detect_port_scan(
                    conn, self.config, ufw_ips, self.geoip, self.fail2ban
                )

        report.alerts_created = sum(1 for o in outcomes if o.created)
        report.alerts_escalated = sum(1 for o in outcomes if not o.created)
        report.duration_ms = int((time.monotonic() - started) * 1000)
        return report

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
    parser = argparse.ArgumentParser(description="VPS Sentinel log ingestion")
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
