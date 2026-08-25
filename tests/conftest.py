from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.config import Config, SSHRule, ScanRule
from sentinel.db import connect, init_db, iso
from sentinel.enrich.fail2ban import Fail2BanClient
from sentinel.enrich.geoip import GeoIPResolver

BASE = datetime(2026, 8, 25, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        auth_log=tmp_path / "auth.log",
        ufw_log=tmp_path / "ufw.log",
        db_path=tmp_path / "sentinel.db",
        geoip_db=tmp_path / "missing-geoip.mmdb",
        ssh=SSHRule(threshold=5, window_seconds=600, cooldown_seconds=600),
        scan=ScanRule(distinct_ports=4, window_seconds=60, cooldown_seconds=300),
        fail2ban_enabled=False,
    )


@pytest.fixture
def conn(config):
    init_db(config.db_path)
    connection = connect(config.db_path)
    yield connection
    connection.commit()
    connection.close()


@pytest.fixture
def geoip(config):
    return GeoIPResolver(config.geoip_db)


@pytest.fixture
def fail2ban():
    return Fail2BanClient(jail="sshd", enabled=False)


def add_ssh_event(conn, ip, *, offset_seconds, username="root", kind="failed_password"):
    ts = iso(BASE + timedelta(seconds=offset_seconds))
    row_id = conn.execute("SELECT COALESCE(MAX(byte_offset), 0) + 100 AS o FROM ssh_events").fetchone()["o"]
    conn.execute(
        "INSERT INTO ssh_events (ts, ip, username, kind, inode, byte_offset) VALUES (?,?,?,?,?,?)",
        (ts, ip, username, kind, 1, row_id),
    )


def add_scan_event(conn, ip, *, offset_seconds, port, proto="TCP"):
    ts = iso(BASE + timedelta(seconds=offset_seconds))
    row_id = conn.execute("SELECT COALESCE(MAX(byte_offset), 0) + 100 AS o FROM scan_events").fetchone()["o"]
    conn.execute(
        "INSERT INTO scan_events (ts, ip, dst_port, proto, inode, byte_offset) VALUES (?,?,?,?,?,?)",
        (ts, ip, port, proto, 1, row_id),
    )


def add_ssh_event_now(conn, ip, *, seconds_ago=0, username="root", kind="failed_password"):
    """Insert an SSH event relative to real wall-clock time.

    The BASE-anchored helpers above are fine for the detectors, which anchor
    their windows on the newest event. Endpoints that query a rolling window
    ending at "now" need timestamps that actually fall inside it.
    """
    from datetime import datetime, timezone
    ts = iso(datetime.now(timezone.utc) - timedelta(seconds=seconds_ago))
    offset = conn.execute(
        "SELECT COALESCE(MAX(byte_offset), 0) + 100 AS o FROM ssh_events"
    ).fetchone()["o"]
    conn.execute(
        "INSERT INTO ssh_events (ts, ip, username, kind, inode, byte_offset) VALUES (?,?,?,?,?,?)",
        (ts, ip, username, kind, 1, offset),
    )


def add_scan_event_now(conn, ip, *, seconds_ago=0, port=3306, proto="TCP"):
    from datetime import datetime, timezone
    ts = iso(datetime.now(timezone.utc) - timedelta(seconds=seconds_ago))
    offset = conn.execute(
        "SELECT COALESCE(MAX(byte_offset), 0) + 100 AS o FROM scan_events"
    ).fetchone()["o"]
    conn.execute(
        "INSERT INTO scan_events (ts, ip, dst_port, proto, inode, byte_offset) VALUES (?,?,?,?,?,?)",
        (ts, ip, port, proto, 1, offset),
    )
