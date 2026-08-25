"""API surface, including the health endpoint the dashboard depends on."""
import os

import pytest
from fastapi.testclient import TestClient

from sentinel.api import create_app
from sentinel.db import init_db
from tests.conftest import (
    add_scan_event,
    add_scan_event_now,
    add_ssh_event,
    add_ssh_event_now,
)
from sentinel.db import connect

ATTACKER = "45.148.10.92"


@pytest.fixture
def client(config, monkeypatch):
    monkeypatch.setenv("SENTINEL_INGEST_IN_APP", "0")  # no background worker in tests
    init_db(config.db_path)
    with TestClient(create_app(config)) as c:
        yield c


def seed(config, ssh_events=6, ports=(3306, 6379, 27017, 5432)):
    conn = connect(config.db_path)
    for i in range(ssh_events):
        add_ssh_event(conn, ATTACKER, offset_seconds=i * 10,
                      username="root" if i < 5 else "admin")
    for port in ports:
        add_scan_event(conn, "193.34.76.15", offset_seconds=1, port=port)
    conn.commit()
    conn.close()


def test_alerts_endpoint_empty_by_default(client):
    body = client.get("/api/alerts").json()
    assert body == {"alerts": [], "count": 0}


def test_alerts_endpoint_returns_detections(client, config, geoip, fail2ban):
    from sentinel.detect import detect_ssh_bruteforce
    seed(config)
    conn = connect(config.db_path)
    detect_ssh_bruteforce(conn, config, {ATTACKER}, geoip, fail2ban)
    conn.commit(); conn.close()

    body = client.get("/api/alerts").json()
    assert body["count"] == 1
    alert = body["alerts"][0]
    assert alert["ip"] == ATTACKER
    assert alert["kind"] == "ssh_bruteforce"
    assert alert["banned_at_detection"] is None  # unknown, not False
    assert "usernames" in alert["detail"]


def test_alerts_kind_filter_rejects_unknown_values(client):
    assert client.get("/api/alerts", params={"kind": "ssh_bruteforce"}).status_code == 200
    assert client.get("/api/alerts", params={"kind": "'; DROP TABLE alerts--"}).status_code == 422


def test_alerts_limit_is_bounded(client):
    assert client.get("/api/alerts", params={"limit": 5000}).status_code == 422
    assert client.get("/api/alerts", params={"limit": 0}).status_code == 422


def test_stats_username_shares_sum_to_about_one_hundred(client, config):
    seed(config)
    body = client.get("/api/stats").json()
    shares = {u["username"]: u["share"] for u in body["usernames"]}
    assert shares["root"] == pytest.approx(83.3, abs=0.2)  # 5 of 6
    assert sum(shares.values()) == pytest.approx(100.0, abs=0.2)


def test_stats_username_denominator_excludes_precursor_lines(client, config):
    conn = connect(config.db_path)
    for i in range(5):
        add_ssh_event(conn, ATTACKER, offset_seconds=i, username="root")
    for i in range(5):
        add_ssh_event(conn, ATTACKER, offset_seconds=i, username="root", kind="invalid_user")
    conn.commit(); conn.close()

    body = client.get("/api/stats").json()
    assert body["username_total"] == 5, "invalid_user lines must not inflate the total"


def test_health_reports_stale_when_never_read(client):
    body = client.get("/api/health").json()
    assert body["healthy"] is False
    assert all(s["stale"] for s in body["sources"])
    assert {s["source"] for s in body["sources"]} == {"ssh", "ufw"}


def test_health_exposes_active_rule_thresholds(client):
    """The dashboard shows the thresholds so an alert can be interpreted."""
    body = client.get("/api/health").json()
    assert body["rules"]["ssh"]["threshold"] == 5
    assert body["rules"]["ssh"]["window_seconds"] == 600
    assert body["rules"]["port_scan"]["distinct_ports"] == 4


def test_health_reports_enrichment_degradation(client):
    body = client.get("/api/health").json()
    assert "not found" in body["enrichment"]["geoip"]
    assert body["enrichment"]["fail2ban"] == "disabled"


def test_dashboard_is_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


# --------------------------------------------------------------- timeline ---

def test_timeline_returns_a_full_bucket_series(client):
    """Empty hours must still appear, or a gap reads as a broken chart."""
    body = client.get("/api/timeline", params={"hours": 24}).json()
    assert len(body["buckets"]) == 24
    assert body["peak"] == 0
    assert all(b["ssh"] == 0 and b["scan"] == 0 for b in body["buckets"])


def test_timeline_buckets_are_chronological(client):
    buckets = client.get("/api/timeline").json()["buckets"]
    hours = [b["hour"] for b in buckets]
    assert hours == sorted(hours)
    assert len(set(hours)) == len(hours), "duplicate hour buckets"


def test_timeline_counts_land_in_the_current_hour(client, config):
    conn = connect(config.db_path)
    for i in range(4):
        add_ssh_event_now(conn, ATTACKER, seconds_ago=i)
    add_scan_event_now(conn, "193.34.76.15", seconds_ago=1, port=3306)
    conn.commit(); conn.close()

    body = client.get("/api/timeline").json()
    assert sum(b["ssh"] for b in body["buckets"]) == 4
    assert sum(b["scan"] for b in body["buckets"]) == 1
    assert body["peak"] == 5


def test_timeline_excludes_precursor_lines_from_the_ssh_series(client, config):
    conn = connect(config.db_path)
    add_ssh_event_now(conn, ATTACKER, seconds_ago=1)
    add_ssh_event_now(conn, ATTACKER, seconds_ago=2, kind="invalid_user")
    conn.commit(); conn.close()

    body = client.get("/api/timeline").json()
    assert sum(b["ssh"] for b in body["buckets"]) == 1


def test_timeline_hours_parameter_is_bounded(client):
    assert client.get("/api/timeline", params={"hours": 0}).status_code == 422
    assert client.get("/api/timeline", params={"hours": 500}).status_code == 422


# ------------------------------------------------------------ threat level ---

def test_threat_is_quiet_with_no_recent_alerts(client):
    threat = client.get("/api/stats").json()["threat"]
    assert threat["level"] == 0 and threat["label"] == "quiet"


def test_threat_escalates_with_active_alert_count(client, config, geoip, fail2ban):
    """Posture is a plain count, so it must move with the number of alerts."""
    from sentinel.detect import detect_ssh_bruteforce

    conn = connect(config.db_path)
    ips = [f"45.148.10.{n}" for n in range(1, 4)]
    for ip in ips:
        for i in range(5):
            add_ssh_event(conn, ip, offset_seconds=i * 10)
    detect_ssh_bruteforce(conn, config, set(ips), geoip, fail2ban)
    conn.commit(); conn.close()

    threat = client.get("/api/stats").json()["threat"]
    assert threat["active_alerts_15m"] == 3
    assert threat["label"] == "high"


def test_scan_alert_ports_carry_service_names(client, config, geoip, fail2ban):
    """A scan report saying "27017" is data; saying "MongoDB" is intelligence."""
    from sentinel.detect import detect_port_scan

    conn = connect(config.db_path)
    for port in (3306, 27017, 6379, 5432):
        add_scan_event(conn, "193.34.76.15", offset_seconds=1, port=port)
    detect_port_scan(conn, config, {"193.34.76.15"}, geoip, fail2ban)
    conn.commit(); conn.close()

    alert = client.get("/api/alerts").json()["alerts"][0]
    services = {e["port"]: e["service"] for e in alert["detail"]["port_services"]}
    assert services[27017] == "MongoDB"
    assert services[3306] == "MySQL"
    assert all(e["category"] == "database" for e in alert["detail"]["port_services"])
