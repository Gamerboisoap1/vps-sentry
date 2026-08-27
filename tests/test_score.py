"""The posture score: arithmetic, transparency, and abstention."""
from types import SimpleNamespace

import pytest

from sentry import score as score_module
from sentry.db import connect, init_db, iso, utcnow
from datetime import timedelta


@pytest.fixture
def conn(config):
    init_db(config.db_path)
    c = connect(config.db_path)
    yield c
    c.commit(); c.close()


def port(exposure="public", category="web", service="HTTP", number=80):
    return SimpleNamespace(exposure=exposure, category=category, service=service, port=number)


def policy(readable=True, root="prohibit-password", passwords=False):
    return SimpleNamespace(
        readable=readable, permit_root_login=root, password_authentication=passwords
    )


def compute(conn, **kw):
    defaults = dict(
        listening_ports=[], ssh_policy=policy(), host_sample=None,
        firewall_active=True, fail2ban_ready=True,
    )
    defaults.update(kw)
    return score_module.compute(conn, **defaults)


def test_clean_host_scores_full_marks(conn):
    result = compute(conn, host_sample=SimpleNamespace(disk_percent=10.0))
    assert result.value == 100
    assert result.band == "good"
    assert result.deductions == []


def test_every_deduction_is_named_and_explained(conn):
    """A number nobody can explain is worse than no number."""
    result = compute(conn, firewall_active=False)
    assert len(result.deductions) == 1
    d = result.deductions[0]
    assert d.rule == "firewall" and d.points == 20 and "UFW" in d.detail
    assert result.value == 80


def test_unknown_inputs_abstain_rather_than_deduct(conn):
    """Punishing the operator for what we could not measure would be wrong."""
    result = compute(
        conn, firewall_active=None, listening_ports=None,
        ssh_policy=None, host_sample=None,
    )
    assert result.deductions == []
    assert result.value == 100
    assert len(result.unknowns) == 4


def test_password_auth_and_root_login_both_deduct(conn):
    result = compute(conn, ssh_policy=policy(root="yes", passwords=True))
    rules = {d.rule for d in result.deductions}
    assert rules == {"root_login", "password_auth"}
    assert result.value == 100 - 15 - 10


def test_publicly_exposed_database_is_penalised(conn):
    ports = [port(category="database", service="MySQL", number=3306)]
    result = compute(conn, listening_ports=ports)
    assert any(d.rule == "exposed_database" for d in result.deductions)


def test_loopback_database_is_not_penalised(conn):
    """Bound to localhost is not reachable, and must not be called exposed."""
    ports = [port(exposure="loopback", category="database", service="MySQL", number=3306)]
    result = compute(conn, listening_ports=ports)
    assert not any(d.rule == "exposed_database" for d in result.deductions)


def test_port_budget_only_counts_public_listeners(conn):
    many_private = [port(exposure="loopback", number=n) for n in range(20)]
    assert not any(d.rule == "open_ports" for d in compute(conn, listening_ports=many_private).deductions)

    many_public = [port(number=n) for n in range(20)]
    assert any(d.rule == "open_ports" for d in compute(conn, listening_ports=many_public).deductions)


def test_login_after_attack_is_the_heaviest_single_deduction(conn):
    conn.execute(
        "INSERT INTO events (ts, kind, category, severity, description) VALUES (?,?,?,?,?)",
        (iso(utcnow()), "SSH_LOGIN_AFTER_ATTACK", "ssh", "critical", "root logged in"),
    )
    result = compute(conn)
    breach = next(d for d in result.deductions if d.rule == "login_after_attack")
    assert breach.points == 25
    assert breach.points == max(d.points for d in result.deductions)


def test_stale_breach_outside_the_window_does_not_deduct(conn):
    old = iso(utcnow() - timedelta(days=3))
    conn.execute(
        "INSERT INTO events (ts, kind, category, severity, description) VALUES (?,?,?,?,?)",
        (old, "SSH_LOGIN_AFTER_ATTACK", "ssh", "critical", "ancient"),
    )
    assert not any(d.rule == "login_after_attack" for d in compute(conn).deductions)


def test_score_is_clamped_at_zero(conn):
    """Enough failures must not produce a negative score."""
    conn.execute(
        "INSERT INTO events (ts, kind, category, severity, description) VALUES (?,?,?,?,?)",
        (iso(utcnow()), "SSH_LOGIN_AFTER_ATTACK", "ssh", "critical", "breach"),
    )
    conn.execute(
        "INSERT INTO alerts (kind, ip, first_seen, last_seen, event_count, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?)",
        ("ssh_bruteforce", "1.2.3.4", iso(utcnow()), iso(utcnow()), 99, iso(utcnow()), iso(utcnow())),
    )
    result = compute(
        conn,
        firewall_active=False,
        fail2ban_ready=False,
        ssh_policy=policy(root="yes", passwords=True),
        listening_ports=[port(category="database", number=n) for n in range(10)],
        host_sample=SimpleNamespace(disk_percent=99.0),
    )
    assert result.value == 0
    assert result.band == "poor"


def test_bands_track_the_value(conn):
    assert score_module._band(100) == "good"
    assert score_module._band(85) == "good"
    assert score_module._band(70) == "fair"
    assert score_module._band(50) == "weak"
    assert score_module._band(10) == "poor"
