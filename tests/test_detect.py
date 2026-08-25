"""Detection rules: thresholds, windows, and alert escalation."""
import json

from sentinel.detect import PORT_SCAN, SSH_BRUTEFORCE, detect_port_scan, detect_ssh_bruteforce
from tests.conftest import add_scan_event, add_ssh_event

ATTACKER = "45.148.10.92"
SCANNER = "193.34.76.15"


def _alerts(conn, kind):
    return conn.execute("SELECT * FROM alerts WHERE kind = ?", (kind,)).fetchall()


# ------------------------------------------------------------- SSH rule ----

def test_below_threshold_does_not_alert(conn, config, geoip, fail2ban):
    for i in range(4):
        add_ssh_event(conn, ATTACKER, offset_seconds=i * 10)
    out = detect_ssh_bruteforce(conn, config, {ATTACKER}, geoip, fail2ban)
    assert out == []
    assert _alerts(conn, SSH_BRUTEFORCE) == []


def test_threshold_reached_creates_alert(conn, config, geoip, fail2ban):
    for i in range(5):
        add_ssh_event(conn, ATTACKER, offset_seconds=i * 10)
    out = detect_ssh_bruteforce(conn, config, {ATTACKER}, geoip, fail2ban)
    assert len(out) == 1 and out[0].created is True
    rows = _alerts(conn, SSH_BRUTEFORCE)
    assert len(rows) == 1
    assert rows[0]["ip"] == ATTACKER
    assert rows[0]["event_count"] == 5


def test_attempts_spread_beyond_window_do_not_alert(conn, config, geoip, fail2ban):
    """Six attempts over an hour is not a brute force; five in ten minutes is."""
    for i in range(6):
        add_ssh_event(conn, ATTACKER, offset_seconds=i * 600)
    out = detect_ssh_bruteforce(conn, config, {ATTACKER}, geoip, fail2ban)
    assert out == []


def test_invalid_user_precursor_does_not_count_toward_threshold(conn, config, geoip, fail2ban):
    """Five 'Invalid user' notices are five halves of five attempts, not five."""
    for i in range(5):
        add_ssh_event(conn, ATTACKER, offset_seconds=i * 10, kind="invalid_user")
    assert detect_ssh_bruteforce(conn, config, {ATTACKER}, geoip, fail2ban) == []


def test_key_only_preauth_closes_do_alert(conn, config, geoip, fail2ban):
    for i in range(5):
        add_ssh_event(conn, ATTACKER, offset_seconds=i * 10, kind="preauth_close")
    out = detect_ssh_bruteforce(conn, config, {ATTACKER}, geoip, fail2ban)
    assert len(out) == 1


def test_sustained_attack_escalates_instead_of_duplicating(conn, config, geoip, fail2ban):
    """The alert-storm guard: one incident stays one row."""
    for i in range(5):
        add_ssh_event(conn, ATTACKER, offset_seconds=i * 10)
    first = detect_ssh_bruteforce(conn, config, {ATTACKER}, geoip, fail2ban)
    assert first[0].created is True

    for i in range(5, 12):
        add_ssh_event(conn, ATTACKER, offset_seconds=i * 10)
    second = detect_ssh_bruteforce(conn, config, {ATTACKER}, geoip, fail2ban)

    assert second[0].created is False, "second detection should escalate, not duplicate"
    rows = _alerts(conn, SSH_BRUTEFORCE)
    assert len(rows) == 1
    assert rows[0]["event_count"] == 12, "escalated alert should report the incident total"


def test_separate_incidents_after_cooldown_create_separate_alerts(conn, config, geoip, fail2ban):
    for i in range(5):
        add_ssh_event(conn, ATTACKER, offset_seconds=i * 10)
    detect_ssh_bruteforce(conn, config, {ATTACKER}, geoip, fail2ban)

    # Well past the 600s cooldown.
    for i in range(5):
        add_ssh_event(conn, ATTACKER, offset_seconds=5000 + i * 10)
    out = detect_ssh_bruteforce(conn, config, {ATTACKER}, geoip, fail2ban)

    assert out[0].created is True
    assert len(_alerts(conn, SSH_BRUTEFORCE)) == 2


def test_two_attackers_get_two_alerts(conn, config, geoip, fail2ban):
    other = "91.240.118.23"
    for i in range(5):
        add_ssh_event(conn, ATTACKER, offset_seconds=i * 10)
        add_ssh_event(conn, other, offset_seconds=i * 10)
    out = detect_ssh_bruteforce(conn, config, {ATTACKER, other}, geoip, fail2ban)
    assert len(out) == 2
    assert {o.ip for o in out} == {ATTACKER, other}


def test_attempts_from_different_ips_do_not_pool(conn, config, geoip, fail2ban):
    """Detection is per-IP; five IPs trying once each is not a brute force."""
    ips = {f"203.0.113.{n}" for n in range(1, 6)}
    for ip in ips:
        add_ssh_event(conn, ip, offset_seconds=5)
    assert detect_ssh_bruteforce(conn, config, ips, geoip, fail2ban) == []


def test_alert_detail_records_username_breakdown(conn, config, geoip, fail2ban):
    for i in range(4):
        add_ssh_event(conn, ATTACKER, offset_seconds=i * 5, username="root")
    add_ssh_event(conn, ATTACKER, offset_seconds=25, username="admin")
    detect_ssh_bruteforce(conn, config, {ATTACKER}, geoip, fail2ban)

    detail = json.loads(_alerts(conn, SSH_BRUTEFORCE)[0]["detail"])
    assert detail["usernames"] == {"root": 4, "admin": 1}
    assert detail["threshold"] == 5 and detail["window_seconds"] == 600


def test_ban_status_unknown_when_fail2ban_unavailable(conn, config, geoip, fail2ban):
    """'Unknown' must be distinguishable from 'not banned'."""
    for i in range(5):
        add_ssh_event(conn, ATTACKER, offset_seconds=i * 10)
    detect_ssh_bruteforce(conn, config, {ATTACKER}, geoip, fail2ban)
    assert _alerts(conn, SSH_BRUTEFORCE)[0]["banned_at_detection"] is None


# ------------------------------------------------------ port-scan rule ----

def test_three_distinct_ports_do_not_alert(conn, config, geoip, fail2ban):
    for port in (22, 80, 443):
        add_scan_event(conn, SCANNER, offset_seconds=1, port=port)
    assert detect_port_scan(conn, config, {SCANNER}, geoip, fail2ban) == []


def test_four_distinct_ports_alert(conn, config, geoip, fail2ban):
    for port in (22, 3306, 6379, 27017):
        add_scan_event(conn, SCANNER, offset_seconds=1, port=port)
    out = detect_port_scan(conn, config, {SCANNER}, geoip, fail2ban)
    assert len(out) == 1
    detail = json.loads(_alerts(conn, PORT_SCAN)[0]["detail"])
    assert detail["port_count"] == 4
    assert detail["ports"] == [22, 3306, 6379, 27017]


def test_hammering_one_port_is_not_a_scan(conn, config, geoip, fail2ban):
    """Distinct ports, not packet count -- twenty hits on 22 is not mapping."""
    for i in range(20):
        add_scan_event(conn, SCANNER, offset_seconds=i, port=22)
    assert detect_port_scan(conn, config, {SCANNER}, geoip, fail2ban) == []


def test_slow_scan_spread_past_window_evades_the_rule(conn, config, geoip, fail2ban):
    """Documents a real limitation: a paced scan stays under the window."""
    for i, port in enumerate((22, 3306, 6379, 27017)):
        add_scan_event(conn, SCANNER, offset_seconds=i * 120, port=port)
    assert detect_port_scan(conn, config, {SCANNER}, geoip, fail2ban) == []


def test_port_scan_escalates_in_place(conn, config, geoip, fail2ban):
    for port in (22, 3306, 6379, 27017):
        add_scan_event(conn, SCANNER, offset_seconds=1, port=port)
    detect_port_scan(conn, config, {SCANNER}, geoip, fail2ban)

    for port in (5432, 8080):
        add_scan_event(conn, SCANNER, offset_seconds=2, port=port)
    out = detect_port_scan(conn, config, {SCANNER}, geoip, fail2ban)

    assert out[0].created is False
    assert len(_alerts(conn, PORT_SCAN)) == 1
    detail = json.loads(_alerts(conn, PORT_SCAN)[0]["detail"])
    assert detail["port_count"] == 6


def test_wide_sweep_caps_stored_port_list(conn, config, geoip, fail2ban):
    for port in range(1000, 1100):
        add_scan_event(conn, SCANNER, offset_seconds=1, port=port)
    detect_port_scan(conn, config, {SCANNER}, geoip, fail2ban)
    detail = json.loads(_alerts(conn, PORT_SCAN)[0]["detail"])
    assert detail["port_count"] == 100
    assert len(detail["ports"]) == 64, "payload should be capped"


def test_geoip_absent_leaves_country_null_without_failing(conn, config, geoip, fail2ban):
    for port in (22, 3306, 6379, 27017):
        add_scan_event(conn, SCANNER, offset_seconds=1, port=port)
    detect_port_scan(conn, config, {SCANNER}, geoip, fail2ban)
    assert _alerts(conn, PORT_SCAN)[0]["country"] is None
