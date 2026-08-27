"""The unified event stream: idempotency, filtering, and the two views."""
import pytest

from sentry import events
from sentry.db import connect, init_db


@pytest.fixture
def conn(config):
    init_db(config.db_path)
    c = connect(config.db_path)
    yield c
    c.commit(); c.close()


def test_emit_stores_an_event(conn):
    assert events.emit(conn, "PORT_SCAN", "10 ports probed", ip="1.2.3.4") is True
    found = events.recent(conn)
    assert len(found) == 1
    assert found[0]["kind"] == "PORT_SCAN"
    assert found[0]["category"] == "network"
    assert found[0]["severity"] == "medium"
    assert found[0]["label"] == "Port scan"


def test_dedupe_key_makes_a_repeat_a_no_op(conn):
    """Re-reading the same log region must not refill the feed."""
    first = events.emit(conn, "SSH_LOGIN", "x logged in", dedupe_key="login:9:100")
    second = events.emit(conn, "SSH_LOGIN", "x logged in", dedupe_key="login:9:100")
    assert first is True and second is False
    assert len(events.recent(conn)) == 1


def test_events_without_dedupe_key_are_all_kept(conn):
    """A NULL key must not collide with another NULL key."""
    for i in range(3):
        events.emit(conn, "MONITOR_START", f"cycle {i}")
    assert len(events.recent(conn)) == 3


def test_unknown_kind_is_filed_not_dropped(conn):
    assert events.emit(conn, "SOMETHING_NEW", "unrecognised") is True
    found = events.recent(conn)[0]
    assert found["category"] == "system" and found["severity"] == "info"


def test_explicit_severity_overrides_the_default(conn):
    events.emit(conn, "NEW_PORT", "port 8080 open", severity="high")
    assert events.recent(conn)[0]["severity"] == "high"


def test_category_filter(conn):
    events.emit(conn, "SSH_BRUTE_FORCE", "a")
    events.emit(conn, "PORT_SCAN", "b")
    events.emit(conn, "MONITOR_START", "c")
    assert len(events.recent(conn, category="ssh")) == 1
    assert len(events.recent(conn, category="network")) == 1
    assert len(events.recent(conn)) == 3


def test_min_severity_is_the_security_events_view(conn):
    """Security Events is the >= medium slice of what Activity Log shows."""
    events.emit(conn, "SSH_LOGIN_AFTER_ATTACK", "critical one")
    events.emit(conn, "SSH_BRUTE_FORCE", "high one")
    events.emit(conn, "PORT_SCAN", "medium one")
    events.emit(conn, "SSH_LOGIN", "info one")

    security_view = events.recent(conn, min_severity="medium")
    activity_view = events.recent(conn)
    assert len(security_view) == 3
    assert len(activity_view) == 4
    assert "info one" not in [e["description"] for e in security_view]


def test_search_matches_ip_and_description(conn):
    events.emit(conn, "SSH_BRUTE_FORCE", "61 failures from 45.148.10.92", ip="45.148.10.92")
    events.emit(conn, "PORT_SCAN", "6 ports from 9.9.9.9", ip="9.9.9.9")
    assert len(events.recent(conn, search="45.148")) == 1
    assert len(events.recent(conn, search="ports")) == 1
    assert len(events.recent(conn, search="nothing here")) == 0


def test_search_term_is_parameterised(conn):
    """The term can come from an attacker-chosen username, so it is bound."""
    events.emit(conn, "SSH_LOGIN", "safe row")
    hostile = "%' OR 1=1 --"
    assert events.recent(conn, search=hostile) == []
    assert len(events.recent(conn)) == 1, "table must be intact"


def test_newest_first(conn):
    events.emit(conn, "SSH_LOGIN", "older", ts="2026-08-27T10:00:00+00:00")
    events.emit(conn, "SSH_LOGIN", "newer", ts="2026-08-27T11:00:00+00:00")
    assert [e["description"] for e in events.recent(conn)] == ["newer", "older"]


def test_counts_by_category_includes_all(conn):
    events.emit(conn, "SSH_BRUTE_FORCE", "a")
    events.emit(conn, "PORT_SCAN", "b")
    counts = events.counts_by_category(conn)
    assert counts["ssh"] == 1 and counts["network"] == 1
    assert counts["system"] == 0 and counts["all"] == 2
