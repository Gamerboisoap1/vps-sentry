"""End-to-end: real files on disk through parse, store, and detect."""
from datetime import datetime, timedelta

from sentry.db import connect
from sentry.ingest import Ingestor

ATTACKER = "45.148.10.92"
SCANNER = "193.34.76.15"


def syslog_stamp(seconds_ago: int) -> str:
    """BSD syslog renders the writer's *local* time with no offset."""
    moment = datetime.now().astimezone() - timedelta(seconds=seconds_ago)
    return moment.strftime("%b %d %H:%M:%S")


def ssh_line(seconds_ago: int, user: str = "root", ip: str = ATTACKER) -> str:
    return (
        f"{syslog_stamp(seconds_ago)} vps-fra1 sshd[28471]: "
        f"Failed password for {user} from {ip} port 51234 ssh2\n"
    )


def ufw_line(seconds_ago: int, port: int, ip: str = SCANNER) -> str:
    return (
        f"{syslog_stamp(seconds_ago)} vps-fra1 kernel: [284719.512033] [UFW BLOCK] "
        f"IN=eth0 OUT= MAC=00:16:3e:2a:11:04 SRC={ip} DST=10.0.0.4 LEN=44 TOS=0x00 "
        f"PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=53122 DPT={port} WINDOW=1024 "
        f"RES=0x00 SYN URGP=0\n"
    )


def test_full_cycle_produces_an_ssh_alert(config):
    config.auth_log.write_text("".join(ssh_line(60 - i * 5) for i in range(6)))
    config.ufw_log.write_text("")

    report = Ingestor(config).run_once()

    assert report.sources[0].events_stored == 6
    assert report.alerts_created == 1

    conn = connect(config.db_path)
    row = conn.execute("SELECT * FROM alerts").fetchone()
    conn.close()
    assert row["ip"] == ATTACKER and row["kind"] == "ssh_bruteforce"


def test_full_cycle_produces_a_port_scan_alert(config):
    config.auth_log.write_text("")
    config.ufw_log.write_text(
        "".join(ufw_line(30, port) for port in (3306, 6379, 27017, 5432))
    )

    report = Ingestor(config).run_once()

    assert report.sources[1].events_stored == 4
    assert report.alerts_created == 1


def test_second_cycle_does_not_reingest_the_same_lines(config):
    """The idempotency guarantee: offsets advance transactionally with events."""
    config.auth_log.write_text("".join(ssh_line(60 - i * 5) for i in range(6)))
    config.ufw_log.write_text("")

    ingestor = Ingestor(config)
    ingestor.run_once()
    second = ingestor.run_once()

    assert second.sources[0].lines_read == 0
    assert second.sources[0].events_stored == 0

    conn = connect(config.db_path)
    total = conn.execute("SELECT COUNT(*) n FROM ssh_events").fetchone()["n"]
    conn.close()
    assert total == 6, "events were double-counted across cycles"


def test_appended_lines_are_picked_up_next_cycle(config):
    config.auth_log.write_text(ssh_line(90))
    config.ufw_log.write_text("")
    ingestor = Ingestor(config)
    ingestor.run_once()

    with config.auth_log.open("a") as fh:
        fh.writelines(ssh_line(60 - i * 5) for i in range(5))
    second = ingestor.run_once()

    assert second.sources[0].events_stored == 5
    assert second.alerts_created == 1


def test_missing_log_is_reported_not_crashed(config):
    """A VPS without rsyslog has no auth.log; that must surface, not explode."""
    config.ufw_log.write_text("")
    report = Ingestor(config).run_once()

    ssh_source = report.sources[0]
    assert ssh_source.error is not None
    assert "not found" in ssh_source.error

    conn = connect(config.db_path)
    state = conn.execute("SELECT * FROM tail_state WHERE source='ssh'").fetchone()
    conn.close()
    assert state is not None and state["last_error"] is not None


def test_non_ssh_noise_is_ignored(config):
    """cron and sudo chatter shares the file but is none of our business."""
    config.auth_log.write_text(
        f"{syslog_stamp(30)} vps-fra1 CRON[123]: pam_unix(cron:session): session opened\n"
        f"{syslog_stamp(29)} vps-fra1 sudo:  deploy : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls\n"
        f"{syslog_stamp(28)} vps-fra1 systemd-logind[812]: New session 214 of user deploy.\n"
    )
    config.ufw_log.write_text("")
    report = Ingestor(config).run_once()
    assert report.sources[0].lines_read == 3
    assert report.sources[0].events_stored == 0
    assert report.alerts_created == 0


def test_successful_login_is_stored_but_raises_no_alert(config):
    """A success is evidence worth keeping and must never trip a threshold."""
    config.auth_log.write_text(
        f"{syslog_stamp(28)} vps-fra1 sshd[1]: Accepted publickey for deploy "
        f"from 10.0.0.9 port 5 ssh2\n"
    )
    config.ufw_log.write_text("")
    report = Ingestor(config).run_once()
    assert report.sources[0].events_stored == 1
    assert report.alerts_created == 0
    assert report.logins_recorded == 1


def test_rotation_between_cycles_keeps_ingesting(config):
    config.auth_log.write_text(ssh_line(120))
    config.ufw_log.write_text("")
    ingestor = Ingestor(config)
    ingestor.run_once()

    config.auth_log.rename(config.auth_log.with_suffix(".log.1"))
    config.auth_log.write_text("".join(ssh_line(60 - i * 5) for i in range(6)))

    second = ingestor.run_once()
    assert second.sources[0].rotated is True
    assert second.sources[0].events_stored == 6
    assert second.alerts_created == 1


def login_line(seconds_ago: int, user: str, ip: str, method: str = "password") -> str:
    return (
        f"{syslog_stamp(seconds_ago)} vps-fra1 sshd[28903]: "
        f"Accepted {method} for {user} from {ip} port 51890 ssh2\n"
    )


def _events(config, kind=None):
    conn = connect(config.db_path)
    sql = "SELECT * FROM events" + (" WHERE kind = ?" if kind else "")
    rows = conn.execute(sql, (kind,) if kind else ()).fetchall()
    conn.close()
    return rows


def test_successful_login_from_a_clean_ip_is_routine(config):
    config.auth_log.write_text(login_line(30, "deploy", "82.14.203.66", "publickey"))
    config.ufw_log.write_text("")
    Ingestor(config).run_once()

    rows = _events(config, "SSH_LOGIN")
    assert len(rows) == 1
    assert rows[0]["severity"] == "info"
    assert _events(config, "SSH_LOGIN_AFTER_ATTACK") == []


def test_login_from_an_attacking_ip_is_critical(config):
    """The sequence that matters: the brute force stopped because it worked.

    Regression test for an ordering bug -- login classification has to run
    *after* detection, because on a first ingest the alert that makes this
    login significant is created in the very same cycle.
    """
    lines = [ssh_line(120 - i * 5) for i in range(8)]        # brute force
    lines.append(login_line(30, "root", ATTACKER))            # then it succeeds
    config.auth_log.write_text("".join(lines))
    config.ufw_log.write_text("")

    report = Ingestor(config).run_once()
    assert report.alerts_created == 1

    routine = _events(config, "SSH_LOGIN")
    breach = _events(config, "SSH_LOGIN_AFTER_ATTACK")
    assert routine == [], "the login must not be filed as ordinary"
    assert len(breach) == 1
    assert breach[0]["severity"] == "critical"
    assert breach[0]["ip"] == ATTACKER


def test_detected_alerts_emit_one_event_each(config):
    config.auth_log.write_text("".join(ssh_line(60 - i * 5) for i in range(6)))
    config.ufw_log.write_text("")
    ingestor = Ingestor(config)
    ingestor.run_once()

    assert len(_events(config, "SSH_BRUTE_FORCE")) == 1

    # A second cycle escalates the same incident; the feed must not gain a
    # duplicate entry for it.
    with config.auth_log.open("a") as fh:
        fh.writelines(ssh_line(20 - i) for i in range(5))
    ingestor.run_once()
    assert len(_events(config, "SSH_BRUTE_FORCE")) == 1


def test_unreadable_log_raises_a_system_event(config):
    config.ufw_log.write_text("")
    Ingestor(config).run_once()
    rows = _events(config, "SOURCE_UNREADABLE")
    assert len(rows) == 1
    assert rows[0]["severity"] == "high"
    assert "ssh" in rows[0]["subject"]


def test_host_sample_is_recorded_each_cycle(config):
    config.auth_log.write_text("")
    config.ufw_log.write_text("")
    report = Ingestor(config).run_once()
    assert report.host_sampled is True

    conn = connect(config.db_path)
    rows = conn.execute("SELECT * FROM host_samples").fetchall()
    conn.close()
    assert len(rows) == 1


def test_first_port_sync_records_a_baseline_without_flooding(config):
    """Every existing listener is not "new"; emitting them all would bury the feed."""
    config.auth_log.write_text("")
    config.ufw_log.write_text("")
    report = Ingestor(config).run_once()

    assert report.ports_opened == 0
    new_port_events = _events(config, "NEW_PORT")
    assert new_port_events == []
    assert len(_events(config, "MONITOR_START")) <= 1
