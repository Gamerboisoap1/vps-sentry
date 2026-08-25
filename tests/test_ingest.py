"""End-to-end: real files on disk through parse, store, and detect."""
from datetime import datetime, timedelta

from sentinel.db import connect
from sentinel.ingest import Ingestor

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


def test_noise_lines_are_ignored(config):
    config.auth_log.write_text(
        f"{syslog_stamp(30)} vps-fra1 CRON[123]: pam_unix(cron:session): session opened\n"
        f"{syslog_stamp(29)} vps-fra1 sudo:  deploy : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls\n"
        f"{syslog_stamp(28)} vps-fra1 sshd[1]: Accepted publickey for deploy from 10.0.0.9 port 5 ssh2\n"
    )
    config.ufw_log.write_text("")
    report = Ingestor(config).run_once()
    assert report.sources[0].lines_read == 3
    assert report.sources[0].events_stored == 0
    assert report.alerts_created == 0


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
