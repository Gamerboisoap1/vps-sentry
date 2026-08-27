"""Parser coverage for the sshd line variants that actually occur."""
from datetime import datetime, timezone

from sentry.parsers import ssh, ufw
from sentry.parsers.ssh import COUNTING_KINDS

NOW = datetime(2026, 8, 25, 14, 0, 0, tzinfo=timezone.utc)
HOST = "Aug 25 13:59:01 vps-fra1 "


def parse_ssh(body: str):
    return ssh.parse_line(HOST + body, now=NOW)


def test_failed_password_for_root():
    ev = parse_ssh("sshd[28471]: Failed password for root from 45.148.10.92 port 51234 ssh2")
    assert ev["kind"] == "failed_password"
    assert ev["ip"] == "45.148.10.92"
    assert ev["username"] == "root"


def test_failed_password_for_invalid_user_extracts_real_username():
    ev = parse_ssh(
        "sshd[28471]: Failed password for invalid user admin from 45.148.10.92 port 51244 ssh2"
    )
    assert ev["username"] == "admin"
    assert ev["kind"] == "failed_password"


def test_key_only_server_preauth_close_is_counted():
    """A VPS with PasswordAuthentication=no reports brute force this way."""
    ev = parse_ssh(
        "sshd[28473]: Connection closed by authenticating user root "
        "45.148.10.92 port 51256 [preauth]"
    )
    assert ev["kind"] == "preauth_close"
    assert ev["kind"] in COUNTING_KINDS
    assert ev["username"] == "root"


def test_connection_closed_by_invalid_user_is_counted():
    ev = parse_ssh(
        "sshd[28473]: Connection closed by invalid user ubuntu 193.34.76.15 port 40122 [preauth]"
    )
    assert ev["kind"] == "preauth_close"
    assert ev["username"] == "ubuntu"


def test_invalid_user_precursor_is_parsed_but_not_counted():
    """Counting this alongside the Failed password line would halve the threshold."""
    ev = parse_ssh("sshd[28473]: Invalid user oracle from 45.148.10.92 port 51250")
    assert ev["kind"] == "invalid_user"
    assert ev["kind"] not in COUNTING_KINDS


def test_failed_publickey_is_counted():
    ev = parse_ssh(
        "sshd[9001]: Failed publickey for root from 91.240.118.23 port 44122 ssh2: "
        "RSA SHA256:abcdef"
    )
    assert ev["kind"] == "failed_publickey"
    assert ev["kind"] in COUNTING_KINDS


def test_max_auth_attempts_is_counted():
    ev = parse_ssh(
        "sshd[9002]: error: maximum authentication attempts exceeded for root "
        "from 91.240.118.23 port 44122 ssh2 [preauth]"
    )
    assert ev["kind"] == "max_auth_attempts"


def test_successful_login_is_parsed_but_never_counted():
    """A success must be recorded and must never move a failure threshold."""
    ev = parse_ssh("sshd[100]: Accepted publickey for deploy from 10.0.0.9 port 5 ssh2")
    assert ev["kind"] == "accepted_login"
    assert ev["kind"] not in COUNTING_KINDS
    assert ev["username"] == "deploy"
    assert ev["method"] == "publickey"


def test_accepted_password_login_is_parsed():
    ev = parse_ssh("sshd[100]: Accepted password for kunal from 45.148.10.92 port 51234 ssh2")
    assert ev["kind"] == "accepted_login"
    assert ev["method"] == "password"
    assert ev["ip"] == "45.148.10.92"


def test_non_sshd_lines_ignored():
    assert ssh.parse_line(HOST + "sudo: pam_unix(sudo:session): session opened", now=NOW) is None
    assert ssh.parse_line(HOST + "CRON[1]: session closed for user root", now=NOW) is None


def test_ipv6_source_is_parsed():
    ev = parse_ssh("sshd[1]: Failed password for root from 2001:db8::dead:beef port 22 ssh2")
    assert ev["ip"] == "2001:db8::dead:beef"


def test_sshd_session_variant_is_recognised():
    """Newer OpenSSH splits the session process out as sshd-session."""
    ev = parse_ssh("sshd-session[4412]: Failed password for root from 45.148.10.92 port 5 ssh2")
    assert ev is not None and ev["kind"] == "failed_password"


# ----------------------------------------------------------------- UFW ----

UFW_LINE = (
    "Aug 25 13:59:41 vps-fra1 kernel: [284719.512033] [UFW BLOCK] IN=eth0 OUT= "
    "MAC=00:16:3e:2a:11:04 SRC=193.34.76.15 DST=10.0.0.4 LEN=44 TOS=0x00 PREC=0x00 "
    "TTL=52 ID=54321 PROTO=TCP SPT=53122 DPT=3306 WINDOW=1024 RES=0x00 SYN URGP=0"
)


def test_ufw_block_line_parsed():
    ev = ufw.parse_line(UFW_LINE, now=NOW)
    assert ev["ip"] == "193.34.76.15"
    assert ev["dst_port"] == 3306
    assert ev["proto"] == "TCP"


def test_ufw_limit_block_variant_parsed():
    ev = ufw.parse_line(UFW_LINE.replace("[UFW BLOCK]", "[UFW LIMIT BLOCK]"), now=NOW)
    assert ev is not None and ev["dst_port"] == 3306


def test_ufw_allow_is_ignored():
    assert ufw.parse_line(UFW_LINE.replace("[UFW BLOCK]", "[UFW ALLOW]"), now=NOW) is None


def test_ufw_icmp_without_port_is_ignored():
    line = (
        "Aug 25 13:59:41 vps-fra1 kernel: [284719.5] [UFW BLOCK] IN=eth0 OUT= "
        "SRC=193.34.76.15 DST=10.0.0.4 LEN=84 PROTO=ICMP TYPE=8 CODE=0"
    )
    assert ufw.parse_line(line, now=NOW) is None


def test_ufw_malformed_port_is_ignored():
    assert ufw.parse_line(UFW_LINE.replace("DPT=3306", "DPT=notaport"), now=NOW) is None
