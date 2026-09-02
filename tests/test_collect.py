"""Collectors: address decoding, exposure classification, sshd policy."""
from sentry.collect import ports as ports_collect
from sentry.collect import users as users_collect
from sentry.collect.host import HostCollector, format_uptime


# --------------------------------------------------------------- ports ----

def test_proc_encodes_ipv4_little_endian():
    """0100007F is 127.0.0.1 with the octets reversed, not 1.0.0.127."""
    assert ports_collect._hex_to_ipv4("0100007F") == "127.0.0.1"
    assert ports_collect._hex_to_ipv4("00000000") == "0.0.0.0"


def test_wildcard_bind_is_public_and_loopback_is_not():
    """The distinction that stops the tool crying wolf about local services."""
    assert ports_collect._classify("0.0.0.0") == "public"
    assert ports_collect._classify("::") == "public"
    assert ports_collect._classify("127.0.0.1") == "loopback"
    assert ports_collect._classify("::1") == "loopback"
    assert ports_collect._classify("10.0.0.4") == "private"
    assert ports_collect._classify("203.0.113.9") == "public"


def test_read_proc_net_keeps_only_listening_sockets(tmp_path):
    content = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000  00000000     0        0 12345 1 x\n"
        "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000  00000000     0        0 12346 1 x\n"
        "   2: 0100007F:D431 0100007F:1F90 01 00000000:00000000 00:00000000  00000000     0        0 12347 1 x\n"
    )
    path = tmp_path / "tcp"
    path.write_text(content)

    rows = ports_collect._read_proc_net(str(path), "tcp", listen_only=True)
    assert len(rows) == 2, "the ESTABLISHED socket must be excluded"
    assert ("0.0.0.0", 22, "12345") in rows
    assert ("127.0.0.1", 8080, "12346") in rows


def test_missing_proc_file_returns_empty_not_error():
    assert ports_collect._read_proc_net("/nonexistent/tcp", "tcp", True) == []


# --------------------------------------------------------------- users ----

def write_sshd(tmp_path, body):
    path = tmp_path / "sshd_config"
    path.write_text(body)
    return str(path)


def test_policy_defaults_when_config_is_unreadable():
    policy = users_collect.read_ssh_policy("/nonexistent/sshd_config")
    assert policy.readable is False
    assert policy.permit_root_login == "prohibit-password"   # OpenSSH default


def test_policy_parsing_ignores_comments(tmp_path):
    path = write_sshd(tmp_path, (
        "# PermitRootLogin yes\n"
        "PermitRootLogin no\n"
        "PasswordAuthentication no\n"
        "AllowUsers deploy kunal\n"
        "DenyUsers baduser\n"
    ))
    policy = users_collect.read_ssh_policy(path)
    assert policy.readable is True
    assert policy.permit_root_login == "no"
    assert policy.password_authentication is False
    assert policy.allow_users == ["deploy", "kunal"]
    assert policy.deny_users == ["baduser"]


def account(username="deploy", shell="/bin/bash", uid=1000, keys=False):
    return users_collect.Account(
        username=username, uid=uid, gid=uid, home=f"/home/{username}",
        shell=shell, kind="regular", ssh_access="unknown", has_authorized_keys=keys,
    )


def test_nologin_shell_cannot_log_in_whatever_the_config_says():
    acct = account(shell="/usr/sbin/nologin")
    access, reasons = users_collect._classify_access(acct, users_collect.SSHPolicy(readable=True))
    assert access == "no"
    assert "nologin" in reasons[0]


def test_allow_list_excludes_everyone_not_named():
    policy = users_collect.SSHPolicy(readable=True, allow_users=["kunal"])
    access, _ = users_collect._classify_access(account(username="deploy"), policy)
    assert access == "no"


def test_named_user_in_allow_list_can_log_in():
    policy = users_collect.SSHPolicy(readable=True, allow_users=["deploy"],
                                     password_authentication=True)
    access, reasons = users_collect._classify_access(account(username="deploy"), policy)
    assert access == "yes"
    assert "in AllowUsers" in reasons


def test_deny_list_wins():
    policy = users_collect.SSHPolicy(readable=True, deny_users=["deploy"])
    access, _ = users_collect._classify_access(account(username="deploy"), policy)
    assert access == "no"


def test_root_blocked_by_permitrootlogin_no():
    policy = users_collect.SSHPolicy(readable=True, permit_root_login="no")
    access, _ = users_collect._classify_access(account(username="root", uid=0), policy)
    assert access == "no"


def test_passwords_disabled_and_no_keys_means_no_access():
    policy = users_collect.SSHPolicy(readable=True, password_authentication=False)
    access, _ = users_collect._classify_access(account(keys=False), policy)
    assert access == "no"


def test_unreadable_config_yields_unknown_not_a_guess():
    policy = users_collect.SSHPolicy(readable=False)
    access, reasons = users_collect._classify_access(account(keys=True), policy)
    assert access == "unknown"
    assert any("not readable" in r for r in reasons)


def test_passwd_parsing_classifies_account_kinds(tmp_path):
    passwd = tmp_path / "passwd"
    passwd.write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "kunal:x:1000:1000::/home/kunal:/bin/bash\n"
        "# a comment\n"
        "malformed-line\n"
    )
    accounts, _ = users_collect.collect(str(passwd), "/nonexistent/sshd_config")
    kinds = {a.username: a.kind for a in accounts}
    assert kinds == {"root": "root", "daemon": "system", "kunal": "regular"}


# ---------------------------------------------------------------- host ----

def test_cpu_is_none_on_the_very_first_sample():
    """CPU is a rate; one reading cannot produce one, and that is not an error."""
    sample = HostCollector().sample()
    assert sample.cpu_percent is None or isinstance(sample.cpu_percent, float)
    assert isinstance(sample.errors, list)


def test_second_sample_can_produce_a_percentage():
    collector = HostCollector()
    collector.sample()
    second = collector.sample()
    if second.cpu_percent is not None:
        assert 0.0 <= second.cpu_percent <= 100.0


def test_disk_reading_is_plausible():
    sample = HostCollector().sample()
    if sample.disk_percent is not None:
        assert 0.0 <= sample.disk_percent <= 100.0
        assert sample.disk_total and sample.disk_total > 0


def test_format_uptime_is_readable():
    assert format_uptime(None) == "unknown"
    assert format_uptime(90) == "1m"
    assert format_uptime(3700) == "1h 1m"
    assert format_uptime(700000) == "8d 2h"


# ------------------------------------------------------------- firewall ----

class _Result:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _patch_ufw(monkeypatch, results):
    """Drive firewall.is_active() with scripted subprocess results."""
    from sentry.collect import firewall as fw
    monkeypatch.setattr(fw.platform, "system", lambda: "Linux")
    monkeypatch.setattr(fw.shutil, "which", lambda name: f"/usr/sbin/{name}")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return results.pop(0)

    monkeypatch.setattr(fw.subprocess, "run", fake_run)
    return calls


def test_firewall_reads_status_without_sudo_when_permitted(monkeypatch):
    from sentry.collect import firewall as fw
    calls = _patch_ufw(monkeypatch, [_Result(0, "Status: active\n")])
    active, detail = fw.is_active()
    assert active is True
    assert len(calls) == 1, "a successful direct call must not escalate"


def test_firewall_falls_back_to_sudo_when_denied(monkeypatch):
    """The service runs unprivileged, so the direct call normally fails.

    Without this fallback the firewall rule abstains forever and the score
    reads identically whether UFW is running or switched off.
    """
    from sentry.collect import firewall as fw
    calls = _patch_ufw(monkeypatch, [
        _Result(1, "", "ERROR: You need to be root to run this script"),
        _Result(0, "Status: inactive\n"),
    ])
    active, detail = fw.is_active()
    assert active is False, "the second attempt's answer must be used"
    assert len(calls) == 2
    assert calls[1][:2] == ["/usr/sbin/sudo", "-n"], "must not prompt for a password"


def test_firewall_returns_unknown_when_both_attempts_fail(monkeypatch):
    """Undetermined is a distinct answer from 'off' and must not deduct."""
    from sentry.collect import firewall as fw
    _patch_ufw(monkeypatch, [_Result(1, "", "denied"), _Result(1, "", "no sudoers rule")])
    active, detail = fw.is_active()
    assert active is None
    assert "could not query" in detail
