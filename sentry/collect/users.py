"""Local account inventory, read-only.

The security question is not "who exists" but "who can log in over SSH", and
those are different sets. An account with a nologin shell cannot open a
session no matter how many times it appears in /etc/passwd, while an account
with a valid shell and a key in authorized_keys can, whatever else is true.

So each account is resolved against the effective sshd policy: AllowUsers and
AllowGroups (an allow-list makes every unlisted account unable to log in),
DenyUsers, PermitRootLogin, and whether password authentication is on at all.
Where the answer cannot be determined -- config unreadable, home directory not
readable -- it reports unknown rather than guessing in either direction.

Strictly read-only: no creation, deletion, or password handling. Reporting is
the whole job.
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

PASSWD = "/etc/passwd"
SSHD_CONFIG = "/etc/ssh/sshd_config"

NOLOGIN_SHELLS = {
    "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false",
    "/usr/bin/nologin", "/dev/null", "",
}

# Below this UID an account is a service account on essentially every distro.
# root (0) is called out separately because it is the one that matters.
REGULAR_UID_MIN = 1000


@dataclass
class SSHPolicy:
    permit_root_login: str = "prohibit-password"   # OpenSSH default since 7.0
    password_authentication: bool = True
    allow_users: list[str] = field(default_factory=list)
    allow_groups: list[str] = field(default_factory=list)
    deny_users: list[str] = field(default_factory=list)
    readable: bool = False
    source: str = SSHD_CONFIG

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Account:
    username: str
    uid: int
    gid: int
    home: str
    shell: str
    kind: str              # "root" | "regular" | "system"
    ssh_access: str        # "yes" | "no" | "unknown"
    reasons: list[str] = field(default_factory=list)
    has_authorized_keys: bool | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def read_ssh_policy(path: str = SSHD_CONFIG) -> SSHPolicy:
    policy = SSHPolicy(source=path)
    try:
        text = Path(path).read_text()
    except OSError:
        return policy   # readable stays False; callers report "unknown"

    policy.readable = True
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        key, values = parts[0].lower(), parts[1:]
        if key == "permitrootlogin":
            policy.permit_root_login = values[0].lower()
        elif key == "passwordauthentication":
            policy.password_authentication = values[0].lower() in {"yes", "true"}
        elif key == "allowusers":
            policy.allow_users.extend(values)
        elif key == "allowgroups":
            policy.allow_groups.extend(values)
        elif key == "denyusers":
            policy.deny_users.extend(values)
    return policy


def _has_authorized_keys(home: str) -> bool | None:
    path = Path(home) / ".ssh" / "authorized_keys"
    try:
        if not path.exists():
            return False
        return path.stat().st_size > 0
    except OSError:
        return None   # exists but unreadable without privilege


def _classify_access(account: Account, policy: SSHPolicy) -> tuple[str, list[str]]:
    reasons: list[str] = []

    if account.shell in NOLOGIN_SHELLS:
        return "no", [f"shell is {account.shell or 'empty'}"]

    if account.username in policy.deny_users:
        return "no", ["listed in DenyUsers"]

    if account.username == "root":
        setting = policy.permit_root_login
        if setting == "no":
            return "no", ["PermitRootLogin no"]
        if setting in {"prohibit-password", "without-password"}:
            reasons.append("PermitRootLogin prohibit-password (keys only)")
        elif setting == "yes":
            reasons.append("PermitRootLogin yes")
        elif setting == "forced-commands-only":
            return "no", ["PermitRootLogin forced-commands-only"]

    # An allow-list is exclusive: anyone not named cannot log in.
    if policy.allow_users and account.username not in policy.allow_users:
        if not policy.allow_groups:
            return "no", ["not in AllowUsers"]
        reasons.append("not in AllowUsers; AllowGroups may still permit")
        return "unknown", reasons
    if policy.allow_users and account.username in policy.allow_users:
        reasons.append("in AllowUsers")

    if account.has_authorized_keys:
        reasons.append("has authorized_keys")
    if policy.password_authentication:
        reasons.append("password authentication enabled")

    if not policy.readable:
        reasons.append("sshd_config not readable; assuming OpenSSH defaults")
        return "unknown", reasons

    if account.has_authorized_keys is None and not policy.password_authentication:
        reasons.append("authorized_keys not readable and passwords disabled")
        return "unknown", reasons

    if not policy.password_authentication and account.has_authorized_keys is False:
        return "no", ["passwords disabled and no authorized_keys"]

    return "yes", reasons


def collect(passwd_path: str = PASSWD, sshd_config: str = SSHD_CONFIG) -> tuple[list[Account], SSHPolicy]:
    policy = read_ssh_policy(sshd_config)
    accounts: list[Account] = []

    try:
        lines = Path(passwd_path).read_text().splitlines()
    except OSError:
        return accounts, policy

    for line in lines:
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 7:
            continue
        username, _, uid_raw, gid_raw, _, home, shell = fields[:7]
        try:
            uid, gid = int(uid_raw), int(gid_raw)
        except ValueError:
            continue

        if uid == 0:
            kind = "root"
        elif uid >= REGULAR_UID_MIN and shell not in NOLOGIN_SHELLS:
            kind = "regular"
        else:
            kind = "system"

        account = Account(
            username=username, uid=uid, gid=gid, home=home, shell=shell,
            kind=kind, ssh_access="unknown",
        )
        account.has_authorized_keys = _has_authorized_keys(home)
        account.ssh_access, account.reasons = _classify_access(account, policy)
        accounts.append(account)

    # Accounts that can log in first, root above them; the rest by uid.
    accounts.sort(key=lambda a: (a.ssh_access != "yes", a.kind != "root", a.uid))
    return accounts, policy


def status(passwd_path: str = PASSWD) -> str:
    if not os.path.exists(passwd_path):
        return f"{passwd_path} not found"
    if not os.access(passwd_path, os.R_OK):
        return f"{passwd_path} not readable"
    return "ready"
