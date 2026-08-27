"""SSH authentication log parser.

Counting failed logins sounds trivial until you look at what sshd actually
writes. Two traps drive the design here:

**Trap 1 -- key-only servers never log "Failed password".** A VPS with
``PasswordAuthentication no`` reports brute force as
``Connection closed by authenticating user root 1.2.3.4 port 5 [preauth]``.
A parser that only knows the password line sits at zero while the box is
visibly under attack.

**Trap 2 -- one attempt produces two lines.** sshd logs
``Invalid user admin from 1.2.3.4`` and then
``Failed password for invalid user admin from 1.2.3.4``. Counting both halves
the effective threshold: five "attempts" would fire after two and a half real
ones. So the precursor line is parsed and stored as evidence but excluded from
:data:`COUNTING_KINDS`, which is what the detector actually counts.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from ..timeparse import TimestampError, parse_timestamp

# Kinds representing a *completed* failed authentication. Precursor notices are
# stored for forensics but must never reach the threshold arithmetic.
COUNTING_KINDS = frozenset(
    {"failed_password", "failed_publickey", "max_auth_attempts", "preauth_close"}
)

_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,45})"

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Failed password for [invalid user ]bob from 1.2.3.4 port 22 ssh2
    (
        "failed_password",
        re.compile(
            r"Failed password for (?:invalid user )?(?P<user>\S+) from " + _IP + r" port \d+"
        ),
    ),
    # Failed publickey for root from 1.2.3.4 port 22 ssh2: RSA SHA256:...
    (
        "failed_publickey",
        re.compile(
            r"Failed publickey for (?:invalid user )?(?P<user>\S+) from " + _IP + r" port \d+"
        ),
    ),
    # error: maximum authentication attempts exceeded for root from 1.2.3.4
    (
        "max_auth_attempts",
        re.compile(
            r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) "
            r"from " + _IP
        ),
    ),
    # Connection closed by (invalid|authenticating) user root 1.2.3.4 port 5 [preauth]
    (
        "preauth_close",
        re.compile(
            r"Connection (?:closed|reset) by (?:invalid|authenticating) user "
            r"(?P<user>\S+) " + _IP
        ),
    ),
    # Invalid user admin from 1.2.3.4 port 5   <- precursor, not counted
    (
        "invalid_user",
        re.compile(r"Invalid user (?P<user>\S+) from " + _IP),
    ),
)

# Only inspect lines emitted by the SSH daemon.
_SSHD_RE = re.compile(r"\bsshd(?:-session)?(?:\[\d+\])?:")


def parse_line(line: str, *, now: datetime | None = None) -> dict[str, Any] | None:
    """Parse one auth.log line into an SSH event, or ``None`` if irrelevant."""
    if not _SSHD_RE.search(line):
        return None

    try:
        timestamp, _ = parse_timestamp(line, now=now)
    except TimestampError:
        return None

    for kind, pattern in _PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        username = match.group("user")
        # sshd renders an unparsable username as "*" or an empty token.
        if username in {"*", "-", ""}:
            username = None
        return {
            "ts": timestamp,
            "ip": match.group("ip"),
            "username": username,
            "kind": kind,
        }
    return None
