"""UFW firewall log parser.

UFW emits kernel netfilter lines of the form::

    [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=193.34.76.15 DST=10.0.0.4 LEN=44
    ... PROTO=TCP SPT=53122 DPT=3306 WINDOW=1024 RES=0x00 SYN URGP=0

Only ``BLOCK`` verdicts are ingested (including the ``[UFW LIMIT BLOCK]``
variant). ``ALLOW`` and ``AUDIT`` lines are ordinary traffic, not probes.

An important limitation to state plainly: UFW only logs what it *blocked*, so
this detects scans against closed ports. A scan touching only open services
(22, 80, 443) leaves no trace here. That is a property of the data source, not
a defect in the rule.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from ..timeparse import TimestampError, parse_timestamp

_BLOCK_RE = re.compile(r"\[UFW\s+(?:[A-Z]+\s+)?BLOCK\]")
_FIELD_RE = re.compile(r"\b(?P<key>SRC|DST|PROTO|SPT|DPT)=(?P<value>\S+)")


def parse_line(line: str, *, now: datetime | None = None) -> dict[str, Any] | None:
    """Parse one ufw.log line into a scan event, or ``None`` if irrelevant."""
    if not _BLOCK_RE.search(line):
        return None

    try:
        timestamp, _ = parse_timestamp(line, now=now)
    except TimestampError:
        return None

    fields = {m.group("key"): m.group("value") for m in _FIELD_RE.finditer(line)}
    source = fields.get("SRC")
    port_raw = fields.get("DPT")
    if not source or not port_raw:
        # ICMP and similar carry no destination port; nothing to count.
        return None

    try:
        port = int(port_raw)
    except ValueError:
        return None
    if not 0 <= port <= 65535:
        return None

    return {
        "ts": timestamp,
        "ip": source,
        "dst_port": port,
        "proto": fields.get("PROTO"),
    }
