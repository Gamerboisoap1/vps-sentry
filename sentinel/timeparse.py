"""Syslog timestamp parsing.

Two formats show up in the wild and both have to work:

* **Traditional BSD syslog** -- ``Aug 25 14:03:22``. Carries no year, so the
  year has to be inferred. Naively stamping "current year" corrupts every
  December log read in January, so a timestamp landing in the future is rolled
  back twelve months.
* **RFC3339 / RFC5424** -- ``2026-08-25T14:03:22.123456+00:00``, emitted by
  journald and by rsyslog on newer distributions.

Traditional syslog records the *server's local time* with no offset, so naive
values are interpreted in the host timezone before conversion to UTC. The
monitor runs on the box that wrote the log, which is what makes that correct.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

# "Aug 25 14:03:22" and the zero-padded "Aug  5 14:03:22" variant.
_BSD_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})"
)

# "2026-08-25T14:03:22.123456+00:00" / "...Z"
_ISO_RE = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Tolerance before a stamp is treated as "must belong to last year". Clock skew
# between the writer and this process is normally milliseconds; a day is a
# generous margin that still catches the new-year rollover.
_FUTURE_TOLERANCE = timedelta(days=1)


class TimestampError(ValueError):
    """Raised when a line carries no timestamp we recognise."""


def parse_timestamp(line: str, *, now: datetime | None = None) -> tuple[datetime, str]:
    """Parse a leading syslog timestamp.

    Returns ``(aware_utc_datetime, remainder_of_line)``.
    """
    reference = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    iso_match = _ISO_RE.match(line)
    if iso_match:
        stamp = iso_match.group("stamp").replace("Z", "+00:00").replace(" ", "T")
        parsed = datetime.fromisoformat(stamp)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        return parsed.astimezone(timezone.utc), line[iso_match.end():].lstrip()

    bsd_match = _BSD_RE.match(line)
    if bsd_match:
        local_reference = reference.astimezone()
        candidate = datetime(
            year=local_reference.year,
            month=_MONTHS[bsd_match.group("mon")],
            day=int(bsd_match.group("day")),
            hour=int(bsd_match.group("hh")),
            minute=int(bsd_match.group("mm")),
            second=int(bsd_match.group("ss")),
        ).astimezone()  # naive -> host local timezone

        # Feb 29 in a non-leap reference year would have raised above; a stamp
        # comfortably in the future belongs to the previous year.
        if candidate - reference > _FUTURE_TOLERANCE:
            candidate = candidate.replace(year=candidate.year - 1)

        return candidate.astimezone(timezone.utc), line[bsd_match.end():].lstrip()

    raise TimestampError(f"unrecognised timestamp: {line[:40]!r}")
