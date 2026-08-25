"""Timestamp parsing, including the year-inference trap."""
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.timeparse import TimestampError, parse_timestamp


def test_bsd_syslog_uses_reference_year():
    now = datetime(2026, 8, 25, 14, 0, 0, tzinfo=timezone.utc)
    ts, rest = parse_timestamp("Aug 25 14:03:22 vps sshd[1]: hello", now=now)
    assert ts.year == 2026
    assert ts.month == 8 and ts.day == 25
    assert rest.startswith("vps sshd[1]:")


def test_bsd_syslog_single_digit_day():
    now = datetime(2026, 8, 25, 14, 0, 0, tzinfo=timezone.utc)
    ts, _ = parse_timestamp("Aug  5 09:01:02 vps sshd[1]: hi", now=now)
    assert ts.day == 5 and ts.hour is not None


def test_december_log_read_in_january_rolls_back_a_year():
    """The classic bug: a Dec 31 line parsed on Jan 1 must not land in the future."""
    now = datetime(2027, 1, 1, 0, 30, 0, tzinfo=timezone.utc)
    ts, _ = parse_timestamp("Dec 31 23:58:01 vps sshd[1]: late", now=now)
    assert ts.year == 2026
    assert ts < now


def test_iso_format_with_offset_is_converted_to_utc():
    ts, rest = parse_timestamp("2026-08-25T14:03:22.123456+02:00 vps sshd[1]: x")
    assert ts.tzinfo == timezone.utc
    assert ts.hour == 12  # 14:03 +02:00 -> 12:03 UTC
    assert rest.startswith("vps")


def test_iso_zulu_format():
    ts, _ = parse_timestamp("2026-08-25T14:03:22Z vps sshd[1]: x")
    assert ts.hour == 14 and ts.tzinfo == timezone.utc


def test_unparseable_line_raises():
    with pytest.raises(TimestampError):
        parse_timestamp("this line has no timestamp at all")


def test_returned_timestamps_are_always_aware():
    now = datetime(2026, 8, 25, 14, 0, 0, tzinfo=timezone.utc)
    ts, _ = parse_timestamp("Aug 25 14:03:22 vps sshd[1]: x", now=now)
    assert ts.tzinfo is not None
    assert abs(ts - now) < timedelta(days=2)
