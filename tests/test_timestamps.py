"""Tests for timestamp parsing, UTC normalization, naive rejection, and audit cutoff."""

from datetime import datetime, timezone, timedelta
import pytest

from ghost_audit.timestamps import (
    SemanticTimestamp,
    TimestampRole,
    format_iso_timestamp,
    is_within_audit_cutoff,
    parse_iso_timestamp,
)


def test_parse_iso_timestamp_utc_z():
    ts = "2026-08-18T09:14:00Z"
    dt = parse_iso_timestamp(ts)
    assert dt.tzinfo == timezone.utc
    assert dt.year == 2026
    assert dt.month == 8
    assert dt.day == 18
    assert dt.hour == 9
    assert dt.minute == 14
    assert dt.second == 0


def test_parse_iso_timestamp_with_offset():
    # +05:30 offset
    ts = "2026-08-18T14:44:00+05:30"
    dt = parse_iso_timestamp(ts)
    # Must be normalized to UTC: 14:44 - 5:30 = 09:14 UTC
    assert dt.tzinfo == timezone.utc
    assert dt.hour == 9
    assert dt.minute == 14

    # -04:00 offset
    ts2 = "2026-08-18T05:14:00-04:00"
    dt2 = parse_iso_timestamp(ts2)
    # 05:14 - (-4:00) = 09:14 UTC
    assert dt2.tzinfo == timezone.utc
    assert dt2.hour == 9
    assert dt2.minute == 14
    assert dt == dt2


def test_reject_timezone_naive_timestamp():
    naive_ts = "2026-08-18T09:14:00"
    with pytest.raises(ValueError, match="timezone-naive"):
        parse_iso_timestamp(naive_ts)

    naive_dt = datetime(2026, 8, 18, 9, 14, 0)
    with pytest.raises(ValueError, match="timezone-naive"):
        parse_iso_timestamp(naive_dt)


def test_reject_empty_or_malformed_timestamp():
    with pytest.raises(ValueError, match="Empty timestamp"):
        parse_iso_timestamp("   ")

    with pytest.raises(ValueError, match="Invalid ISO-8601"):
        parse_iso_timestamp("invalid-date-format")


def test_format_iso_timestamp():
    dt = datetime(2026, 8, 18, 9, 14, 0, tzinfo=timezone.utc)
    formatted = format_iso_timestamp(dt)
    assert formatted == "2026-08-18T09:14:00Z"

    # With non-UTC offset, should format as UTC with Z
    tz_ist = timezone(timedelta(hours=5, minutes=30))
    dt_ist = datetime(2026, 8, 18, 14, 44, 0, tzinfo=tz_ist)
    assert format_iso_timestamp(dt_ist) == "2026-08-18T09:14:00Z"

    # Naive rejection
    with pytest.raises(ValueError, match="timezone-naive"):
        format_iso_timestamp(datetime(2026, 8, 18, 9, 14, 0))


def test_inclusive_audit_cutoff_comparison():
    audit_at = parse_iso_timestamp("2026-09-01T12:00:00Z")

    # Before cutoff
    event_before = parse_iso_timestamp("2026-09-01T11:59:59Z")
    assert is_within_audit_cutoff(event_before, audit_at) is True

    # Exactly at cutoff (inclusive contract)
    event_exact = parse_iso_timestamp("2026-09-01T12:00:00Z")
    assert is_within_audit_cutoff(event_exact, audit_at) is True

    # Same time with different timezone offset (+02:00)
    event_offset = parse_iso_timestamp("2026-09-01T14:00:00+02:00")
    assert is_within_audit_cutoff(event_offset, audit_at) is True

    # After cutoff
    event_after = parse_iso_timestamp("2026-09-01T12:00:01Z")
    assert is_within_audit_cutoff(event_after, audit_at) is False


def test_semantic_timestamp_wrapper():
    dt = parse_iso_timestamp("2026-08-18T09:14:00Z")
    sem = SemanticTimestamp(
        value=dt,
        role=TimestampRole.REQUEST_TIME,
        description="Initial deletion request received",
    )
    assert sem.role == TimestampRole.REQUEST_TIME
    assert sem.value == dt

    # Reject naive in SemanticTimestamp
    naive_dt = datetime(2026, 8, 18, 9, 14, 0)
    with pytest.raises(ValueError, match="must be timezone-aware"):
        SemanticTimestamp(value=naive_dt, role=TimestampRole.AUDIT_CUTOFF)
