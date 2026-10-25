"""Timestamp utilities and contracts for ghost_audit."""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class TimestampRole(str, Enum):
    """Semantic distinction for timestamp roles in the audit workflow."""

    REQUEST_TIME = "REQUEST_TIME"
    WORKFLOW_REPORTING_TIME = "WORKFLOW_REPORTING_TIME"
    AUDIT_CUTOFF = "AUDIT_CUTOFF"
    IDENTITY_CHANGE_TIME = "IDENTITY_CHANGE_TIME"
    EVIDENCE_CAPTURE_TIME = "EVIDENCE_CAPTURE_TIME"
    FUTURE_RETENTION_EXPIRY = "FUTURE_RETENTION_EXPIRY"


@dataclass(frozen=True)
class SemanticTimestamp:
    """Wrapper that preserves the distinction between different timestamp roles."""

    value: datetime
    role: TimestampRole
    description: Optional[str] = None

    def __post_init__(self) -> None:
        if self.value.tzinfo is None or self.value.tzinfo.utcoffset(self.value) is None:
            raise ValueError(f"Timestamp for role {self.role.value} must be timezone-aware.")


def parse_iso_timestamp(ts_input: str | datetime) -> datetime:
    """Parse an ISO-8601 timestamp string into a UTC-normalized timezone-aware datetime.

    Rejects timezone-naive timestamps with ValueError.
    Supports 'Z' and explicit timezone offsets (e.g., +02:00, -05:00).
    """
    if isinstance(ts_input, datetime):
        dt = ts_input
    elif isinstance(ts_input, str):
        cleaned = ts_input.strip()
        if not cleaned:
            raise ValueError("Empty timestamp string.")
        try:
            dt = datetime.fromisoformat(cleaned)
        except Exception as exc:
            raise ValueError(f"Invalid ISO-8601 timestamp '{ts_input}': {exc}") from exc
    else:
        raise TypeError(f"Expected str or datetime, got {type(ts_input).__name__}")

    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(f"Timestamp '{ts_input}' is timezone-naive; timezone-aware ISO-8601 required.")

    # Normalize to UTC
    return dt.astimezone(timezone.utc)


def format_iso_timestamp(dt: datetime) -> str:
    """Format a timezone-aware datetime consistently as an ISO-8601 UTC string with 'Z'."""
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError("Cannot format timezone-naive datetime.")
    dt_utc = dt.astimezone(timezone.utc)
    # Keep fractional seconds when supplied; dropping them can move an event
    # from after a cutoff onto the cutoff when the value is round-tripped.
    return dt_utc.isoformat(timespec="auto").replace("+00:00", "Z")


def is_within_audit_cutoff(event_time: datetime, audit_at: datetime) -> bool:
    """Check if an event time is within the audit cutoff.

    Normalizes both times to UTC.
    The cutoff is inclusive: an event exactly at audit_at is within the cutoff.
    """
    event_utc = parse_iso_timestamp(event_time)
    audit_utc = parse_iso_timestamp(audit_at)
    return event_utc <= audit_utc
