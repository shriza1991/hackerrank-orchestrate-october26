"""Typed data contracts and provenance models for identity resolution."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ghost_audit.timestamps import parse_iso_timestamp


class SourceType(str, Enum):
    """Source origin of an identity fact."""

    SNAPSHOT = "SNAPSHOT"
    AUDIT_LOG = "AUDIT_LOG"


class IdentifierProvenance(BaseModel):
    """Explicit provenance tracking for an observed identifier fact."""

    model_config = ConfigDict(frozen=True)

    source_type: SourceType
    source_file: str  # "user_identities.csv" or "user_audit_log.csv"
    source_id: Optional[str] = None  # audit_id when from audit log
    source_locator: str  # e.g., "user_id:user_01" or "audit_id:audit_01"
    field_name: str
    raw_value: str
    normalized_value: str
    timestamp: datetime
    change_type: str  # "CURRENT_SNAPSHOT", "OLD_VALUE", "NEW_VALUE"
    validity_start: Optional[datetime] = None
    validity_end: Optional[datetime] = None

    @field_validator("timestamp", "validity_start", "validity_end", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> Optional[datetime]:
        if v is None:
            return None
        return parse_iso_timestamp(v)


class IdentifierInterval(BaseModel):
    """Reconstructed validity interval and provenance for a single identifier value."""

    model_config = ConfigDict(frozen=True)

    field_name: str
    raw_value: str
    normalized_value: str
    is_current_at_cutoff: bool
    validity_start: Optional[datetime] = None
    validity_end: Optional[datetime] = None
    sources: list[IdentifierProvenance] = Field(default_factory=list)

    @field_validator("validity_start", "validity_end", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> Optional[datetime]:
        if v is None:
            return None
        return parse_iso_timestamp(v)


class UserHistoryTimeline(BaseModel):
    """Reconstructed subject history up to an inclusive audit cutoff."""

    model_config = ConfigDict(frozen=True)

    user_id: str
    current_identifiers: dict[str, str] = Field(default_factory=dict)
    normalized_current_identifiers: dict[str, str] = Field(default_factory=dict)
    historical_identifiers: list[dict[str, Any]] = Field(default_factory=list)
    searchable_identifiers: list[str] = Field(default_factory=list)
    supporting_audit_ids: list[str] = Field(default_factory=list)
    provenance: list[dict[str, Any]] = Field(default_factory=list)
    applicable_timestamps: dict[str, datetime] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
