"""Intermediate models for subsequent pipeline stages."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ghost_audit.models.common import NonBlankStr
from ghost_audit.timestamps import parse_iso_timestamp


class IdentityResolutionStatus(str, Enum):
    """Status of identity resolution for a subject."""

    RESOLVED = "RESOLVED"
    AMBIGUOUS = "AMBIGUOUS"
    UNRESOLVED = "UNRESOLVED"


class IdentityResolutionResult(BaseModel):
    """Result of identity and identifier resolution."""

    model_config = ConfigDict(frozen=True)

    resolution_status: IdentityResolutionStatus = IdentityResolutionStatus.UNRESOLVED
    stable_subject_reference: Optional[str] = None  # user_id when resolved
    current_identifiers: dict[str, Any] = Field(default_factory=dict)
    historical_identifiers: list[dict[str, Any]] = Field(default_factory=list)
    supporting_references: list[str] = Field(default_factory=list)  # audit_ids, activity_ids, etc.
    applicable_timestamps: dict[str, datetime] = Field(default_factory=dict)
    notes: Optional[str] = None
    request_email: Optional[str] = None
    normalized_request_email: Optional[str] = None
    match_method: Optional[str] = None
    candidates: list[str] = Field(default_factory=list)
    searchable_identifiers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    provenance: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("applicable_timestamps", mode="before")
    @classmethod
    def normalize_timestamps(cls, value):
        if isinstance(value, dict):
            return {key: parse_iso_timestamp(item) for key, item in value.items()}
        return value  # Let Pydantic describe an invalid mapping shape.

    @model_validator(mode="after")
    def require_resolved_subject(self):
        if self.resolution_status == IdentityResolutionStatus.RESOLVED:
            if not self.stable_subject_reference or not self.stable_subject_reference.strip():
                raise ValueError("A RESOLVED identity requires a stable subject reference.")
        return self


class EvidenceObservation(BaseModel):
    """Observation extracted from evidence files or logs."""

    model_config = ConfigDict(frozen=True)

    evidence_id: NonBlankStr
    source_locator: Optional[str] = None  # e.g., page, table, JSON path, line
    capture_time: datetime
    observation_time: Optional[datetime] = None
    system_id: Optional[str] = None
    resource_id: Optional[str] = None
    extracted_facts: dict[str, Any] = Field(default_factory=dict)
    extraction_method: NonBlankStr = "UNSPECIFIED"
    uncertainty_or_warnings: list[str] = Field(default_factory=list)

    @field_validator("capture_time", "observation_time", mode="before")
    @classmethod
    def normalize_timestamp(cls, value):
        return None if value is None else parse_iso_timestamp(value)


class ResourceAssessment(BaseModel):
    """Assessment of resource state against deletion policy."""

    model_config = ConfigDict(frozen=True)

    system_id: NonBlankStr
    resource_id: NonBlankStr
    data_category: Optional[str] = None
    observed_state: Optional[str] = None
    supporting_observations: list[str] = Field(default_factory=list)
    applicable_policy_rule_id: Optional[str] = None
    unresolved_questions: list[str] = Field(default_factory=list)
