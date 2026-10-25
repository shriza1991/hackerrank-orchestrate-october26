"""Intermediate models for subsequent pipeline stages."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


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


class EvidenceObservation(BaseModel):
    """Observation extracted from evidence files or logs."""

    model_config = ConfigDict(frozen=True)

    evidence_id: str
    source_locator: Optional[str] = None  # e.g., page, table, JSON path, line
    capture_time: datetime
    observation_time: Optional[datetime] = None
    system_id: Optional[str] = None
    resource_id: Optional[str] = None
    extracted_facts: dict[str, Any] = Field(default_factory=dict)
    extraction_method: str = "UNSPECIFIED"
    uncertainty_or_warnings: list[str] = Field(default_factory=list)


class ResourceAssessment(BaseModel):
    """Assessment of resource state against deletion policy."""

    model_config = ConfigDict(frozen=True)

    system_id: str
    resource_id: str
    data_category: Optional[str] = None
    observed_state: Optional[str] = None
    supporting_observations: list[str] = Field(default_factory=list)
    applicable_policy_rule_id: Optional[str] = None
    unresolved_questions: list[str] = Field(default_factory=list)
