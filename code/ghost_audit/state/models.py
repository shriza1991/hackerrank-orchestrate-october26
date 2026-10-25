"""Typed models for resource-state reconstruction at audit cutoff."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ghost_audit.timestamps import parse_iso_timestamp


class ExistenceState(str, Enum):
    """Observed existence state of a resource copy at audit_at."""

    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    UNKNOWN = "UNKNOWN"
    CONFLICTED = "CONFLICTED"


class SubjectAttribution(str, Enum):
    """Whether an observed record is attributed to the audit subject."""

    SUPPORTED = "SUPPORTED"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"
    UNKNOWN = "UNKNOWN"


class ProcessState(str, Enum):
    """Observed operational state of a background sync/stream/connector process."""

    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RestoreState(str, Enum):
    """Observed backup restore permission or accessibility."""

    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class FieldStatus(str, Enum):
    """Field-level observation status for identifying content."""

    EXPOSED = "EXPOSED"
    NULL = "NULL"
    EMPTY = "EMPTY"
    MASKED = "MASKED"
    UNREADABLE = "UNREADABLE"
    MISSING = "MISSING"
    RETAINED_STABLE_REF = "RETAINED_STABLE_REF"


class CopyType(str, Enum):
    """Distinct storage topology or copy classification."""

    PRIMARY = "PRIMARY"
    READ_REPLICA = "READ_REPLICA"
    REGIONAL_REPLICA = "REGIONAL_REPLICA"
    FAILOVER_REPLICA = "FAILOVER_REPLICA"
    REPORTING_REPLICA = "REPORTING_REPLICA"
    SEARCH_INDEX = "SEARCH_INDEX"
    EXPORT_ARCHIVE = "EXPORT_ARCHIVE"
    SUPPORT_ATTACHMENT = "SUPPORT_ATTACHMENT"
    DATABASE_BACKUP = "DATABASE_BACKUP"
    SYSTEM_PROCESS = "SYSTEM_PROCESS"
    UNKNOWN = "UNKNOWN"


class CopyKey(BaseModel):
    """Source-qualified key distinguishing store copies and replicas."""

    model_config = ConfigDict(frozen=True)

    system_id: str
    resource_id: str
    copy_type: CopyType = CopyType.PRIMARY
    store_locator: Optional[str] = None

    def __str__(self) -> str:
        loc = f"@{self.store_locator}" if self.store_locator else ""
        return f"{self.system_id}:{self.resource_id}[{self.copy_type.value}{loc}]"


class FieldObservation(BaseModel):
    """Observation of an individual identifier or content field."""

    model_config = ConfigDict(frozen=True)

    field_name: str
    status: FieldStatus
    raw_value: Optional[str] = None
    is_direct_pii: bool = False
    is_stable_ref: bool = False
    claim_label: Optional[str] = None  # e.g., if UI labeled field as "redacted" but raw exposes value


class StateTimelineEvent(BaseModel):
    """Chronological event affecting a copy or resource state."""

    model_config = ConfigDict(frozen=True)

    event_id: str
    event_time: datetime
    event_type: str
    source_id: str
    source_type: str  # EVIDENCE_FILE or SYSTEM_ACTIVITY
    source_locator: Optional[str] = None
    is_claim: bool = False
    observed_existence: Optional[ExistenceState] = None
    claim_result: Optional[str] = None
    time_role_basis: str  # Grounded justification for the chosen timestamp
    facts: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_time", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> datetime:
        return parse_iso_timestamp(v)


class CopyStateAssessment(BaseModel):
    """Reconstructed state of one specific resource copy at audit_at."""

    copy_key: CopyKey
    existence: ExistenceState = ExistenceState.UNKNOWN
    attribution: SubjectAttribution = SubjectAttribution.UNKNOWN
    fields: dict[str, FieldObservation] = Field(default_factory=dict)
    process_state: ProcessState = ProcessState.NOT_APPLICABLE
    restore_state: RestoreState = RestoreState.NOT_APPLICABLE
    last_observation_time: Optional[datetime] = None
    last_activity_time: Optional[datetime] = None
    is_recreated: bool = False
    recreation_details: Optional[str] = None
    supporting_observations: list[str] = Field(default_factory=list)
    supporting_activities: list[str] = Field(default_factory=list)
    unverified_claims: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    timeline: list[StateTimelineEvent] = Field(default_factory=list)

    @field_validator("last_observation_time", "last_activity_time", mode="before")
    @classmethod
    def normalize_timestamps(cls, v: Any) -> Optional[datetime]:
        return None if v is None else parse_iso_timestamp(v)


class ResourceStateAggregate(BaseModel):
    """Resource-level aggregate preserving all copies and surviving records."""

    model_config = ConfigDict(frozen=True)

    system_id: str
    resource_id: str
    canonical_key: str  # f"{system_id}:{resource_id}"
    data_category: Optional[str] = None
    aggregate_existence: ExistenceState = ExistenceState.UNKNOWN
    copies: dict[str, CopyStateAssessment] = Field(default_factory=dict)
    surviving_copies: list[str] = Field(default_factory=list)
    absent_copies: list[str] = Field(default_factory=list)
    observed_pii_exposed: bool = False
    has_recreation_risk: bool = False
    has_restore_risk: bool = False
    conflicts: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ScopedAbsenceCheck(BaseModel):
    """Grounded proof of absence established via scoped negative lookup or complete inventory."""

    model_config = ConfigDict(frozen=True)

    system_id: str
    resource_id: Optional[str] = None
    source_id: str
    source_locator: Optional[str] = None
    timestamp: datetime
    table_scope: str
    checked_identifiers: list[str] = Field(default_factory=list)
    membership_result: str  # ABSENT, PRESENT, UNKNOWN
    completeness_basis: str

    @field_validator("timestamp", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> datetime:
        return parse_iso_timestamp(v)


class StateDiagnostics(BaseModel):
    """Operational diagnostics and conflict records for state reconstruction."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    audit_at: datetime
    coverage_scope: str = "KNOWN_COMPLETE"
    total_resources_evaluated: int = 0
    total_copies_evaluated: int = 0
    conflicts_detected: list[str] = Field(default_factory=list)
    unverified_claims_count: int = 0
    recreations_detected: list[str] = Field(default_factory=list)
    stale_or_incomplete_warnings: list[str] = Field(default_factory=list)
    unreadable_or_failed_files: list[str] = Field(default_factory=list)
    deferred_files: list[str] = Field(default_factory=list)
    execution_time_ms: float = 0.0

    @field_validator("audit_at", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> datetime:
        return parse_iso_timestamp(v)


class CaseStateReconstruction(BaseModel):
    """Complete case-level resource-state reconstruction at audit cutoff."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    audit_at: datetime
    is_blocked: bool = False
    blocking_reason: Optional[str] = None
    is_diagnostic_mode: bool = False
    subject_id: Optional[str] = None
    resources: dict[str, ResourceStateAggregate] = Field(default_factory=dict)
    active_processes: list[str] = Field(default_factory=list)
    restore_risks: list[str] = Field(default_factory=list)
    scoped_absence_checks: list[ScopedAbsenceCheck] = Field(default_factory=list)
    diagnostics: StateDiagnostics

    @field_validator("audit_at", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> datetime:
        return parse_iso_timestamp(v)
