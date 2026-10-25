"""Strict typed models and contracts for evidence linking and retrieval."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ghost_audit.models.intermediate_models import (
    EvidenceObservation,
    IdentityResolutionStatus,
)
from ghost_audit.timestamps import parse_iso_timestamp


class ResourceKey(BaseModel):
    """Grounded resource key preserving system and resource context."""

    model_config = ConfigDict(frozen=True)

    system_id: str
    resource_id: str
    source_locator: Optional[str] = None

    def __str__(self) -> str:
        if self.source_locator:
            return f"{self.system_id}:{self.resource_id}@{self.source_locator}"
        return f"{self.system_id}:{self.resource_id}"

    @classmethod
    def from_string(cls, s: str) -> ResourceKey:
        loc = None
        if "@" in s:
            s, loc = s.split("@", 1)
        if ":" in s:
            sys_id, res_id = s.split(":", 1)
            return cls(system_id=sys_id, resource_id=res_id, source_locator=loc)
        return cls(system_id="unknown", resource_id=s, source_locator=loc)


class LinkRelationship(str, Enum):
    """Categorization of supported evidence and identity links."""

    DIRECT_SUBJECT_IDENTIFIER = "DIRECT_SUBJECT_IDENTIFIER"
    CATALOG_RESOURCE_IDENTITY = "CATALOG_RESOURCE_IDENTITY"
    CATALOG_EXTERNAL_ALIAS = "CATALOG_EXTERNAL_ALIAS"
    OBSERVATION_RESOURCE_CHAIN = "OBSERVATION_RESOURCE_CHAIN"
    ACTIVITY_RESOURCE_MATCH = "ACTIVITY_RESOURCE_MATCH"
    TRACE_CORRELATION = "TRACE_CORRELATION"
    SCOPED_INVENTORY = "SCOPED_INVENTORY"


class LinkProvenance(BaseModel):
    """Detailed audit provenance for an evidence link."""

    model_config = ConfigDict(frozen=True)

    source_type: str  # "EVIDENCE_OBSERVATION", "SYSTEM_ACTIVITY", "USER_AUDIT", "DATA_CATALOG"
    source_id: str  # file_id, activity_id, or audit_id
    source_locator: Optional[str] = None
    timestamp: datetime
    relationship: LinkRelationship
    is_direct: bool = True
    uncertainty_or_warnings: list[str] = Field(default_factory=list)

    @field_validator("timestamp", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> datetime:
        return parse_iso_timestamp(v)


class LinkEndpoint(BaseModel):
    """Endpoint of a link: subject, identifier, resource, or activity."""

    model_config = ConfigDict(frozen=True)

    endpoint_type: str  # "SUBJECT", "IDENTIFIER", "RESOURCE", "ACTIVITY", "ALIAS"
    endpoint_id: str

    def __str__(self) -> str:
        return f"{self.endpoint_type}:{self.endpoint_id}"


class EvidenceLink(BaseModel):
    """An established directed link connecting entities in the evidence graph."""

    model_config = ConfigDict(frozen=True)

    link_id: str
    from_endpoint: LinkEndpoint
    to_endpoint: LinkEndpoint
    provenance: LinkProvenance
    explanation: str


class SelectedObservation(BaseModel):
    """Observation selected for case evidence packet with linking justification."""

    model_config = ConfigDict(frozen=True)

    observation: EvidenceObservation
    matched_identifiers: list[str] = Field(default_factory=list)
    grounded_resources: list[str] = Field(default_factory=list)
    primary_relationship: LinkRelationship
    supporting_links: list[EvidenceLink] = Field(default_factory=list)


class SelectedActivity(BaseModel):
    """System activity event concerning a grounded resource."""

    model_config = ConfigDict(frozen=True)

    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str
    grounded_resource_key: str
    supporting_link: EvidenceLink

    @field_validator("event_time", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> datetime:
        return parse_iso_timestamp(v)


class ScopedInventory(BaseModel):
    """Scoped inventory observation retaining table or store context for absence checking."""

    model_config = ConfigDict(frozen=True)

    system_id: str
    resource_id: Optional[str] = None
    source_id: str
    source_locator: Optional[str] = None
    timestamp: datetime
    scope_context: dict[str, Any] = Field(default_factory=dict)
    extracted_facts: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> datetime:
        return parse_iso_timestamp(v)


class AmbiguousOrRejectedLink(BaseModel):
    """Candidate link rejected or flagged as ambiguous to avoid false joins."""

    model_config = ConfigDict(frozen=True)

    candidate_endpoint: str
    source_id: str
    reason: str
    details: dict[str, Any] = Field(default_factory=dict)


class RetrievalDiagnostics(BaseModel):
    """Operational diagnostics and coverage metrics for retrieval."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    audit_at: datetime
    total_eligible_observations_scanned: int = 0
    total_future_observations_excluded: int = 0
    total_eligible_activities_scanned: int = 0
    total_future_activities_excluded: int = 0
    max_expansion_depth_reached: int = 0
    cycles_detected: list[str] = Field(default_factory=list)
    coverage_warnings: list[str] = Field(default_factory=list)
    coverage_scope: str = "KNOWN_COMPLETE"  # KNOWN_COMPLETE, KNOWN_INCOMPLETE, UNKNOWN
    failed_files: list[str] = Field(default_factory=list)
    deferred_files: list[str] = Field(default_factory=list)
    manifest_errors: list[str] = Field(default_factory=list)
    execution_time_ms: float = 0.0

    @field_validator("audit_at", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> datetime:
        return parse_iso_timestamp(v)


class CaseEvidencePacket(BaseModel):
    """Complete, provenance-rich evidence packet for a single deletion audit case."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    email: str
    requested_at: datetime
    reported_status: str
    reported_at: datetime
    audit_at: datetime

    intent_decision: Optional[str] = None
    identity_status: IdentityResolutionStatus
    stable_subject_reference: Optional[str] = None

    subject_identifiers: list[str] = Field(default_factory=list)
    grounded_resources: list[str] = Field(default_factory=list)

    selected_observations: list[SelectedObservation] = Field(default_factory=list)
    selected_activities: list[SelectedActivity] = Field(default_factory=list)
    scoped_inventories: list[ScopedInventory] = Field(default_factory=list)

    linking_graph: list[EvidenceLink] = Field(default_factory=list)
    ambiguous_or_rejected_links: list[AmbiguousOrRejectedLink] = Field(default_factory=list)

    diagnostics: RetrievalDiagnostics
    is_blocked: bool = False
    blocking_reason: Optional[str] = None

    @field_validator("requested_at", "reported_at", "audit_at", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> datetime:
        return parse_iso_timestamp(v)
