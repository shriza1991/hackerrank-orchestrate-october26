"""Domain models for evidence-grounded policy decision engine."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ghost_audit.models.input_models import DataCategory, RequiredAction
from ghost_audit.state.models import ExistenceState, CopyKey
from ghost_audit.timestamps import parse_iso_timestamp


class PolicyComplianceOutcome(str, Enum):
    """Internal compliance outcome for policy evaluation."""

    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"
    UNDETERMINED = "UNDETERMINED"


class ConditionEvaluation(str, Enum):
    """Evaluation result for a rule's conditional premise."""

    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


class CopyPolicyAssessment(BaseModel):
    """Policy assessment for a single physical copy/store of a resource."""

    model_config = ConfigDict(frozen=True)

    copy_key: str
    system_id: str
    resource_id: str
    copy_type: str
    store_locator: Optional[str] = None
    data_category: Optional[DataCategory] = None
    category_basis: str = ""
    rule_id: Optional[str] = None
    required_action: Optional[RequiredAction] = None
    condition_evaluation: ConditionEvaluation = ConditionEvaluation.UNKNOWN
    condition_details: str = ""
    observed_existence: ExistenceState = ExistenceState.UNKNOWN
    observed_pii_exposed: bool = False
    pii_details: list[str] = Field(default_factory=list)
    target_properties: dict[str, Any] = Field(default_factory=dict)
    outcome: PolicyComplianceOutcome = PolicyComplianceOutcome.UNDETERMINED
    evidence_references: list[str] = Field(default_factory=list)
    timestamps: dict[str, Any] = Field(default_factory=dict)
    missing_facts: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    coverage_limitations: list[str] = Field(default_factory=list)
    retention_obligation: Optional[str] = None
    recreation_risk: Optional[str] = None
    restore_risk: Optional[str] = None
    notes: list[str] = Field(default_factory=list)


class ResourcePolicyAssessment(BaseModel):
    """Policy assessment aggregated across all copies of a resource."""

    model_config = ConfigDict(frozen=True)

    system_id: str
    resource_id: str
    canonical_key: str
    data_category: Optional[DataCategory] = None
    category_basis: str = ""
    rule_id: Optional[str] = None
    required_action: Optional[RequiredAction] = None
    condition_evaluation: ConditionEvaluation = ConditionEvaluation.UNKNOWN
    condition_details: str = ""
    copies: dict[str, CopyPolicyAssessment] = Field(default_factory=dict)
    outcome: PolicyComplianceOutcome = PolicyComplianceOutcome.UNDETERMINED
    recreation_risk: Optional[str] = None
    restore_risk: Optional[str] = None
    missing_facts: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    coverage_limitations: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ProcessRiskAssessment(BaseModel):
    """Grounded assessment of a data flow, synchronization, or background process."""

    model_config = ConfigDict(frozen=True)

    process_id: str
    system_id: str
    target_resource: Optional[str] = None
    target_copy: Optional[str] = None
    risk_type: str = "ACTIVE_DATA_FLOW"
    is_active: bool = False
    details: str = ""
    supporting_evidence: list[str] = Field(default_factory=list)


class RestoreRiskAssessment(BaseModel):
    """Grounded assessment of a backup archive or restore permission path."""

    model_config = ConfigDict(frozen=True)

    backup_id: str
    system_id: str
    target_resource: Optional[str] = None
    target_copy: Optional[str] = None
    risk_type: str = "RESTORE_ALLOWED"
    is_blocked: bool = False
    details: str = ""
    supporting_evidence: list[str] = Field(default_factory=list)


class CasePolicyAssessment(BaseModel):
    """Full policy assessment for a case at audit_at."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    audit_at: datetime
    is_authorized_deletion: bool = False
    intent_status: str = "UNKNOWN"
    diagnostic_bypass: bool = False
    is_blocked: bool = False
    blocking_reason: Optional[str] = None
    resources: dict[str, ResourcePolicyAssessment] = Field(default_factory=dict)
    process_risks: list[ProcessRiskAssessment] = Field(default_factory=list)
    restore_risks: list[RestoreRiskAssessment] = Field(default_factory=list)
    overall_compliance: PolicyComplianceOutcome = PolicyComplianceOutcome.UNDETERMINED
    violations_summary: list[str] = Field(default_factory=list)
    unresolved_summary: list[str] = Field(default_factory=list)
    coverage_limitations: list[str] = Field(default_factory=list)
    evaluation_time_ms: float = 0.0

    @field_validator("audit_at", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> datetime:
        return parse_iso_timestamp(v)
