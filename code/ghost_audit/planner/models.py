"""Internal models for remediation planning and dependency reasoning."""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field

from ghost_audit.models.output_models import (
    DeletionStatus,
    OutputRow,
    Step,
    StepOperation,
    StepPhase,
    StepState,
    step_canonical_key,
)


class PlannedStep(BaseModel):
    """An internal planned step with dependency and provenance tracking."""

    model_config = ConfigDict(frozen=True)

    phase: StepPhase
    system_id: str
    resource_id: str
    operation: StepOperation
    state: StepState
    evidence_id: str = ""
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    execution_priority: int = 100
    target_copy: Optional[str] = None
    reason: str = ""


class CasePlan(BaseModel):
    """Complete audit decision and plan for a case."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    status: DeletionStatus
    steps: list[Step] = Field(default_factory=list)
    internal_steps: list[PlannedStep] = Field(default_factory=list)
    execution_graph: dict[str, list[str]] = Field(default_factory=dict)
    is_unresolved: bool = False
    unresolved_reasons: list[str] = Field(default_factory=list)

    def to_output_row(self) -> OutputRow:
        """Convert to validated canonical OutputRow."""
        return OutputRow(
            case_id=self.case_id,
            deletion_status=self.status,
            steps=self.steps,
        )
