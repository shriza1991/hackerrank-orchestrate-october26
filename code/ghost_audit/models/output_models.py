"""Output data contracts and validation helpers."""

from enum import Enum
import json
from typing import NamedTuple
from pydantic import BaseModel, ConfigDict, Field, model_validator


class DeletionStatus(str, Enum):
    """Allowed deletion assessment statuses."""

    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class StepPhase(str, Enum):
    """Execution phase for audit and remediation steps."""

    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"


class StepOperation(str, Enum):
    """Allowed step operations across phases."""

    # Finding operations
    REPORT_REMAINING_RECORD = "REPORT_REMAINING_RECORD"
    REPORT_EXPOSED_PII = "REPORT_EXPOSED_PII"
    REPORT_ACTIVE_DATA_FLOW = "REPORT_ACTIVE_DATA_FLOW"
    REPORT_RESTORE_RISK = "REPORT_RESTORE_RISK"

    # Remediation operations
    DISABLE_DATA_FLOW = "DISABLE_DATA_FLOW"
    BLOCK_RESTORE = "BLOCK_RESTORE"
    DELETE_RECORD = "DELETE_RECORD"
    REDACT_RECORD = "REDACT_RECORD"
    ANONYMIZE_RECORD = "ANONYMIZE_RECORD"

    # Verification operations
    VERIFY_RECORD_ABSENT = "VERIFY_RECORD_ABSENT"
    VERIFY_RECORD_PRESENT = "VERIFY_RECORD_PRESENT"
    VERIFY_RECORD_REDACTED = "VERIFY_RECORD_REDACTED"
    VERIFY_RECORD_ANONYMIZED = "VERIFY_RECORD_ANONYMIZED"
    VERIFY_DATA_FLOW_DISABLED = "VERIFY_DATA_FLOW_DISABLED"
    VERIFY_RESTORE_BLOCKED = "VERIFY_RESTORE_BLOCKED"


class StepState(str, Enum):
    """Allowed states for resources in steps."""

    PRESENT = "PRESENT"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    BLOCKED = "BLOCKED"
    ABSENT = "ABSENT"
    REDACTED = "REDACTED"
    ANONYMIZED = "ANONYMIZED"


# Exact permitted (phase, state) pairs for each operation
ALLOWED_OPERATION_PHASE_STATE: dict[StepOperation, tuple[StepPhase, StepState]] = {
    StepOperation.REPORT_REMAINING_RECORD: (StepPhase.FINDING, StepState.PRESENT),
    StepOperation.REPORT_EXPOSED_PII: (StepPhase.FINDING, StepState.PRESENT),
    StepOperation.REPORT_ACTIVE_DATA_FLOW: (StepPhase.FINDING, StepState.ACTIVE),
    StepOperation.REPORT_RESTORE_RISK: (StepPhase.FINDING, StepState.ACTIVE),
    StepOperation.DISABLE_DATA_FLOW: (StepPhase.REMEDIATION, StepState.DISABLED),
    StepOperation.BLOCK_RESTORE: (StepPhase.REMEDIATION, StepState.BLOCKED),
    StepOperation.DELETE_RECORD: (StepPhase.REMEDIATION, StepState.ABSENT),
    StepOperation.REDACT_RECORD: (StepPhase.REMEDIATION, StepState.REDACTED),
    StepOperation.ANONYMIZE_RECORD: (StepPhase.REMEDIATION, StepState.ANONYMIZED),
    StepOperation.VERIFY_RECORD_ABSENT: (StepPhase.VERIFICATION, StepState.ABSENT),
    StepOperation.VERIFY_RECORD_PRESENT: (StepPhase.VERIFICATION, StepState.PRESENT),
    StepOperation.VERIFY_RECORD_REDACTED: (StepPhase.VERIFICATION, StepState.REDACTED),
    StepOperation.VERIFY_RECORD_ANONYMIZED: (StepPhase.VERIFICATION, StepState.ANONYMIZED),
    StepOperation.VERIFY_DATA_FLOW_DISABLED: (StepPhase.VERIFICATION, StepState.DISABLED),
    StepOperation.VERIFY_RESTORE_BLOCKED: (StepPhase.VERIFICATION, StepState.BLOCKED),
}

# Ordering ranks
PHASE_ORDER: dict[StepPhase, int] = {
    StepPhase.FINDING: 1,
    StepPhase.REMEDIATION: 2,
    StepPhase.VERIFICATION: 3,
}

OPERATION_ORDER: dict[StepOperation, int] = {
    # Findings
    StepOperation.REPORT_REMAINING_RECORD: 1,
    StepOperation.REPORT_EXPOSED_PII: 2,
    StepOperation.REPORT_ACTIVE_DATA_FLOW: 3,
    StepOperation.REPORT_RESTORE_RISK: 4,
    # Remediation
    StepOperation.DISABLE_DATA_FLOW: 1,
    StepOperation.BLOCK_RESTORE: 2,
    StepOperation.DELETE_RECORD: 3,
    StepOperation.REDACT_RECORD: 4,
    StepOperation.ANONYMIZE_RECORD: 5,
    # Verification
    StepOperation.VERIFY_RECORD_ABSENT: 1,
    StepOperation.VERIFY_RECORD_PRESENT: 2,
    StepOperation.VERIFY_RECORD_REDACTED: 3,
    StepOperation.VERIFY_RECORD_ANONYMIZED: 4,
    StepOperation.VERIFY_DATA_FLOW_DISABLED: 5,
    StepOperation.VERIFY_RESTORE_BLOCKED: 6,
}


class CanonicalSortKey(NamedTuple):
    """Sort key for canonical step sequence comparison."""

    phase_rank: int
    operation_rank: int
    system_id: str
    resource_id: str


def step_canonical_key(step: "Step") -> CanonicalSortKey:
    """Return canonical sorting key: phase -> operation -> system_id -> resource_id."""
    return CanonicalSortKey(
        phase_rank=PHASE_ORDER[step.phase],
        operation_rank=OPERATION_ORDER[step.operation],
        system_id=step.system_id,
        resource_id=step.resource_id,
    )


class Step(BaseModel):
    """Single step within steps_json."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    step_no: int = Field(ge=1, description="1-indexed consecutive step number")
    phase: StepPhase
    system_id: str
    resource_id: str
    operation: StepOperation
    state: StepState
    evidence_id: str = ""

    @model_validator(mode="after")
    def validate_operation_phase_state(self) -> "Step":
        expected = ALLOWED_OPERATION_PHASE_STATE.get(self.operation)
        if expected is None:
            raise ValueError(f"Unknown operation '{self.operation}'.")
        exp_phase, exp_state = expected
        if self.phase != exp_phase:
            raise ValueError(
                f"Operation '{self.operation.value}' requires phase '{exp_phase.value}', got '{self.phase.value}'."
            )
        if self.state != exp_state:
            raise ValueError(
                f"Operation '{self.operation.value}' requires state '{exp_state.value}', got '{self.state.value}'."
            )
        return self


def validate_steps_sequence(status: DeletionStatus, steps: list[Step]) -> list[str]:
    """Perform comprehensive structural validation on a sequence of steps for a given deletion status.

    Returns a list of validation error descriptions. Empty list means valid.
    """
    errors: list[str] = []

    # Case 1: NOT_APPLICABLE
    if status == DeletionStatus.NOT_APPLICABLE:
        if len(steps) != 0:
            errors.append(f"NOT_APPLICABLE requires an empty steps_json array; got {len(steps)} steps.")
        return errors

    # Case 2: COMPLETE or INCOMPLETE must have at least one step
    if len(steps) == 0:
        errors.append(f"Status '{status.value}' requires steps, but steps_json is empty.")
        return errors

    # Consecutive numbering starting at 1
    for i, step in enumerate(steps, start=1):
        if step.step_no != i:
            errors.append(f"Step at index {i-1} has step_no={step.step_no}, expected {i}.")

    # Status-specific phase and citation validation
    if status == DeletionStatus.COMPLETE:
        for step in steps:
            if step.phase != StepPhase.VERIFICATION:
                errors.append(
                    f"COMPLETE case can only contain VERIFICATION steps, found step {step.step_no} with phase '{step.phase.value}'."
                )
            if not step.evidence_id:
                errors.append(
                    f"COMPLETE case verification step {step.step_no} must cite evidence; evidence_id is empty."
                )
    elif status == DeletionStatus.INCOMPLETE:
        phases_present = {step.phase for step in steps}
        if StepPhase.FINDING not in phases_present:
            errors.append("INCOMPLETE case must contain at least one FINDING step.")
        if StepPhase.REMEDIATION not in phases_present:
            errors.append("INCOMPLETE case must contain at least one REMEDIATION step.")
        if StepPhase.VERIFICATION not in phases_present:
            errors.append("INCOMPLETE case must contain at least one VERIFICATION step.")

        for step in steps:
            if step.phase == StepPhase.FINDING:
                if not step.evidence_id:
                    errors.append(
                        f"FINDING step {step.step_no} must cite participant evidence; evidence_id is empty."
                    )
            elif step.phase == StepPhase.REMEDIATION:
                if step.evidence_id != "":
                    errors.append(
                        f"REMEDIATION step {step.step_no} must have empty evidence_id (''); got '{step.evidence_id}'."
                    )
            elif step.phase == StepPhase.VERIFICATION:
                if step.evidence_id != "":
                    errors.append(
                        f"INCOMPLETE verification step {step.step_no} must have empty evidence_id (''); got '{step.evidence_id}'."
                    )

    # Canonical order validation
    for i in range(len(steps) - 1):
        k1 = step_canonical_key(steps[i])
        k2 = step_canonical_key(steps[i + 1])
        if k1 > k2:
            errors.append(
                f"Step ordering violation between step {steps[i].step_no} ({k1}) and step {steps[i+1].step_no} ({k2})."
            )

    return errors


class OutputRow(BaseModel):
    """Final output row contract for output.csv."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    deletion_status: DeletionStatus
    steps: list[Step] = Field(default_factory=list)

    def validate_row(self) -> list[str]:
        """Validate step sequence according to the row's deletion status."""
        return validate_steps_sequence(self.deletion_status, self.steps)

    def steps_json_string(self) -> str:
        """Serialize steps as a valid JSON array."""
        return json.dumps([s.model_dump() for s in self.steps], separators=(",", ":"))

    def to_csv_record(self) -> tuple[str, str, str]:
        """Return tuple of (case_id, deletion_status, steps_json)."""
        return self.case_id, self.deletion_status.value, self.steps_json_string()
