"""Tests for output models, step validation, ordering, and citation constraints."""

import json
import pytest

from ghost_audit.models.output_models import (
    DeletionStatus,
    OutputRow,
    Step,
    StepOperation,
    StepPhase,
    StepState,
    validate_steps_sequence,
)


def test_valid_step_creation():
    step = Step(
        step_no=1,
        phase=StepPhase.FINDING,
        system_id="account_service",
        resource_id="account_005",
        operation=StepOperation.REPORT_REMAINING_RECORD,
        state=StepState.PRESENT,
        evidence_id="evidence_54",
    )
    assert step.step_no == 1
    assert step.phase == StepPhase.FINDING
    assert step.operation == StepOperation.REPORT_REMAINING_RECORD
    assert step.state == StepState.PRESENT


def test_step_operation_phase_state_mismatch():
    # Wrong state for operation (REPORT_REMAINING_RECORD must be PRESENT, not ABSENT)
    with pytest.raises(ValueError, match="requires state 'PRESENT'"):
        Step(
            step_no=1,
            phase=StepPhase.FINDING,
            system_id="account_service",
            resource_id="account_005",
            operation=StepOperation.REPORT_REMAINING_RECORD,
            state=StepState.ABSENT,
            evidence_id="evidence_54",
        )

    # Wrong phase for operation (DELETE_RECORD must be REMEDIATION, not FINDING)
    with pytest.raises(ValueError, match="requires phase 'REMEDIATION'"):
        Step(
            step_no=1,
            phase=StepPhase.FINDING,
            system_id="account_service",
            resource_id="account_005",
            operation=StepOperation.DELETE_RECORD,
            state=StepState.ABSENT,
            evidence_id="",
        )


def test_step_forbids_extra_fields():
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        Step.model_validate(
            {
                "step_no": 1,
                "phase": "FINDING",
                "system_id": "account_service",
                "resource_id": "account_005",
                "operation": "REPORT_REMAINING_RECORD",
                "state": "PRESENT",
                "evidence_id": "evidence_54",
                "unexpected_field": "disallowed",
            }
        )


def test_not_applicable_constraints():
    # Valid: empty steps
    errors = validate_steps_sequence(DeletionStatus.NOT_APPLICABLE, [])
    assert errors == []

    # Invalid: non-empty steps
    step = Step(
        step_no=1,
        phase=StepPhase.VERIFICATION,
        system_id="account_service",
        resource_id="account_001",
        operation=StepOperation.VERIFY_RECORD_ABSENT,
        state=StepState.ABSENT,
        evidence_id="evidence_54",
    )
    errors = validate_steps_sequence(DeletionStatus.NOT_APPLICABLE, [step])
    assert any("requires an empty steps_json array" in e for e in errors)


def test_complete_constraints():
    # Valid COMPLETE case: only verification, with evidence_id
    step1 = Step(
        step_no=1,
        phase=StepPhase.VERIFICATION,
        system_id="account_service",
        resource_id="account_001",
        operation=StepOperation.VERIFY_RECORD_ABSENT,
        state=StepState.ABSENT,
        evidence_id="evidence_54",
    )
    errors = validate_steps_sequence(DeletionStatus.COMPLETE, [step1])
    assert errors == []

    # Invalid: missing evidence_id
    step_no_ev = Step(
        step_no=1,
        phase=StepPhase.VERIFICATION,
        system_id="account_service",
        resource_id="account_001",
        operation=StepOperation.VERIFY_RECORD_ABSENT,
        state=StepState.ABSENT,
        evidence_id="",
    )
    errors = validate_steps_sequence(DeletionStatus.COMPLETE, [step_no_ev])
    assert any("must cite evidence" in e for e in errors)

    # Invalid: contains FINDING or REMEDIATION step
    step_rem = Step(
        step_no=1,
        phase=StepPhase.REMEDIATION,
        system_id="account_service",
        resource_id="account_001",
        operation=StepOperation.DELETE_RECORD,
        state=StepState.ABSENT,
        evidence_id="",
    )
    errors = validate_steps_sequence(DeletionStatus.COMPLETE, [step_rem])
    assert any("can only contain VERIFICATION steps" in e for e in errors)


def test_incomplete_constraints():
    # Valid INCOMPLETE case
    step1 = Step(
        step_no=1,
        phase=StepPhase.FINDING,
        system_id="account_service",
        resource_id="account_005",
        operation=StepOperation.REPORT_REMAINING_RECORD,
        state=StepState.PRESENT,
        evidence_id="evidence_54",
    )
    step2 = Step(
        step_no=2,
        phase=StepPhase.REMEDIATION,
        system_id="account_service",
        resource_id="account_005",
        operation=StepOperation.DELETE_RECORD,
        state=StepState.ABSENT,
        evidence_id="",
    )
    step3 = Step(
        step_no=3,
        phase=StepPhase.VERIFICATION,
        system_id="account_service",
        resource_id="account_005",
        operation=StepOperation.VERIFY_RECORD_ABSENT,
        state=StepState.ABSENT,
        evidence_id="",
    )
    errors = validate_steps_sequence(DeletionStatus.INCOMPLETE, [step1, step2, step3])
    assert errors == []

    # Invalid: finding without evidence_id
    bad_step1 = Step(
        step_no=1,
        phase=StepPhase.FINDING,
        system_id="account_service",
        resource_id="account_005",
        operation=StepOperation.REPORT_REMAINING_RECORD,
        state=StepState.PRESENT,
        evidence_id="",
    )
    errors = validate_steps_sequence(DeletionStatus.INCOMPLETE, [bad_step1, step2, step3])
    assert any("FINDING step 1 must cite participant evidence" in e for e in errors)

    # Invalid: remediation with non-empty evidence_id
    bad_step2 = Step(
        step_no=2,
        phase=StepPhase.REMEDIATION,
        system_id="account_service",
        resource_id="account_005",
        operation=StepOperation.DELETE_RECORD,
        state=StepState.ABSENT,
        evidence_id="evidence_99",
    )
    errors = validate_steps_sequence(DeletionStatus.INCOMPLETE, [step1, bad_step2, step3])
    assert any("must have empty evidence_id" in e for e in errors)


def test_step_numbering_consecutive():
    step1 = Step(
        step_no=2,  # Should start at 1
        phase=StepPhase.VERIFICATION,
        system_id="account_service",
        resource_id="account_001",
        operation=StepOperation.VERIFY_RECORD_ABSENT,
        state=StepState.ABSENT,
        evidence_id="evidence_54",
    )
    errors = validate_steps_sequence(DeletionStatus.COMPLETE, [step1])
    assert any("expected 1" in e for e in errors)


def test_canonical_step_ordering():
    # Out of order: Verification before Remediation
    step_verif = Step(
        step_no=1,
        phase=StepPhase.VERIFICATION,
        system_id="account_service",
        resource_id="account_005",
        operation=StepOperation.VERIFY_RECORD_ABSENT,
        state=StepState.ABSENT,
        evidence_id="",
    )
    step_remed = Step(
        step_no=2,
        phase=StepPhase.REMEDIATION,
        system_id="account_service",
        resource_id="account_005",
        operation=StepOperation.DELETE_RECORD,
        state=StepState.ABSENT,
        evidence_id="",
    )
    errors = validate_steps_sequence(DeletionStatus.INCOMPLETE, [step_verif, step_remed])
    assert any("Step ordering violation" in e for e in errors)


def test_output_row_serialization():
    row_na = OutputRow(case_id="case_000", deletion_status=DeletionStatus.NOT_APPLICABLE)
    assert row_na.steps_json_string() == "[]"
    assert row_na.to_csv_record() == ("case_000", "NOT_APPLICABLE", "[]")

    step = Step(
        step_no=1,
        phase=StepPhase.VERIFICATION,
        system_id="account_service",
        resource_id="account_001",
        operation=StepOperation.VERIFY_RECORD_ABSENT,
        state=StepState.ABSENT,
        evidence_id="evidence_54",
    )
    row_complete = OutputRow(
        case_id="case_01",
        deletion_status=DeletionStatus.COMPLETE,
        steps=[step],
    )
    serialized = row_complete.steps_json_string()
    deserialized = json.loads(serialized)
    assert len(deserialized) == 1
    assert deserialized[0]["step_no"] == 1
    assert deserialized[0]["system_id"] == "account_service"
