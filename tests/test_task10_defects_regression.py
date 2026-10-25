"""Regression tests demonstrating Task 10 defects prior to fixes."""

from datetime import datetime
from pathlib import Path
import pytest

from ghost_audit.models.input_models import DataCategory, RequiredAction
from ghost_audit.policy.evaluator import PolicyEvaluator
from ghost_audit.policy.models import ConditionEvaluation, PolicyComplianceOutcome
from ghost_audit.policy.rules import PolicyRuleCatalog
from ghost_audit.state.models import (
    CopyKey,
    CopyStateAssessment,
    CopyType,
    ExistenceState,
    FieldObservation,
    FieldStatus,
    ResourceStateAggregate,
    StateTimelineEvent,
)


def _dt(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


@pytest.fixture
def policy_catalog() -> PolicyRuleCatalog:
    return PolicyRuleCatalog.load_from_csv(Path("dataset/deletion_rules.csv"))


def test_account_tombstone_without_evidence_is_not_satisfied(policy_catalog: PolicyRuleCatalog):
    """Defect 1A: ACCOUNT_TOMBSTONE with PRESENT existence and no fields/facts must not be SATISFIED."""
    evaluator = PolicyEvaluator(policy_catalog, audit_at=_dt("2026-09-10T12:00:00Z"))
    c_key = CopyKey(system_id="identity_service", resource_id="tombstone_empty", copy_type=CopyType.PRIMARY)

    ast_empty = CopyStateAssessment(
        copy_key=c_key,
        existence=ExistenceState.PRESENT,
        fields={},  # No proof of preserved user_id or removal of direct PII
    )
    res_empty = ResourceStateAggregate(
        system_id="identity_service",
        resource_id="tombstone_empty",
        canonical_key="identity_service:tombstone_empty",
        copies={str(c_key): ast_empty},
        aggregate_existence=ExistenceState.PRESENT,
    )
    res_eval = evaluator.evaluate_resource(
        resource=res_empty,
        category=DataCategory.ACCOUNT_TOMBSTONE,
        category_basis="test",
        subject_identifiers=["user_123", "alice@example.com"],
    )
    # Must NOT be SATISFIED without evidence of preserved stable ref and removed PII
    assert res_eval.outcome != PolicyComplianceOutcome.SATISFIED
    assert res_eval.outcome == PolicyComplianceOutcome.UNDETERMINED


def test_analytics_profile_without_evidence_is_not_satisfied(policy_catalog: PolicyRuleCatalog):
    """Defect 1A: ANALYTICS_PROFILE with PRESENT existence and no fields/facts must not be SATISFIED."""
    evaluator = PolicyEvaluator(policy_catalog, audit_at=_dt("2026-09-10T12:00:00Z"))
    c_key = CopyKey(system_id="analytics_platform", resource_id="analytics_empty", copy_type=CopyType.PRIMARY)

    ast_empty = CopyStateAssessment(
        copy_key=c_key,
        existence=ExistenceState.PRESENT,
        fields={},
    )
    res_empty = ResourceStateAggregate(
        system_id="analytics_platform",
        resource_id="analytics_empty",
        canonical_key="analytics_platform:analytics_empty",
        copies={str(c_key): ast_empty},
        aggregate_existence=ExistenceState.PRESENT,
    )
    res_eval = evaluator.evaluate_resource(
        resource=res_empty,
        category=DataCategory.ANALYTICS_PROFILE,
        category_basis="test",
        subject_identifiers=["user_123", "alice@example.com"],
    )
    # Must NOT be SATISFIED without proof of anonymization
    assert res_eval.outcome != PolicyComplianceOutcome.SATISFIED
    assert res_eval.outcome == PolicyComplianceOutcome.UNDETERMINED


def test_support_message_without_shared_context_facts_is_unknown(policy_catalog: PolicyRuleCatalog):
    """Defect 1A: SUPPORT_MESSAGE without shared context facts must have UNKNOWN condition, not SATISFIED."""
    evaluator = PolicyEvaluator(policy_catalog, audit_at=_dt("2026-09-10T12:00:00Z"))
    c_key = CopyKey(system_id="support_platform", resource_id="support_msg_empty", copy_type=CopyType.PRIMARY)

    ast_empty = CopyStateAssessment(
        copy_key=c_key,
        existence=ExistenceState.PRESENT,
        fields={},
    )
    res_empty = ResourceStateAggregate(
        system_id="support_platform",
        resource_id="support_msg_empty",
        canonical_key="support_platform:support_msg_empty",
        copies={str(c_key): ast_empty},
        aggregate_existence=ExistenceState.PRESENT,
    )
    res_eval = evaluator.evaluate_resource(
        resource=res_empty,
        category=DataCategory.SUPPORT_MESSAGE,
        category_basis="test",
        subject_identifiers=["alice@example.com"],
    )
    assert res_eval.condition_evaluation == ConditionEvaluation.UNKNOWN
    assert res_eval.outcome == PolicyComplianceOutcome.UNDETERMINED


def test_support_attachment_missing_ownership_is_unknown(policy_catalog: PolicyRuleCatalog):
    """Defect 1A: SUPPORT_ATTACHMENT without ownership facts must be UNKNOWN, not assumed exclusively owned."""
    evaluator = PolicyEvaluator(policy_catalog, audit_at=_dt("2026-09-10T12:00:00Z"))
    c_key = CopyKey(system_id="support_platform", resource_id="attachment_empty", copy_type=CopyType.PRIMARY)

    ast_empty = CopyStateAssessment(
        copy_key=c_key,
        existence=ExistenceState.PRESENT,
        fields={},
    )
    res_empty = ResourceStateAggregate(
        system_id="support_platform",
        resource_id="attachment_empty",
        canonical_key="support_platform:attachment_empty",
        copies={str(c_key): ast_empty},
        aggregate_existence=ExistenceState.PRESENT,
    )
    res_eval = evaluator.evaluate_resource(
        resource=res_empty,
        category=DataCategory.SUPPORT_ATTACHMENT,
        category_basis="test",
        subject_identifiers=["alice@example.com"],
    )
    assert res_eval.condition_evaluation == ConditionEvaluation.UNKNOWN
    assert res_eval.outcome == PolicyComplianceOutcome.UNDETERMINED


def test_legal_hold_timing_checks_start_and_end(policy_catalog: PolicyRuleCatalog):
    """Defect 1A: LEGAL_HOLD_RECORD evaluates hold_start as well as hold_end."""
    audit_at = _dt("2026-09-01T12:00:00Z")
    evaluator = PolicyEvaluator(policy_catalog, audit_at=audit_at)
    c_key = CopyKey(system_id="legal_service", resource_id="hold_01", copy_type=CopyType.PRIMARY)

    # Hold starts in the future: not active at audit_at
    ev_future = StateTimelineEvent(
        event_id="ev_future_hold",
        event_time=_dt("2026-08-01T12:00:00Z"),
        event_type="OBSERVED_RECORD",
        source_id="ev_01",
        source_type="EVIDENCE_FILE",
        time_role_basis="test",
        facts={"hold_status": "ACTIVE", "hold_start": "2026-09-15T00:00:00Z", "hold_end": "2026-12-31T00:00:00Z"},
    )
    ast_future = CopyStateAssessment(
        copy_key=c_key,
        existence=ExistenceState.PRESENT,
        timeline=[ev_future],
    )
    res_future = ResourceStateAggregate(
        system_id="legal_service",
        resource_id="hold_01",
        canonical_key="legal_service:hold_01",
        copies={str(c_key): ast_future},
        aggregate_existence=ExistenceState.PRESENT,
    )
    res_eval = evaluator.evaluate_resource(
        resource=res_future,
        category=DataCategory.LEGAL_HOLD_RECORD,
        category_basis="test",
        subject_identifiers=["alice@example.com"],
    )
    assert res_eval.condition_evaluation == ConditionEvaluation.FALSE
    assert res_eval.outcome == PolicyComplianceOutcome.UNDETERMINED
