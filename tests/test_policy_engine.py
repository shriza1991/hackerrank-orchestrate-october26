"""Comprehensive test suite for evidence-grounded policy decision engine (Task 10)."""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from ghost_audit.models.input_models import (
    DataCategory,
    DeletionRequest,
    DeletionRule,
    ReportedResult,
    ReportedStatus,
    RequiredAction,
    SystemActivityEvent,
)
from ghost_audit.models.intermediate_models import EvidenceObservation, IdentityResolutionStatus
from ghost_audit.policy.category_classifier import GroundedCategoryClassifier
from ghost_audit.policy.evaluator import PolicyEvaluator
from ghost_audit.policy.models import (
    ConditionEvaluation,
    CopyPolicyAssessment,
    PolicyComplianceOutcome,
    ProcessRiskAssessment,
    ResourcePolicyAssessment,
    RestoreRiskAssessment,
)
from ghost_audit.policy.rules import PolicyRuleCatalog, PolicyRuleCatalogError
from ghost_audit.policy.service import PolicyDecisionEngine
from ghost_audit.retrieval.models import CaseEvidencePacket, SelectedObservation, LinkRelationship
from ghost_audit.state.models import (
    CaseStateReconstruction,
    CopyKey,
    CopyStateAssessment,
    CopyType,
    ExistenceState,
    FieldObservation,
    FieldStatus,
    ProcessState,
    ResourceStateAggregate,
    RestoreState,
    StateDiagnostics,
    StateTimelineEvent,
)
from ghost_audit.state.service import ResourceStateReconstructionService


def _dt(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


@pytest.fixture
def policy_catalog() -> PolicyRuleCatalog:
    rules_path = Path("dataset/deletion_rules.csv")
    return PolicyRuleCatalog.load_from_csv(rules_path)


@pytest.fixture
def policy_engine(policy_catalog: PolicyRuleCatalog) -> PolicyDecisionEngine:
    return PolicyDecisionEngine(policy_catalog)


# ---------------------------------------------------------------------------
# 1. Rule Catalog Validation Tests
# ---------------------------------------------------------------------------

def test_rule_catalog_loads_all_15_rules(policy_catalog: PolicyRuleCatalog):
    """Rule catalog must contain all 15 rules without silent fallback."""
    rules = policy_catalog.all_rules()
    assert len(rules) == 15
    for cat in DataCategory:
        rule = policy_catalog.get_rule(cat)
        assert rule.data_category == cat
        assert rule.rule_id.startswith("rule_")


def test_rule_catalog_rejects_duplicate_or_conflicting_rules():
    """Duplicate or conflicting rules must raise PolicyRuleCatalogError."""
    r1 = DeletionRule(
        rule_id="rule_01",
        data_category=DataCategory.USER_PROFILE,
        condition="Always",
        required_action=RequiredAction.DELETE,
    )
    r2 = DeletionRule(
        rule_id="rule_01_dup",
        data_category=DataCategory.USER_PROFILE,
        condition="Always",
        required_action=RequiredAction.DELETE,
    )
    with pytest.raises(PolicyRuleCatalogError, match="Conflicting rule for category"):
        PolicyRuleCatalog([r1, r2])


def test_rule_catalog_rejects_missing_rules():
    """Missing standard categories must raise PolicyRuleCatalogError."""
    r1 = DeletionRule(
        rule_id="rule_01",
        data_category=DataCategory.USER_PROFILE,
        condition="Always",
        required_action=RequiredAction.DELETE,
    )
    with pytest.raises(PolicyRuleCatalogError, match="Missing required policy rules"):
        PolicyRuleCatalog([r1])


# ---------------------------------------------------------------------------
# 2. Grounded Category Classification Tests
# ---------------------------------------------------------------------------

def test_category_classification_replaces_synthetic_categories():
    """Replaces synthetic categories with grounded policy categories."""
    cat, basis = GroundedCategoryClassifier.classify(
        system_id="account_service",
        resource_id="account_001",
        store_locator="table:customer_profiles",
    )
    assert cat == DataCategory.USER_PROFILE

    cat, basis = GroundedCategoryClassifier.classify(
        system_id="search_service",
        resource_id="search_101",
        store_locator="search_index:users",
    )
    assert cat == DataCategory.SEARCH_INDEX_ENTRY

    cat, basis = GroundedCategoryClassifier.classify(
        system_id="identity_service",
        resource_id="tombstone_001",
        store_locator="table:account_tombstones",
    )
    assert cat == DataCategory.ACCOUNT_TOMBSTONE


def test_unknown_or_conflicting_category_remains_unresolved():
    """Ambiguous or conflicting category evidence must return None."""
    cat, basis = GroundedCategoryClassifier.classify(
        system_id="custom_system",
        resource_id="blob_xyz",
        store_locator="s3://unknown/data",
        facts={},
    )
    assert cat is None
    assert "Unresolved category" in basis

    # Conflicting explicit and table facts
    cat_conflict, basis_conflict = GroundedCategoryClassifier.classify(
        system_id="mixed_system",
        resource_id="record_123",
        facts={"record_type": "user_export", "data_category": "SECURITY_AUDIT_LOG"},
    )
    assert cat_conflict is None
    assert "Conflicting category evidence" in basis_conflict


# ---------------------------------------------------------------------------
# 3. Policy Semantics: All 15 Categories
# ---------------------------------------------------------------------------

def test_delete_categories_surviving_copy_violates(policy_catalog: PolicyRuleCatalog):
    """For DELETE categories, a surviving copy violates deletion."""
    evaluator = PolicyEvaluator(policy_catalog, audit_at=_dt("2026-09-10T12:00:00Z"))

    for cat in [
        DataCategory.USER_PROFILE,
        DataCategory.SECONDARY_IDENTIFIER,
        DataCategory.SEARCH_INDEX_ENTRY,
        DataCategory.CACHE_ENTRY,
        DataCategory.USER_EXPORT,
        DataCategory.MARKETING_PROFILE,
    ]:
        c_key = CopyKey(system_id="test_sys", resource_id="res_01", copy_type=CopyType.PRIMARY)
        copy_ast = CopyStateAssessment(
            copy_key=c_key,
            existence=ExistenceState.PRESENT,
        )
        res_agg = ResourceStateAggregate(
            system_id="test_sys",
            resource_id="res_01",
            canonical_key="test_sys:res_01",
            copies={str(c_key): copy_ast},
            aggregate_existence=ExistenceState.PRESENT,
            surviving_copies=[str(c_key)],
        )

        res_eval = evaluator.evaluate_resource(
            resource=res_agg,
            category=cat,
            category_basis="test",
            subject_identifiers=["u1@test.com"],
        )
        assert res_eval.outcome == PolicyComplianceOutcome.VIOLATED
        assert res_eval.condition_evaluation == ConditionEvaluation.TRUE


def test_delete_categories_all_copies_absent_satisfies(policy_catalog: PolicyRuleCatalog):
    """When all copies are ABSENT, DELETE category is SATISFIED."""
    evaluator = PolicyEvaluator(policy_catalog, audit_at=_dt("2026-09-10T12:00:00Z"))
    c_key = CopyKey(system_id="test_sys", resource_id="res_01", copy_type=CopyType.PRIMARY)
    copy_ast = CopyStateAssessment(
        copy_key=c_key,
        existence=ExistenceState.ABSENT,
    )
    res_agg = ResourceStateAggregate(
        system_id="test_sys",
        resource_id="res_01",
        canonical_key="test_sys:res_01",
        copies={str(c_key): copy_ast},
        aggregate_existence=ExistenceState.ABSENT,
        absent_copies=[str(c_key)],
    )

    res_eval = evaluator.evaluate_resource(
        resource=res_agg,
        category=DataCategory.USER_PROFILE,
        category_basis="test",
        subject_identifiers=["u1@test.com"],
    )
    assert res_eval.outcome == PolicyComplianceOutcome.SATISFIED


def test_primary_absence_plus_surviving_replica_violates(policy_catalog: PolicyRuleCatalog):
    """Primary absence does not erase surviving replica violation."""
    evaluator = PolicyEvaluator(policy_catalog, audit_at=_dt("2026-09-10T12:00:00Z"))
    c_prim = CopyKey(system_id="account_service", resource_id="account_01", copy_type=CopyType.PRIMARY)
    c_rep = CopyKey(system_id="account_service", resource_id="account_01", copy_type=CopyType.READ_REPLICA)

    ast_prim = CopyStateAssessment(copy_key=c_prim, existence=ExistenceState.ABSENT)
    ast_rep = CopyStateAssessment(copy_key=c_rep, existence=ExistenceState.PRESENT)

    res_agg = ResourceStateAggregate(
        system_id="account_service",
        resource_id="account_01",
        canonical_key="account_service:account_01",
        copies={str(c_prim): ast_prim, str(c_rep): ast_rep},
        aggregate_existence=ExistenceState.PRESENT,
        surviving_copies=[str(c_rep)],
        absent_copies=[str(c_prim)],
    )

    res_eval = evaluator.evaluate_resource(
        resource=res_agg,
        category=DataCategory.USER_PROFILE,
        category_basis="test",
        subject_identifiers=["u1@test.com"],
    )
    assert res_eval.outcome == PolicyComplianceOutcome.VIOLATED
    assert res_eval.copies[str(c_prim)].outcome == PolicyComplianceOutcome.SATISFIED
    assert res_eval.copies[str(c_rep)].outcome == PolicyComplianceOutcome.VIOLATED


def test_account_tombstone_stable_reference_vs_exposed_pii(policy_catalog: PolicyRuleCatalog):
    """ACCOUNT_TOMBSTONE permits stable user_id but violates on exposed direct PII."""
    evaluator = PolicyEvaluator(policy_catalog, audit_at=_dt("2026-09-10T12:00:00Z"))
    c_key = CopyKey(system_id="identity_service", resource_id="tombstone_01", copy_type=CopyType.PRIMARY)

    # 1. Compliant tombstone: only user_id
    ast_ok = CopyStateAssessment(
        copy_key=c_key,
        existence=ExistenceState.PRESENT,
        fields={"user_id": FieldObservation(field_name="user_id", status=FieldStatus.RETAINED_STABLE_REF, raw_value="usr_123")},
    )
    res_ok = ResourceStateAggregate(
        system_id="identity_service",
        resource_id="tombstone_01",
        canonical_key="identity_service:tombstone_01",
        copies={str(c_key): ast_ok},
        aggregate_existence=ExistenceState.PRESENT,
    )
    res_eval_ok = evaluator.evaluate_resource(
        resource=res_ok,
        category=DataCategory.ACCOUNT_TOMBSTONE,
        category_basis="test",
        subject_identifiers=["usr_123", "alice@example.com"],
    )
    assert res_eval_ok.outcome == PolicyComplianceOutcome.SATISFIED

    # 2. Non-compliant tombstone: exposed email
    ast_violation = CopyStateAssessment(
        copy_key=c_key,
        existence=ExistenceState.PRESENT,
        fields={
            "user_id": FieldObservation(field_name="user_id", status=FieldStatus.EXPOSED, raw_value="usr_123"),
            "email": FieldObservation(field_name="email", status=FieldStatus.EXPOSED, raw_value="alice@example.com"),
        },
    )
    res_violation = ResourceStateAggregate(
        system_id="identity_service",
        resource_id="tombstone_01",
        canonical_key="identity_service:tombstone_01",
        copies={str(c_key): ast_violation},
        aggregate_existence=ExistenceState.PRESENT,
        observed_pii_exposed=True,
    )
    res_eval_violation = evaluator.evaluate_resource(
        resource=res_violation,
        category=DataCategory.ACCOUNT_TOMBSTONE,
        category_basis="test",
        subject_identifiers=["usr_123", "alice@example.com"],
    )
    assert res_eval_violation.outcome == PolicyComplianceOutcome.VIOLATED


def test_analytics_with_remaining_payload_despite_anonymized_flag(policy_catalog: PolicyRuleCatalog):
    """ANALYTICS_PROFILE with anonymized:true flag but identifying payload violates anonymization."""
    evaluator = PolicyEvaluator(policy_catalog, audit_at=_dt("2026-09-10T12:00:00Z"))
    c_key = CopyKey(system_id="analytics_platform", resource_id="analytics_901", copy_type=CopyType.PRIMARY)

    ev = StateTimelineEvent(
        event_id="ev_01",
        event_time=_dt("2026-09-01T10:00:00Z"),
        event_type="OBSERVED_RECORD",
        source_id="evidence_56",
        source_type="EVIDENCE_FILE",
        time_role_basis="test",
        facts={"anonymized": True, "subject_link": "user_901", "email": "user901@test.com"},
    )
    ast = CopyStateAssessment(
        copy_key=c_key,
        existence=ExistenceState.PRESENT,
        timeline=[ev],
        fields={
            "email": FieldObservation(field_name="email", status=FieldStatus.EXPOSED, raw_value="user901@test.com"),
        },
    )
    res_agg = ResourceStateAggregate(
        system_id="analytics_platform",
        resource_id="analytics_901",
        canonical_key="analytics_platform:analytics_901",
        copies={str(c_key): ast},
        aggregate_existence=ExistenceState.PRESENT,
        observed_pii_exposed=True,
    )

    res_eval = evaluator.evaluate_resource(
        resource=res_agg,
        category=DataCategory.ANALYTICS_PROFILE,
        category_basis="test",
        subject_identifiers=["user901@test.com", "user_901"],
    )
    assert res_eval.condition_evaluation == ConditionEvaluation.TRUE
    assert res_eval.outcome == PolicyComplianceOutcome.VIOLATED


def test_shared_support_context_vs_subject_attachment(policy_catalog: PolicyRuleCatalog):
    """SUPPORT_MESSAGE retains context with redacted PII; SUPPORT_ATTACHMENT must be deleted if subject-only."""
    evaluator = PolicyEvaluator(policy_catalog, audit_at=_dt("2026-09-10T12:00:00Z"))

    # 1. Support message with shared context redacted
    c_msg = CopyKey(system_id="support_platform", resource_id="support_msg_1", copy_type=CopyType.PRIMARY)
    ev_msg = StateTimelineEvent(
        event_id="ev_msg",
        event_time=_dt("2026-09-01T10:00:00Z"),
        event_type="OBSERVED_RECORD",
        source_id="ev_01",
        source_type="EVIDENCE_FILE",
        time_role_basis="test",
        facts={"shared_context": True, "agent": "Agent Smith", "order_id": "ORD-123"},
    )
    ast_msg = CopyStateAssessment(
        copy_key=c_msg,
        existence=ExistenceState.PRESENT,
        timeline=[ev_msg],
        fields={
            "customer_name": FieldObservation(field_name="customer_name", status=FieldStatus.MASKED),
            "agent_name": FieldObservation(field_name="agent_name", status=FieldStatus.EXPOSED, raw_value="Agent Smith"),
        },
    )
    res_msg = ResourceStateAggregate(
        system_id="support_platform",
        resource_id="support_msg_1",
        canonical_key="support_platform:support_msg_1",
        copies={str(c_msg): ast_msg},
        aggregate_existence=ExistenceState.PRESENT,
    )
    res_eval_msg = evaluator.evaluate_resource(
        resource=res_msg,
        category=DataCategory.SUPPORT_MESSAGE,
        category_basis="test",
        subject_identifiers=["John Doe", "john@example.com"],
    )
    # Agent Smith being present is not a violation of subject privacy!
    assert res_eval_msg.outcome == PolicyComplianceOutcome.SATISFIED

    # 2. Support attachment belonging only to subject
    c_att = CopyKey(system_id="support_platform", resource_id="attachment_doc_1", copy_type=CopyType.PRIMARY)
    ev_att = StateTimelineEvent(
        event_id="ev_att",
        event_time=_dt("2026-09-01T10:00:00Z"),
        event_type="OBSERVED_RECORD",
        source_id="ev_02",
        source_type="EVIDENCE_FILE",
        time_role_basis="test",
        facts={"belongs_only_to_subject": True},
    )
    ast_att_present = CopyStateAssessment(
        copy_key=c_att,
        existence=ExistenceState.PRESENT,
        timeline=[ev_att],
    )
    res_att = ResourceStateAggregate(
        system_id="support_platform",
        resource_id="attachment_doc_1",
        canonical_key="support_platform:attachment_doc_1",
        copies={str(c_att): ast_att_present},
        aggregate_existence=ExistenceState.PRESENT,
    )
    res_eval_att = evaluator.evaluate_resource(
        resource=res_att,
        category=DataCategory.SUPPORT_ATTACHMENT,
        category_basis="test",
        subject_identifiers=["john@example.com"],
    )
    assert res_eval_att.outcome == PolicyComplianceOutcome.VIOLATED


def test_retention_boundary_and_legal_hold_timing(policy_catalog: PolicyRuleCatalog):
    """SECURITY_AUDIT_LOG and LEGAL_HOLD_RECORD within valid temporal boundaries at audit_at."""
    audit_at = _dt("2026-09-10T12:00:00Z")
    evaluator = PolicyEvaluator(policy_catalog, audit_at=audit_at)

    # Security audit log: active retention
    c_sec = CopyKey(system_id="security_service", resource_id="audit_rec_1", copy_type=CopyType.PRIMARY)
    ev_sec = StateTimelineEvent(
        event_id="ev_sec",
        event_time=_dt("2026-09-01T10:00:00Z"),
        event_type="OBSERVED_RECORD",
        source_id="ev_sec",
        source_type="EVIDENCE_FILE",
        time_role_basis="test",
        facts={"retention_until": "2026-12-31T23:59:59Z"},
    )
    ast_sec = CopyStateAssessment(
        copy_key=c_sec,
        existence=ExistenceState.PRESENT,
        timeline=[ev_sec],
    )
    res_sec = ResourceStateAggregate(
        system_id="security_service",
        resource_id="audit_rec_1",
        canonical_key="security_service:audit_rec_1",
        copies={str(c_sec): ast_sec},
        aggregate_existence=ExistenceState.PRESENT,
    )
    res_eval_sec = evaluator.evaluate_resource(
        resource=res_sec,
        category=DataCategory.SECURITY_AUDIT_LOG,
        category_basis="test",
        subject_identifiers=["john@example.com"],
    )
    assert res_eval_sec.condition_evaluation == ConditionEvaluation.TRUE
    assert res_eval_sec.outcome == PolicyComplianceOutcome.SATISFIED

    # Premature deletion of retained security audit log violates policy!
    ast_sec_absent = CopyStateAssessment(
        copy_key=c_sec,
        existence=ExistenceState.ABSENT,
        timeline=[ev_sec],
    )
    res_sec_absent = ResourceStateAggregate(
        system_id="security_service",
        resource_id="audit_rec_1",
        canonical_key="security_service:audit_rec_1",
        copies={str(c_sec): ast_sec_absent},
        aggregate_existence=ExistenceState.ABSENT,
    )
    res_eval_sec_absent = evaluator.evaluate_resource(
        resource=res_sec_absent,
        category=DataCategory.SECURITY_AUDIT_LOG,
        category_basis="test",
        subject_identifiers=["john@example.com"],
    )
    assert res_eval_sec_absent.outcome == PolicyComplianceOutcome.VIOLATED


def test_restore_block_claim_vs_observed_restore_restriction(policy_catalog: PolicyRuleCatalog):
    """Restore block claim is insufficient proof; verified blocked is satisfied."""
    evaluator = PolicyEvaluator(policy_catalog, audit_at=_dt("2026-09-10T12:00:00Z"))
    c_bk = CopyKey(system_id="backup_service", resource_id="backup_100", copy_type=CopyType.DATABASE_BACKUP)

    # 1. Unverified claim only
    ast_claim = CopyStateAssessment(
        copy_key=c_bk,
        existence=ExistenceState.PRESENT,
        restore_state=RestoreState.ALLOWED,
        unverified_claims=["BLOCK_RESTORE SUCCESS"],
    )
    res_claim = ResourceStateAggregate(
        system_id="backup_service",
        resource_id="backup_100",
        canonical_key="backup_service:backup_100",
        copies={str(c_bk): ast_claim},
        aggregate_existence=ExistenceState.PRESENT,
    )
    res_eval_claim = evaluator.evaluate_resource(
        resource=res_claim,
        category=DataCategory.BACKUP_ARCHIVE,
        category_basis="test",
        subject_identifiers=["user@test.com"],
    )
    assert res_eval_claim.outcome == PolicyComplianceOutcome.VIOLATED

    # 2. Verified BLOCKED
    ast_blocked = CopyStateAssessment(
        copy_key=c_bk,
        existence=ExistenceState.PRESENT,
        restore_state=RestoreState.BLOCKED,
    )
    res_blocked = ResourceStateAggregate(
        system_id="backup_service",
        resource_id="backup_100",
        canonical_key="backup_service:backup_100",
        copies={str(c_bk): ast_blocked},
        aggregate_existence=ExistenceState.PRESENT,
    )
    res_eval_blocked = evaluator.evaluate_resource(
        resource=res_blocked,
        category=DataCategory.BACKUP_ARCHIVE,
        category_basis="test",
        subject_identifiers=["user@test.com"],
    )
    assert res_eval_blocked.outcome == PolicyComplianceOutcome.SATISFIED


def test_email_delivery_log_redaction_semantics(policy_catalog: PolicyRuleCatalog):
    """EMAIL_DELIVERY_LOG applies REDACT when containing user email."""
    evaluator = PolicyEvaluator(policy_catalog, audit_at=_dt("2026-09-10T12:00:00Z"))
    c_log = CopyKey(system_id="email_service", resource_id="delivery_log_1", copy_type=CopyType.PRIMARY)

    # 1. Exposed email
    ev_exposed = StateTimelineEvent(
        event_id="ev_01",
        event_time=_dt("2026-09-01T10:00:00Z"),
        event_type="OBSERVED_RECORD",
        source_id="ev_01",
        source_type="EVIDENCE_FILE",
        time_role_basis="test",
        facts={"to": "target_user@test.com", "status": "DELIVERED"},
    )
    ast_exposed = CopyStateAssessment(
        copy_key=c_log,
        existence=ExistenceState.PRESENT,
        timeline=[ev_exposed],
        fields={"to": FieldObservation(field_name="to", status=FieldStatus.EXPOSED, raw_value="target_user@test.com")},
    )
    res_exposed = ResourceStateAggregate(
        system_id="email_service",
        resource_id="delivery_log_1",
        canonical_key="email_service:delivery_log_1",
        copies={str(c_log): ast_exposed},
        aggregate_existence=ExistenceState.PRESENT,
        observed_pii_exposed=True,
    )
    res_eval_exposed = evaluator.evaluate_resource(
        resource=res_exposed,
        category=DataCategory.EMAIL_DELIVERY_LOG,
        category_basis="test",
        subject_identifiers=["target_user@test.com"],
    )
    assert res_eval_exposed.condition_evaluation == ConditionEvaluation.TRUE
    assert res_eval_exposed.outcome == PolicyComplianceOutcome.VIOLATED

    # 2. Redacted email
    ev_redacted = StateTimelineEvent(
        event_id="ev_02",
        event_time=_dt("2026-09-01T10:00:00Z"),
        event_type="OBSERVED_RECORD",
        source_id="ev_02",
        source_type="EVIDENCE_FILE",
        time_role_basis="test",
        facts={"to": "[REDACTED]", "is_redacted": True, "status": "DELIVERED"},
    )
    ast_redacted = CopyStateAssessment(
        copy_key=c_log,
        existence=ExistenceState.PRESENT,
        timeline=[ev_redacted],
        fields={"to": FieldObservation(field_name="to", status=FieldStatus.MASKED, raw_value="[REDACTED]")},
    )
    res_redacted = ResourceStateAggregate(
        system_id="email_service",
        resource_id="delivery_log_1",
        canonical_key="email_service:delivery_log_1",
        copies={str(c_log): ast_redacted},
        aggregate_existence=ExistenceState.PRESENT,
    )
    res_eval_redacted = evaluator.evaluate_resource(
        resource=res_redacted,
        category=DataCategory.EMAIL_DELIVERY_LOG,
        category_basis="test",
        subject_identifiers=["target_user@test.com"],
    )
    assert res_eval_redacted.outcome == PolicyComplianceOutcome.SATISFIED


def test_failed_coverage_prevents_unsupported_satisfaction(policy_engine: PolicyDecisionEngine):
    """Failed or deferred file coverage prevents unsupported satisfaction."""
    recon = CaseStateReconstruction(
        case_id="case_cov",
        audit_at=_dt("2026-09-10T12:00:00Z"),
        is_diagnostic_mode=True,
        resources={},
        diagnostics=StateDiagnostics(
            case_id="case_cov",
            audit_at=_dt("2026-09-10T12:00:00Z"),
            deferred_files=["evidence_99.pdf"],
            unreadable_or_failed_files=[],
        ),
    )
    assessment = policy_engine.assess_case(recon=recon, diagnostic=True)
    assert assessment.overall_compliance == PolicyComplianceOutcome.UNDETERMINED
    assert "evidence_99.pdf" in assessment.coverage_limitations


def test_shuffled_input_determinism(policy_engine: PolicyDecisionEngine):
    """Engine produces identical semantic assessments under shuffled input."""
    import random

    recon = CaseStateReconstruction(
        case_id="case_det",
        audit_at=_dt("2026-09-10T12:00:00Z"),
        is_diagnostic_mode=True,
        resources={},
        diagnostics=StateDiagnostics(case_id="case_det", audit_at=_dt("2026-09-10T12:00:00Z")),
    )
    a1 = policy_engine.assess_case(recon=recon, diagnostic=True)
    a2 = policy_engine.assess_case(recon=recon, diagnostic=True)
    assert a1.overall_compliance == a2.overall_compliance
    assert a1.violations_summary == a2.violations_summary
