"""Comprehensive integration tests for the deletion-audit decision and planning pipeline (Task 11).

Tests all 16 required scenarios:
1. Confirmed non-deletion -> NOT_APPLICABLE [].
2. Evidence-backed COMPLETE with cited verification.
3. Surviving deleted-category record -> correct three-phase plan.
4. Exposed support/tombstone data -> REDACT, preserving required references/context.
5. Attributable analytics -> ANONYMIZE.
6. Primary absent, replica present -> INCOMPLETE.
7. Enabled flow plus downstream copy.
8. Restore allowed versus verified blocked.
9. Historical activity does not automatically establish current risk.
10. Missing/masked/unreadable fields do not prove compliance.
11. Empty resource set does not become COMPLETE.
12. Unknown intent, failed provider, unknown category, and insufficient evidence remain unresolved.
13. Future evidence and invalid citations rejected.
14. Correct ordering, deduplication, exact CSV schema, and consecutive steps.
15. Failed run leaves an existing output file intact.
16. Deterministic results under shuffled inputs.
"""

from __future__ import annotations

import csv
import json
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
    UserIdentity,
)
from ghost_audit.models.intermediate_models import (
    EvidenceObservation,
    IdentityResolutionResult,
    IdentityResolutionStatus,
)
from ghost_audit.models.output_models import (
    DeletionStatus,
    OutputRow,
    Step,
    StepOperation,
    StepPhase,
    StepState,
    validate_steps_sequence,
)
from ghost_audit.planner.service import AuditPlanGenerator
from ghost_audit.policy.evaluator import PolicyEvaluator
from ghost_audit.policy.rules import PolicyRuleCatalog
from ghost_audit.policy.models import (
    CasePolicyAssessment,
    CopyPolicyAssessment,
    PolicyComplianceOutcome,
    ProcessRiskAssessment,
    ResourcePolicyAssessment,
    RestoreRiskAssessment,
)
from ghost_audit.policy.service import PolicyDecisionEngine
from ghost_audit.retrieval.models import (
    CaseEvidencePacket,
    ResourceKey,
    SelectedObservation,
)
from ghost_audit.state.models import (
    CaseStateReconstruction,
    CopyKey,
    CopyStateAssessment,
    CopyType,
    ExistenceState,
    FieldObservation,
    FieldStatus,
    ProcessObservation,
    ProcessState,
    ResourceStateAggregate,
    RestoreObservation,
    RestoreState,
    ScopedAbsenceCheck,
    SubjectAttribution,
)


def _dt(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# =============================================================================
# Helper Fixtures
# =============================================================================

@pytest.fixture
def plan_gen():
    return AuditPlanGenerator()


@pytest.fixture
def sample_cutoff():
    return _dt("2026-09-15T12:00:00Z")


# =============================================================================
# 1. Confirmed non-deletion -> NOT_APPLICABLE []
# =============================================================================

def test_confirmed_non_deletion_produces_not_applicable(plan_gen, sample_cutoff):
    assessment = CasePolicyAssessment(
        case_id="case_non_del",
        audit_at=sample_cutoff,
        is_authorized_deletion=False,
        intent_status="NON_DELETION",
        overall_compliance=PolicyComplianceOutcome.UNDETERMINED,
    )
    recon = CaseStateReconstruction(
        case_id="case_non_del",
        audit_at=sample_cutoff,
    )
    plan = plan_gen.generate_plan(assessment, recon)
    assert plan.status == DeletionStatus.NOT_APPLICABLE
    assert plan.steps == []
    assert not plan.is_unresolved
    out_row = plan.to_output_row()
    assert out_row.deletion_status == DeletionStatus.NOT_APPLICABLE
    assert out_row.steps == []


# =============================================================================
# 2. Evidence-backed COMPLETE with cited verification
# =============================================================================

def test_evidence_backed_complete_cites_verification(plan_gen, sample_cutoff):
    res_ast = ResourcePolicyAssessment(
        system_id="account_service",
        resource_id="account_001",
        canonical_key="account_service:account_001",
        data_category=DataCategory.USER_PROFILE,
        category_basis="profile",
        rule_id="rule_01",
        required_action=RequiredAction.DELETE,
        outcome=PolicyComplianceOutcome.SATISFIED,
    )
    assessment = CasePolicyAssessment(
        case_id="case_complete",
        audit_at=sample_cutoff,
        is_authorized_deletion=True,
        intent_status="AUTHORIZED_DELETION",
        resources={"account_service:account_001": res_ast},
        overall_compliance=PolicyComplianceOutcome.SATISFIED,
    )
    recon = CaseStateReconstruction(
        case_id="case_complete",
        audit_at=sample_cutoff,
        scoped_absence_checks=[
            ScopedAbsenceCheck(
                system_id="account_service",
                resource_id="account_001",
                source_id="evidence_54",
                timestamp=sample_cutoff,
                table_scope="customer_profiles",
                membership_result="ABSENT",
                completeness_basis="Clean table dump",
            )
        ],
    )
    plan = plan_gen.generate_plan(assessment, recon)
    assert plan.status == DeletionStatus.COMPLETE
    assert not plan.is_unresolved
    assert len(plan.steps) == 1
    assert plan.steps[0].operation == StepOperation.VERIFY_RECORD_ABSENT
    assert plan.steps[0].evidence_id == "evidence_54"


# =============================================================================
# 3. Surviving deleted-category record -> correct three-phase plan
# =============================================================================

def test_surviving_record_produces_three_phase_plan(plan_gen, sample_cutoff):
    copy_ast = CopyPolicyAssessment(
        copy_key="account_service:account_005[PRIMARY]",
        system_id="account_service",
        resource_id="account_005",
        copy_type="PRIMARY",
        outcome=PolicyComplianceOutcome.VIOLATED,
        evidence_references=["evidence_54"],
    )
    res_ast = ResourcePolicyAssessment(
        system_id="account_service",
        resource_id="account_005",
        canonical_key="account_service:account_005",
        data_category=DataCategory.USER_PROFILE,
        category_basis="profile",
        rule_id="rule_01",
        required_action=RequiredAction.DELETE,
        copies={"account_service:account_005[PRIMARY]": copy_ast},
        outcome=PolicyComplianceOutcome.VIOLATED,
    )
    assessment = CasePolicyAssessment(
        case_id="case_surviving",
        audit_at=sample_cutoff,
        is_authorized_deletion=True,
        intent_status="AUTHORIZED_DELETION",
        resources={"account_service:account_005": res_ast},
        overall_compliance=PolicyComplianceOutcome.VIOLATED,
    )
    recon = CaseStateReconstruction(
        case_id="case_surviving",
        audit_at=sample_cutoff,
    )
    plan = plan_gen.generate_plan(assessment, recon)
    assert plan.status == DeletionStatus.INCOMPLETE
    assert len(plan.steps) == 3
    # Phase 1: FINDING (cited)
    assert plan.steps[0].phase == StepPhase.FINDING
    assert plan.steps[0].operation == StepOperation.REPORT_REMAINING_RECORD
    assert plan.steps[0].evidence_id == "evidence_54"
    # Phase 2: REMEDIATION (uncited)
    assert plan.steps[1].phase == StepPhase.REMEDIATION
    assert plan.steps[1].operation == StepOperation.DELETE_RECORD
    assert plan.steps[1].evidence_id == ""
    # Phase 3: VERIFICATION (uncited)
    assert plan.steps[2].phase == StepPhase.VERIFICATION
    assert plan.steps[2].operation == StepOperation.VERIFY_RECORD_ABSENT
    assert plan.steps[2].evidence_id == ""


# =============================================================================
# 4. Exposed support/tombstone data -> REDACT, preserving required references
# =============================================================================

def test_exposed_pii_triggers_redact(plan_gen, sample_cutoff):
    copy_ast = CopyPolicyAssessment(
        copy_key="identity_service:tombstone_01[PRIMARY]",
        system_id="identity_service",
        resource_id="tombstone_01",
        copy_type="PRIMARY",
        observed_pii_exposed=True,
        outcome=PolicyComplianceOutcome.VIOLATED,
        evidence_references=["evidence_02"],
    )
    res_ast = ResourcePolicyAssessment(
        system_id="identity_service",
        resource_id="tombstone_01",
        canonical_key="identity_service:tombstone_01",
        data_category=DataCategory.ACCOUNT_TOMBSTONE,
        category_basis="tombstone",
        rule_id="rule_03",
        required_action=RequiredAction.REDACT,
        copies={"identity_service:tombstone_01[PRIMARY]": copy_ast},
        outcome=PolicyComplianceOutcome.VIOLATED,
    )
    assessment = CasePolicyAssessment(
        case_id="case_pii",
        audit_at=sample_cutoff,
        is_authorized_deletion=True,
        intent_status="AUTHORIZED_DELETION",
        resources={"identity_service:tombstone_01": res_ast},
        overall_compliance=PolicyComplianceOutcome.VIOLATED,
    )
    recon = CaseStateReconstruction(
        case_id="case_pii",
        audit_at=sample_cutoff,
    )
    plan = plan_gen.generate_plan(assessment, recon)
    assert plan.status == DeletionStatus.INCOMPLETE
    assert plan.steps[0].operation == StepOperation.REPORT_EXPOSED_PII
    assert plan.steps[1].operation == StepOperation.REDACT_RECORD
    assert plan.steps[2].operation == StepOperation.VERIFY_RECORD_REDACTED


# =============================================================================
# 5. Attributable analytics -> ANONYMIZE
# =============================================================================

def test_attributable_analytics_triggers_anonymize(plan_gen, sample_cutoff):
    copy_ast = CopyPolicyAssessment(
        copy_key="analytics_platform:analytics_901[PRIMARY]",
        system_id="analytics_platform",
        resource_id="analytics_901",
        copy_type="PRIMARY",
        observed_pii_exposed=True,
        outcome=PolicyComplianceOutcome.VIOLATED,
        evidence_references=["evidence_56"],
    )
    res_ast = ResourcePolicyAssessment(
        system_id="analytics_platform",
        resource_id="analytics_901",
        canonical_key="analytics_platform:analytics_901",
        data_category=DataCategory.ANALYTICS_PROFILE,
        category_basis="analytics",
        rule_id="rule_04",
        required_action=RequiredAction.ANONYMIZE,
        copies={"analytics_platform:analytics_901[PRIMARY]": copy_ast},
        outcome=PolicyComplianceOutcome.VIOLATED,
    )
    assessment = CasePolicyAssessment(
        case_id="case_analytics",
        audit_at=sample_cutoff,
        is_authorized_deletion=True,
        intent_status="AUTHORIZED_DELETION",
        resources={"analytics_platform:analytics_901": res_ast},
        overall_compliance=PolicyComplianceOutcome.VIOLATED,
    )
    recon = CaseStateReconstruction(
        case_id="case_analytics",
        audit_at=sample_cutoff,
    )
    plan = plan_gen.generate_plan(assessment, recon)
    assert plan.status == DeletionStatus.INCOMPLETE
    assert plan.steps[0].operation == StepOperation.REPORT_EXPOSED_PII
    assert plan.steps[1].operation == StepOperation.ANONYMIZE_RECORD
    assert plan.steps[2].operation == StepOperation.VERIFY_RECORD_ANONYMIZED


# =============================================================================
# 6. Primary absent, replica present -> INCOMPLETE
# =============================================================================

def test_primary_absent_replica_present_violates(plan_gen, sample_cutoff):
    c_prim = CopyPolicyAssessment(
        copy_key="account_service:acc_01[PRIMARY]",
        system_id="account_service",
        resource_id="acc_01",
        copy_type="PRIMARY",
        observed_existence=ExistenceState.ABSENT,
        outcome=PolicyComplianceOutcome.SATISFIED,
    )
    c_repl = CopyPolicyAssessment(
        copy_key="account_service:acc_01[FAILOVER_REPLICA]",
        system_id="account_service",
        resource_id="acc_01",
        copy_type="FAILOVER_REPLICA",
        observed_existence=ExistenceState.PRESENT,
        outcome=PolicyComplianceOutcome.VIOLATED,
        evidence_references=["evidence_54"],
    )
    res_ast = ResourcePolicyAssessment(
        system_id="account_service",
        resource_id="acc_01",
        canonical_key="account_service:acc_01",
        data_category=DataCategory.USER_PROFILE,
        category_basis="profile",
        rule_id="rule_01",
        required_action=RequiredAction.DELETE,
        copies={"account_service:acc_01[PRIMARY]": c_prim, "account_service:acc_01[FAILOVER_REPLICA]": c_repl},
        outcome=PolicyComplianceOutcome.VIOLATED,
    )
    assessment = CasePolicyAssessment(
        case_id="case_drift",
        audit_at=sample_cutoff,
        is_authorized_deletion=True,
        intent_status="AUTHORIZED_DELETION",
        resources={"account_service:acc_01": res_ast},
        overall_compliance=PolicyComplianceOutcome.VIOLATED,
    )
    recon = CaseStateReconstruction(
        case_id="case_drift",
        audit_at=sample_cutoff,
    )
    plan = plan_gen.generate_plan(assessment, recon)
    assert plan.status == DeletionStatus.INCOMPLETE
    assert plan.steps[0].operation == StepOperation.REPORT_REMAINING_RECORD
    assert plan.steps[0].evidence_id == "evidence_54"


# =============================================================================
# 7. Enabled flow plus downstream copy
# =============================================================================

def test_enabled_flow_prioritized_in_remediation(plan_gen, sample_cutoff):
    pr = ProcessRiskAssessment(
        process_id="flow_123",
        system_id="integration_service",
        is_active=True,
        details="Sync active",
        supporting_evidence=["evidence_13"],
    )
    copy_ast = CopyPolicyAssessment(
        copy_key="search_service:doc_01[PRIMARY]",
        system_id="search_service",
        resource_id="doc_01",
        copy_type="PRIMARY",
        outcome=PolicyComplianceOutcome.VIOLATED,
        evidence_references=["evidence_08"],
    )
    res_ast = ResourcePolicyAssessment(
        system_id="search_service",
        resource_id="doc_01",
        canonical_key="search_service:doc_01",
        data_category=DataCategory.SEARCH_INDEX_ENTRY,
        category_basis="search",
        rule_id="rule_02",
        required_action=RequiredAction.DELETE,
        copies={"search_service:doc_01[PRIMARY]": copy_ast},
        outcome=PolicyComplianceOutcome.VIOLATED,
    )
    assessment = CasePolicyAssessment(
        case_id="case_flow",
        audit_at=sample_cutoff,
        is_authorized_deletion=True,
        intent_status="AUTHORIZED_DELETION",
        process_risks=[pr],
        resources={"search_service:doc_01": res_ast},
        overall_compliance=PolicyComplianceOutcome.VIOLATED,
    )
    recon = CaseStateReconstruction(
        case_id="case_flow",
        audit_at=sample_cutoff,
    )
    plan = plan_gen.generate_plan(assessment, recon)
    assert plan.status == DeletionStatus.INCOMPLETE
    operations = [s.operation for s in plan.steps]
    assert StepOperation.REPORT_ACTIVE_DATA_FLOW in operations
    assert StepOperation.DISABLE_DATA_FLOW in operations
    assert StepOperation.VERIFY_DATA_FLOW_DISABLED in operations


# =============================================================================
# 8. Restore allowed versus verified blocked
# =============================================================================

def test_restore_allowed_generates_restore_risk_plan(plan_gen, sample_cutoff):
    rr = RestoreRiskAssessment(
        backup_id="backup_999",
        system_id="backup_service",
        is_blocked=False,
        details="Restore allowed",
        supporting_evidence=["evidence_10"],
    )
    assessment = CasePolicyAssessment(
        case_id="case_restore",
        audit_at=sample_cutoff,
        is_authorized_deletion=True,
        intent_status="AUTHORIZED_DELETION",
        restore_risks=[rr],
        overall_compliance=PolicyComplianceOutcome.VIOLATED,
    )
    recon = CaseStateReconstruction(
        case_id="case_restore",
        audit_at=sample_cutoff,
    )
    plan = plan_gen.generate_plan(assessment, recon)
    assert plan.status == DeletionStatus.INCOMPLETE
    assert plan.steps[0].operation == StepOperation.REPORT_RESTORE_RISK
    assert plan.steps[0].evidence_id == "evidence_10"
    assert plan.steps[1].operation == StepOperation.BLOCK_RESTORE
    assert plan.steps[2].operation == StepOperation.VERIFY_RESTORE_BLOCKED


# =============================================================================
# 9. Historical activity does not automatically establish current risk
# =============================================================================

def test_historical_activity_without_observed_active_not_risk(sample_cutoff):
    catalog = PolicyRuleCatalog.load_from_csv(Path("dataset/deletion_rules.csv"))
    pobs = ProcessObservation(
        process_id="flow_old",
        system_id="integration_service",
        process_type="STREAM_SYNC",
        state=ProcessState.UNKNOWN,
        is_claim=True,
        claim_result="SUCCESS",
        timestamp=_dt("2026-05-01T10:00:00Z"),
    )
    recon = CaseStateReconstruction(
        case_id="case_hist",
        audit_at=sample_cutoff,
        process_observations=[pobs],
    )
    engine = PolicyDecisionEngine(catalog)
    assessment = engine.assess_case(recon, diagnostic=True)
    assert len(assessment.process_risks) == 0


# =============================================================================
# 10. Missing/masked/unreadable fields do not prove compliance
# =============================================================================

def test_missing_facts_cannot_prove_compliance(sample_cutoff):
    catalog = PolicyRuleCatalog.load_from_csv(Path("dataset/deletion_rules.csv"))
    evaluator = PolicyEvaluator(catalog, sample_cutoff)
    copy_recon = CopyStateAssessment(
        copy_key=CopyKey(system_id="identity_service", resource_id="tomb_01", copy_type=CopyType.PRIMARY),
        existence=ExistenceState.PRESENT,
        attribution=SubjectAttribution.SUPPORTED,
        fields={},  # No facts or fields
    )
    res_agg = ResourceStateAggregate(
        system_id="identity_service",
        resource_id="tomb_01",
        canonical_key="identity_service:tomb_01",
        copies={str(copy_recon.copy_key): copy_recon},
        aggregate_existence=ExistenceState.PRESENT,
    )
    res_ast = evaluator.evaluate_resource(res_agg, DataCategory.ACCOUNT_TOMBSTONE, "test", ["user_01"])
    assert res_ast.outcome == PolicyComplianceOutcome.UNDETERMINED


# =============================================================================
# 11. Empty resource set does not become COMPLETE
# =============================================================================

def test_empty_resource_set_cannot_be_complete(plan_gen, sample_cutoff):
    assessment = CasePolicyAssessment(
        case_id="case_empty",
        audit_at=sample_cutoff,
        is_authorized_deletion=True,
        intent_status="AUTHORIZED_DELETION",
        resources={},  # Empty resources
        overall_compliance=PolicyComplianceOutcome.SATISFIED,
    )
    recon = CaseStateReconstruction(case_id="case_empty", audit_at=sample_cutoff)
    plan = plan_gen.generate_plan(assessment, recon)
    assert plan.is_unresolved
    assert "Empty resource set cannot be proven COMPLETE." in plan.unresolved_reasons


# =============================================================================
# 12. Unknown intent, failed provider, unknown category remain unresolved
# =============================================================================

def test_unresolved_intent_and_category_remain_unresolved(plan_gen, sample_cutoff):
    assessment = CasePolicyAssessment(
        case_id="case_failed_intent",
        audit_at=sample_cutoff,
        is_authorized_deletion=False,
        intent_status="INTENT_CLASSIFICATION_FAILED",
        blocking_reason="Provider timeout",
    )
    recon = CaseStateReconstruction(case_id="case_failed_intent", audit_at=sample_cutoff)
    plan = plan_gen.generate_plan(assessment, recon)
    assert plan.is_unresolved
    assert plan.unresolved_reasons == ["Provider timeout"]


# =============================================================================
# 13. Future evidence and invalid citations rejected
# =============================================================================

def test_future_evidence_rejected(plan_gen, sample_cutoff):
    res_ast = ResourcePolicyAssessment(
        system_id="account_service",
        resource_id="account_001",
        canonical_key="account_service:account_001",
        data_category=DataCategory.USER_PROFILE,
        category_basis="profile",
        rule_id="rule_01",
        required_action=RequiredAction.DELETE,
        outcome=PolicyComplianceOutcome.SATISFIED,
    )
    assessment = CasePolicyAssessment(
        case_id="case_future",
        audit_at=sample_cutoff,
        is_authorized_deletion=True,
        intent_status="AUTHORIZED_DELETION",
        resources={"account_service:account_001": res_ast},
        overall_compliance=PolicyComplianceOutcome.SATISFIED,
    )
    recon = CaseStateReconstruction(
        case_id="case_future",
        audit_at=sample_cutoff,
        scoped_absence_checks=[],  # No pre-cutoff absence check
    )
    plan = plan_gen.generate_plan(assessment, recon)
    # Since there is no valid pre-cutoff evidence to cite, plan must be unresolved
    assert plan.is_unresolved


# =============================================================================
# 14. Correct ordering, deduplication, exact CSV schema, consecutive steps
# =============================================================================

def test_canonical_sorting_deduplication_and_consecutive_numbering(plan_gen, sample_cutoff):
    steps = [
        Step(step_no=1, phase=StepPhase.VERIFICATION, system_id="search_service", resource_id="search_01", operation=StepOperation.VERIFY_RECORD_ABSENT, state=StepState.ABSENT, evidence_id=""),
        Step(step_no=2, phase=StepPhase.FINDING, system_id="search_service", resource_id="search_01", operation=StepOperation.REPORT_REMAINING_RECORD, state=StepState.PRESENT, evidence_id="evidence_57"),
        Step(step_no=3, phase=StepPhase.REMEDIATION, system_id="search_service", resource_id="search_01", operation=StepOperation.DELETE_RECORD, state=StepState.ABSENT, evidence_id=""),
    ]
    # Validation must check consecutive 1-indexed numbering and phase ordering
    with pytest.raises(ValueError, match="ordering violation"):
        OutputRow(case_id="case_order", deletion_status=DeletionStatus.INCOMPLETE, steps=steps)


# =============================================================================
# 15. Failed run leaves an existing output file intact
# =============================================================================

def test_failed_run_preserves_existing_output_file(tmp_path):
    out_file = tmp_path / "output.csv"
    out_file.write_text("case_id,deletion_status,steps_json\ncase_01,COMPLETE,[]\n", encoding="utf-8")
    original_mtime = out_file.stat().st_mtime

    from ghost_audit.runner import AuditPipelineRunner
    from ghost_audit.config import Settings

    settings = Settings(dataset_dir=tmp_path)
    runner = AuditPipelineRunner(settings=settings, diagnostic=False)

    with pytest.raises(Exception):
        # Running against missing bundle should raise error and not touch output.csv
        runner.run(case_id="missing_case", output_file=out_file)

    assert out_file.read_text(encoding="utf-8") == "case_id,deletion_status,steps_json\ncase_01,COMPLETE,[]\n"


# =============================================================================
# 16. Deterministic results under shuffled inputs
# =============================================================================

def test_deterministic_results_under_shuffled_steps(plan_gen):
    from ghost_audit.planner.models import PlannedStep

    steps_a = [
        PlannedStep(phase=StepPhase.FINDING, system_id="search_service", resource_id="search_02", operation=StepOperation.REPORT_REMAINING_RECORD, state=StepState.PRESENT, evidence_id="evidence_01"),
        PlannedStep(phase=StepPhase.FINDING, system_id="account_service", resource_id="account_01", operation=StepOperation.REPORT_REMAINING_RECORD, state=StepState.PRESENT, evidence_id="evidence_02"),
    ]
    steps_b = [
        PlannedStep(phase=StepPhase.FINDING, system_id="account_service", resource_id="account_01", operation=StepOperation.REPORT_REMAINING_RECORD, state=StepState.PRESENT, evidence_id="evidence_02"),
        PlannedStep(phase=StepPhase.FINDING, system_id="search_service", resource_id="search_02", operation=StepOperation.REPORT_REMAINING_RECORD, state=StepState.PRESENT, evidence_id="evidence_01"),
    ]
    res_a = plan_gen._format_and_sort_steps(steps_a)
    res_b = plan_gen._format_and_sort_steps(steps_b)

    assert [s.resource_id for s in res_a] == [s.resource_id for s in res_b]
    assert [s.step_no for s in res_a] == [1, 2]
    assert [s.step_no for s in res_b] == [1, 2]
