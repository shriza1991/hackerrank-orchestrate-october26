"""Submission-blocker regressions spanning planner, runner, cache, and usage boundaries."""

from __future__ import annotations

import json
from decimal import Decimal
from datetime import datetime, timezone

import pytest

from ghost_audit.config import Settings
from ghost_audit.intent.models import IntentDecision, IntentReason
from ghost_audit.intent.prompt import PROMPT_VERSION
from ghost_audit.intent.service import request_text_digest
from ghost_audit.llm.errors import ConfigurationError
from ghost_audit.llm.types import UsageRecord
from ghost_audit.llm.usage import UsageTracker
from ghost_audit.models.input_models import DataCategory, RequiredAction
from ghost_audit.models.output_models import DeletionStatus, StepOperation
from ghost_audit.planner.service import AuditPlanGenerator, extract_participant_evidence_id
from ghost_audit.policy.models import (
    CasePolicyAssessment,
    CopyPolicyAssessment,
    PolicyComplianceOutcome,
    ProcessRiskAssessment,
    ResourcePolicyAssessment,
    RestoreRiskAssessment,
)
from ghost_audit.runner import AuditPipelineRunner
from ghost_audit.state.models import CaseStateReconstruction


@pytest.fixture
def sample_cutoff():
    return datetime(2026, 6, 1, tzinfo=timezone.utc)


def _assessment(cutoff, resource, *, process_risks=None, restore_risks=None):
    return CasePolicyAssessment(
        case_id="case_safety", audit_at=cutoff, is_authorized_deletion=True,
        intent_status="AUTHORIZED_DELETION", resources={resource.canonical_key: resource},
        process_risks=process_risks or [], restore_risks=restore_risks or [],
        overall_compliance=PolicyComplianceOutcome.VIOLATED,
    )


def _resource(action, outcome=PolicyComplianceOutcome.VIOLATED):
    copy = CopyPolicyAssessment(
        copy_key="backup_service:backup_1[DATABASE_BACKUP]", system_id="backup_service",
        resource_id="backup_1", copy_type="DATABASE_BACKUP", required_action=action,
        outcome=outcome, evidence_references=["evidence_10"],
    )
    return ResourcePolicyAssessment(
        system_id="backup_service", resource_id="backup_1",
        canonical_key="backup_service:backup_1", data_category=DataCategory.BACKUP_ARCHIVE,
        required_action=action, copies={copy.copy_key: copy}, outcome=outcome,
    )


def test_retain_violation_never_generates_delete(sample_cutoff):
    planner = AuditPlanGenerator()
    plan = planner.generate_plan(
        _assessment(sample_cutoff, _resource(RequiredAction.RETAIN)),
        CaseStateReconstruction(case_id="case_safety", audit_at=sample_cutoff),
    )
    assert plan.is_unresolved
    assert all(step.operation != StepOperation.DELETE_RECORD for step in plan.internal_steps)
    assert "no grounded repair operation" in plan.unresolved_reasons[0]


def test_retained_backup_restore_safety_is_planned_separately(sample_cutoff):
    retained = _resource(RequiredAction.RETAIN, PolicyComplianceOutcome.SATISFIED)
    restore = RestoreRiskAssessment(
        backup_id="backup_1", system_id="backup_service", target_resource="backup_1",
        is_blocked=False, supporting_evidence=["evidence_10"], details="Restore allowed",
    )
    plan = AuditPlanGenerator().generate_plan(
        _assessment(sample_cutoff, retained, restore_risks=[restore]),
        CaseStateReconstruction(case_id="case_safety", audit_at=sample_cutoff),
    )
    operations = [step.operation for step in plan.steps]
    assert StepOperation.BLOCK_RESTORE in operations
    assert StepOperation.VERIFY_RESTORE_BLOCKED in operations
    assert StepOperation.VERIFY_RECORD_PRESENT in operations
    assert StepOperation.DELETE_RECORD not in operations


def test_unknown_action_is_unresolved_not_delete(sample_cutoff):
    plan = AuditPlanGenerator().generate_plan(
        _assessment(sample_cutoff, _resource(None)),
        CaseStateReconstruction(case_id="case_safety", audit_at=sample_cutoff),
    )
    assert plan.is_unresolved
    assert "Unknown required action" in plan.unresolved_reasons[0]


def test_citation_ids_require_exact_participant_visible_identifier():
    allowed = {"evidence_10", "activity_7", "audit_3"}
    assert extract_participant_evidence_id("evidence_10", allowed) == "evidence_10"
    for invalid in ("obs_evidence_10_row_2", "resource_10", "10", "unknown", "evidence_999"):
        assert extract_participant_evidence_id(invalid, allowed) == ""


def test_grounded_execution_dependencies_are_separate_from_output_order(sample_cutoff):
    copy = CopyPolicyAssessment(
        copy_key="search_service:doc_1[PRIMARY]", system_id="search_service",
        resource_id="doc_1", copy_type="PRIMARY", required_action=RequiredAction.DELETE,
        outcome=PolicyComplianceOutcome.VIOLATED, evidence_references=["evidence_8"],
    )
    resource = ResourcePolicyAssessment(
        system_id="search_service", resource_id="doc_1", canonical_key="search_service:doc_1",
        data_category=DataCategory.SEARCH_INDEX_ENTRY, required_action=RequiredAction.DELETE,
        copies={copy.copy_key: copy}, outcome=PolicyComplianceOutcome.VIOLATED,
    )
    flow = ProcessRiskAssessment(
        process_id="flow_1", system_id="integration_service", target_resource="doc_1",
        is_active=True, supporting_evidence=["evidence_13"],
    )
    plan = AuditPlanGenerator().generate_plan(
        _assessment(sample_cutoff, resource, process_risks=[flow]),
        CaseStateReconstruction(case_id="case_safety", audit_at=sample_cutoff),
    )
    delete_node = "DELETE_RECORD:search_service:doc_1"
    assert plan.execution_graph[delete_node] == ["DISABLE_DATA_FLOW:integration_service:flow_1"]
    assert [step.step_no for step in plan.steps] == list(range(1, len(plan.steps) + 1))


def _cache_for_request(request, decision="NON_DELETION"):
    reason = "EXPLICIT_NON_DELETION" if decision == "NON_DELETION" else "DIRECT_DELETION"
    return {
        "version": 1,
        "classifications": {
            request.case_id: {
                "request_text_sha256": request_text_digest(request.request_text),
                "prompt_version": PROMPT_VERSION,
                "provider": "test-provider",
                "model": "test-model",
                "intent": {
                    "decision": decision,
                    "reason_code": reason,
                    "supporting_quote": request.request_text,
                    "explanation": "Validated fixture classification.",
                },
            }
        },
    }


def test_malformed_and_stale_intent_caches_are_rejected(tmp_path, real_dataset_dir):
    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"case_01":{"decision":"DELETION_REQUEST"}}', encoding="utf-8")
    with pytest.raises(ConfigurationError, match="Invalid intent cache"):
        AuditPipelineRunner(Settings(real_dataset_dir), intent_cache_path=malformed)

    from ghost_audit.loader import DataLoader
    request = DataLoader(Settings(real_dataset_dir)).load_bundle(sample=True).requests[0]
    cache = _cache_for_request(request)
    cache["classifications"][request.case_id]["request_text_sha256"] = "0" * 64
    stale = tmp_path / "stale.json"
    stale.write_text(json.dumps(cache), encoding="utf-8")
    runner = AuditPipelineRunner(Settings(real_dataset_dir), intent_cache_path=stale)
    with pytest.raises(ConfigurationError, match="request-text mismatch"):
        runner.run(case_id=request.case_id, sample=True)


def test_runner_confirmed_non_deletion_and_missing_classification_are_distinct(
    tmp_path, real_dataset_dir
):
    from ghost_audit.loader import DataLoader
    settings = Settings(real_dataset_dir)
    request = DataLoader(settings).load_bundle(sample=True).requests[0]
    cache_path = tmp_path / "intent.json"
    cache_path.write_text(json.dumps(_cache_for_request(request)), encoding="utf-8")

    rows, summary = AuditPipelineRunner(settings, intent_cache_path=cache_path).run(
        case_id=request.case_id, sample=True
    )
    assert summary.unresolved_cases == 0
    assert rows[0].deletion_status == DeletionStatus.NOT_APPLICABLE

    rows, summary = AuditPipelineRunner(settings).run(case_id=request.case_id, sample=True)
    assert rows == [] and summary.unresolved_cases == 1
    assert "intent classification" in " ".join(summary.unresolved_details[request.case_id]).lower()


def test_diagnostic_root_write_is_rejected_and_existing_file_preserved(
    tmp_path, real_dataset_dir, monkeypatch
):
    import ghost_audit.runner as runner_module

    monkeypatch.setattr(runner_module, "REPO_ROOT", tmp_path)
    root_output = tmp_path / "output.csv"
    original = "case_id,deletion_status,steps_json\nprotected,COMPLETE,[]\n"
    root_output.write_text(original, encoding="utf-8")
    runner = AuditPipelineRunner(Settings(real_dataset_dir), diagnostic=True)
    with pytest.raises(RuntimeError, match="complete, non-diagnostic"):
        runner.run(case_id="case_01", sample=True, output_file=root_output)
    assert root_output.read_text(encoding="utf-8") == original
    assert not list(tmp_path.glob("tmp*"))


def test_usage_json_persists_attempts_decimal_and_parent_directory(tmp_path):
    tracker = UsageTracker()
    tracker.add(UsageRecord(
        logical_request_id="run:1", run_id="run", task_name="intent", case_id="case_1",
        attempt_id="run:1:1", outcome="SUCCESS", provider="provider", requested_model="m",
        provider_model="served", input_tokens=10, output_tokens=4, input_details={},
        output_details={}, estimated_cost=Decimal("0.00001230"), new_api_request=True,
    ))
    path = tmp_path / "nested" / "usage.json"
    tracker.write_json(path, run_provenance={"run_id": "run"})
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["attempts"][0]["estimated_cost"] == "0.00001230"
    assert payload["summary"]["overall"]["estimated_cost"] == "0.00001230"
    assert payload["run_provenance"] == {"run_id": "run"}
