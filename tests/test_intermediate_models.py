"""Tests for intermediate models ensuring unknown fields remain unknown."""

from datetime import datetime, timezone

from ghost_audit.models.intermediate_models import (
    EvidenceObservation,
    IdentityResolutionResult,
    IdentityResolutionStatus,
    ResourceAssessment,
)


def test_identity_resolution_result_defaults():
    res = IdentityResolutionResult()
    assert res.resolution_status == IdentityResolutionStatus.UNRESOLVED
    assert res.stable_subject_reference is None
    assert res.current_identifiers == {}
    assert res.historical_identifiers == []
    assert res.supporting_references == []
    assert res.applicable_timestamps == {}


def test_evidence_observation_structure():
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    obs = EvidenceObservation(
        evidence_id="evidence_01",
        source_locator="line:42",
        capture_time=now,
        system_id="account_service",
        resource_id="account_005",
        extracted_facts={"email": "test@example.com"},
        extraction_method="LOG_PARSER",
        uncertainty_or_warnings=["low confidence"],
    )
    assert obs.evidence_id == "evidence_01"
    assert obs.source_locator == "line:42"
    assert obs.system_id == "account_service"
    assert obs.resource_id == "account_005"
    assert obs.extracted_facts["email"] == "test@example.com"
    assert obs.uncertainty_or_warnings == ["low confidence"]


def test_resource_assessment_structure():
    assess = ResourceAssessment(
        system_id="search_service",
        resource_id="search_001",
        data_category="SEARCH_INDEX_ENTRY",
        observed_state="PRESENT",
        supporting_observations=["evidence_57"],
        applicable_policy_rule_id="rule_03",
        unresolved_questions=["Replication delay unknown"],
    )
    assert assess.system_id == "search_service"
    assert assess.observed_state == "PRESENT"
    assert assess.applicable_policy_rule_id == "rule_03"
