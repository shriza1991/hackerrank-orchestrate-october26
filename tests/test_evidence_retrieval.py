"""Comprehensive unit and integration tests for Evidence Linking and Retrieval (Task 8).

Verifies exact matching, catalog aliases, temporal boundaries, cross-subject isolation,
cycle detection, determinism, and absence handling without external network or model calls.
"""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from ghost_audit.identity.index import IdentityIndex
from ghost_audit.identity.service import IdentityResolutionService
from ghost_audit.models.input_models import (
    DeletionRequest,
    ReportedResult,
    ReportedStatus,
    SystemActivityEvent,
    UserAuditLogEntry,
    UserIdentity,
)
from ghost_audit.models.intermediate_models import (
    EvidenceObservation,
    IdentityResolutionResult,
    IdentityResolutionStatus,
)
from ghost_audit.retrieval.index import CorpusIndex
from ghost_audit.retrieval.linker import EvidenceLinker
from ghost_audit.retrieval.models import (
    LinkRelationship,
    ResourceKey,
)
from ghost_audit.retrieval.service import EvidenceRetrievalService


def _dt(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def sample_user_bundle():
    identities = [
        UserIdentity(
            user_id="user_01",
            name="Elena Rostova",
            email="elena.current@example.com",
            phone="+15550100",
            email_hash="hash_elena_curr",
            updated_at=_dt("2026-08-01T10:00:00Z"),
        ),
        UserIdentity(
            user_id="user_02",
            name="Mateo Rios",
            email="mateo@example.com",
            phone="+15550200",
            email_hash="hash_mateo",
            updated_at=_dt("2026-08-01T10:00:00Z"),
        ),
    ]
    audit_logs = [
        UserAuditLogEntry(
            audit_id="audit_01",
            user_id="user_01",
            event_time=_dt("2026-05-01T12:00:00Z"),
            field_name="email",
            old_value="elena.old@example.com",
            new_value="elena.current@example.com",
        ),
        UserAuditLogEntry(
            audit_id="audit_02",
            user_id="user_01",
            event_time=_dt("2026-05-01T12:00:00Z"),
            field_name="phone",
            old_value="+15550199",
            new_value="+15550100",
        ),
    ]
    return identities, audit_logs


# =============================================================================
# Tests
# =============================================================================

def test_current_and_historical_identifier_matches(sample_user_bundle):
    """Subject matches observations with current email, historical email, and user_id."""
    identities, audit_logs = sample_user_bundle
    id_svc = IdentityResolutionService.from_data(identities, audit_logs)

    obs1 = EvidenceObservation(
        evidence_id="ev_01",
        capture_time=_dt("2026-08-10T10:00:00Z"),
        system_id="account_service",
        resource_id="acc_01",
        subject_references=["user_01"],
        source_locator="customer_profiles_primary",
    )
    obs2 = EvidenceObservation(
        evidence_id="ev_02",
        capture_time=_dt("2026-08-10T10:00:00Z"),
        system_id="support_platform",
        resource_id="supp_01",
        subject_references=["elena.old@example.com"],
        source_locator="ticket_55",
    )

    index = CorpusIndex(observations=[obs1, obs2], activity_events=[])
    retrieval_svc = EvidenceRetrievalService(index=index, identity_service=id_svc)

    req = DeletionRequest(
        case_id="case_01",
        email="elena.old@example.com",
        requested_at=_dt("2026-08-15T10:00:00Z"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=_dt("2026-08-16T10:00:00Z"),
        audit_at=_dt("2026-08-20T10:00:00Z"),
        request_text="Please delete my data.",
    )

    pkt = retrieval_svc.retrieve_for_case(req, diagnostic_mode=True)
    assert not pkt.is_blocked
    assert pkt.stable_subject_reference == "user_01"
    assert len(pkt.selected_observations) == 2
    assert "account_service:acc_01@customer_profiles_primary" in pkt.grounded_resources
    assert "support_platform:supp_01@ticket_55" in pkt.grounded_resources


def test_exact_boundaries_and_prefix_collisions(sample_user_bundle):
    """Exact string boundaries must prevent false substring matches (e.g. user_01 vs user_010)."""
    identities, audit_logs = sample_user_bundle
    id_svc = IdentityResolutionService.from_data(identities, audit_logs)

    obs_target = EvidenceObservation(
        evidence_id="ev_01",
        capture_time=_dt("2026-08-10T10:00:00Z"),
        system_id="account_service",
        resource_id="acc_01",
        subject_references=["user_01"],
    )
    obs_collision = EvidenceObservation(
        evidence_id="ev_02",
        capture_time=_dt("2026-08-10T10:00:00Z"),
        system_id="account_service",
        resource_id="acc_10",
        subject_references=["user_010", "not-elena.current@example.com", "elena.current@example.company"],
    )

    index = CorpusIndex(observations=[obs_target, obs_collision], activity_events=[])
    retrieval_svc = EvidenceRetrievalService(index=index, identity_service=id_svc)

    req = DeletionRequest(
        case_id="case_01",
        email="elena.current@example.com",
        requested_at=_dt("2026-08-15T10:00:00Z"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=_dt("2026-08-16T10:00:00Z"),
        audit_at=_dt("2026-08-20T10:00:00Z"),
        request_text="Please delete my account.",
    )

    pkt = retrieval_svc.retrieve_for_case(req, diagnostic_mode=True)
    assert len(pkt.selected_observations) == 1
    assert pkt.selected_observations[0].observation.evidence_id == "ev_01"


def test_catalog_aliases_and_attachments(sample_user_bundle):
    """LINK_RESOURCE_IDENTITY event establishes canonical resource and display/attachment alias."""
    identities, audit_logs = sample_user_bundle
    id_svc = IdentityResolutionService.from_data(identities, audit_logs)

    cat_event = SystemActivityEvent(
        activity_id="act_4001",
        event_time=_dt("2026-08-01T08:00:00Z"),
        event_type="LINK_RESOURCE_IDENTITY",
        source_system="data_catalog",
        target_system="object_storage",
        resource_id="obj_99",
        reported_result=ReportedResult.SUCCESS,
        details="Attachment catalog confirmed obj_99 (user_01_handover.pdf) belongs only to elena.current@example.com and user_01; no other subject is linked.",
    )
    obs = EvidenceObservation(
        evidence_id="ev_doc",
        capture_time=_dt("2026-08-05T08:00:00Z"),
        system_id="object_storage",
        resource_id="obj_99",
        extracted_facts={"file_name": "user_01_handover.pdf"},
    )

    index = CorpusIndex(observations=[obs], activity_events=[cat_event])
    retrieval_svc = EvidenceRetrievalService(index=index, identity_service=id_svc)

    req = DeletionRequest(
        case_id="case_01",
        email="elena.current@example.com",
        requested_at=_dt("2026-08-15T10:00:00Z"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=_dt("2026-08-16T10:00:00Z"),
        audit_at=_dt("2026-08-20T10:00:00Z"),
        request_text="Delete my data.",
    )

    pkt = retrieval_svc.retrieve_for_case(req, diagnostic_mode=True)
    assert "object_storage:obj_99" in pkt.grounded_resources
    assert any(l.provenance.relationship == LinkRelationship.CATALOG_RESOURCE_IDENTITY for l in pkt.linking_graph)
    assert len(pkt.selected_observations) == 1


def test_sanitized_record_linked_through_prior_resource(sample_user_bundle):
    """Anonymized analytics record without PII is retrieved via chained grounded resource reference."""
    identities, audit_logs = sample_user_bundle
    id_svc = IdentityResolutionService.from_data(identities, audit_logs)

    # obs1 has user_id and links to account_77
    obs1 = EvidenceObservation(
        evidence_id="ev_01",
        capture_time=_dt("2026-08-10T10:00:00Z"),
        system_id="account_service",
        resource_id="account_77",
        subject_references=["user_01"],
        extracted_facts={"linked_resources": ["analytics_99"]},
    )
    # obs2 is anonymized profile (no direct PII) but resource_id is analytics_99
    obs2 = EvidenceObservation(
        evidence_id="ev_02",
        capture_time=_dt("2026-08-11T10:00:00Z"),
        system_id="analytics_platform",
        resource_id="analytics_99",
        extracted_facts={"customer_reference": None, "email": None, "audience_cohort": "shopper"},
    )

    index = CorpusIndex(observations=[obs1, obs2], activity_events=[])
    retrieval_svc = EvidenceRetrievalService(index=index, identity_service=id_svc)

    req = DeletionRequest(
        case_id="case_01",
        email="elena.current@example.com",
        requested_at=_dt("2026-08-15T10:00:00Z"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=_dt("2026-08-16T10:00:00Z"),
        audit_at=_dt("2026-08-20T10:00:00Z"),
        request_text="Delete my account.",
    )

    pkt = retrieval_svc.retrieve_for_case(req, diagnostic_mode=True)
    assert "account_service:account_77" in pkt.grounded_resources
    assert "analytics_platform:analytics_99" in pkt.grounded_resources
    assert len(pkt.selected_observations) == 2


def test_zero_row_lookup_and_scoped_inventories(sample_user_bundle):
    """Zero-row readback log lookup and scoped inventories are properly preserved."""
    identities, audit_logs = sample_user_bundle
    id_svc = IdentityResolutionService.from_data(identities, audit_logs)

    lookup_obs = EvidenceObservation(
        evidence_id="ev_log",
        capture_time=_dt("2026-08-10T10:00:00Z"),
        system_id="account_service",
        resource_id="account_7566",
        subject_references=["elena.current@example.com"],
        extracted_facts={"rows": 0, "http_status": 404, "lookup_key": "elena.current@example.com"},
    )
    inv_obs = EvidenceObservation(
        evidence_id="ev_sql",
        capture_time=_dt("2026-08-10T10:00:00Z"),
        system_id="account_service",
        observation_type="INVENTORY_SCOPE",
        source_locator="customer_profiles_failover_replica",
        extracted_facts={"inventory": ["acc_02", "acc_03"]},
    )

    index = CorpusIndex(observations=[lookup_obs, inv_obs], activity_events=[])
    retrieval_svc = EvidenceRetrievalService(index=index, identity_service=id_svc)

    req = DeletionRequest(
        case_id="case_01",
        email="elena.current@example.com",
        requested_at=_dt("2026-08-15T10:00:00Z"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=_dt("2026-08-16T10:00:00Z"),
        audit_at=_dt("2026-08-20T10:00:00Z"),
        request_text="Delete my data.",
    )

    pkt = retrieval_svc.retrieve_for_case(req, diagnostic_mode=True)
    assert len(pkt.selected_observations) == 1
    assert pkt.selected_observations[0].observation.evidence_id == "ev_log"
    assert len(pkt.scoped_inventories) == 1
    assert pkt.scoped_inventories[0].source_id == "ev_sql"
    assert pkt.scoped_inventories[0].system_id == "account_service"


def test_different_subjects_sharing_file_table_page(sample_user_bundle):
    """Rows or records belonging to another subject must not be linked or merged."""
    identities, audit_logs = sample_user_bundle
    id_svc = IdentityResolutionService.from_data(identities, audit_logs)

    # Observation has matched phone (+15550100) but explicit user_id of user_02
    conflicting_obs = EvidenceObservation(
        evidence_id="ev_leak",
        capture_time=_dt("2026-08-10T10:00:00Z"),
        system_id="account_service",
        resource_id="acc_mateo",
        subject_references=["+15550100"],
        extracted_facts={"user_id": "user_02"},
    )

    index = CorpusIndex(observations=[conflicting_obs], activity_events=[])
    retrieval_svc = EvidenceRetrievalService(index=index, identity_service=id_svc)

    req = DeletionRequest(
        case_id="case_01",
        email="elena.current@example.com",
        requested_at=_dt("2026-08-15T10:00:00Z"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=_dt("2026-08-16T10:00:00Z"),
        audit_at=_dt("2026-08-20T10:00:00Z"),
        request_text="Delete my data.",
    )

    pkt = retrieval_svc.retrieve_for_case(req, diagnostic_mode=True)
    # Conflicting observation must be rejected and not selected
    assert len(pkt.selected_observations) == 0
    assert len(pkt.ambiguous_or_rejected_links) == 1
    assert "CROSS_USER_CONFLICT" in pkt.ambiguous_or_rejected_links[0].reason


def test_multiple_systems_reusing_resource_id(sample_user_bundle):
    """Resource IDs reused across systems must maintain distinct system context."""
    identities, audit_logs = sample_user_bundle
    id_svc = IdentityResolutionService.from_data(identities, audit_logs)

    obs_acc = EvidenceObservation(
        evidence_id="ev_01",
        capture_time=_dt("2026-08-10T10:00:00Z"),
        system_id="account_service",
        resource_id="res_01",
        subject_references=["user_01"],
    )
    obs_search = EvidenceObservation(
        evidence_id="ev_02",
        capture_time=_dt("2026-08-10T10:00:00Z"),
        system_id="search_service",
        resource_id="res_01",
        subject_references=["user_01"],
    )

    index = CorpusIndex(observations=[obs_acc, obs_search], activity_events=[])
    retrieval_svc = EvidenceRetrievalService(index=index, identity_service=id_svc)

    req = DeletionRequest(
        case_id="case_01",
        email="elena.current@example.com",
        requested_at=_dt("2026-08-15T10:00:00Z"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=_dt("2026-08-16T10:00:00Z"),
        audit_at=_dt("2026-08-20T10:00:00Z"),
        request_text="Delete my data.",
    )

    pkt = retrieval_svc.retrieve_for_case(req, diagnostic_mode=True)
    assert "account_service:res_01" in pkt.grounded_resources
    assert "search_service:res_01" in pkt.grounded_resources
    assert len(pkt.grounded_resources) == 2


def test_future_source_and_link_exclusion(sample_user_bundle):
    """Observations and activities occurring after audit_at cutoff must be strictly excluded."""
    identities, audit_logs = sample_user_bundle
    id_svc = IdentityResolutionService.from_data(identities, audit_logs)

    obs_past = EvidenceObservation(
        evidence_id="ev_past",
        capture_time=_dt("2026-08-10T10:00:00Z"),
        system_id="account_service",
        resource_id="acc_past",
        subject_references=["user_01"],
    )
    obs_future = EvidenceObservation(
        evidence_id="ev_future",
        capture_time=_dt("2026-08-25T10:00:00Z"),  # AFTER cutoff 2026-08-20
        system_id="account_service",
        resource_id="acc_future",
        subject_references=["user_01"],
    )
    act_past = SystemActivityEvent(
        activity_id="act_01",
        event_time=_dt("2026-08-12T10:00:00Z"),
        event_type="DELETE_RECORD",
        source_system="worker",
        target_system="account_service",
        resource_id="acc_past",
        reported_result=ReportedResult.SUCCESS,
        details="Deleted acc_past",
    )
    act_future = SystemActivityEvent(
        activity_id="act_02",
        event_time=_dt("2026-08-22T10:00:00Z"),  # AFTER cutoff
        event_type="DELETE_RECORD",
        source_system="worker",
        target_system="account_service",
        resource_id="acc_past",
        reported_result=ReportedResult.SUCCESS,
        details="Future deletion",
    )

    index = CorpusIndex(observations=[obs_past, obs_future], activity_events=[act_past, act_future])
    retrieval_svc = EvidenceRetrievalService(index=index, identity_service=id_svc)

    req = DeletionRequest(
        case_id="case_01",
        email="elena.current@example.com",
        requested_at=_dt("2026-08-15T10:00:00Z"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=_dt("2026-08-16T10:00:00Z"),
        audit_at=_dt("2026-08-20T10:00:00Z"),
        request_text="Delete my data.",
    )

    pkt = retrieval_svc.retrieve_for_case(req, diagnostic_mode=True)
    assert len(pkt.selected_observations) == 1
    assert pkt.selected_observations[0].observation.evidence_id == "ev_past"
    assert len(pkt.selected_activities) == 1
    assert pkt.selected_activities[0].activity_id == "act_01"
    assert pkt.diagnostics.total_future_observations_excluded == 1
    assert pkt.diagnostics.total_future_activities_excluded == 1


def test_cycle_detection_and_expansion_limits(sample_user_bundle):
    """Mutually referencing resources must be handled gracefully without infinite looping."""
    identities, audit_logs = sample_user_bundle
    id_svc = IdentityResolutionService.from_data(identities, audit_logs)

    # obs1: user_01 -> res_A -> links to res_B
    obs1 = EvidenceObservation(
        evidence_id="ev_01",
        capture_time=_dt("2026-08-10T10:00:00Z"),
        system_id="service_a",
        resource_id="res_A",
        subject_references=["user_01"],
        extracted_facts={"linked_resources": ["res_B"]},
    )
    # obs2: res_B -> links back to res_A (cycle!)
    obs2 = EvidenceObservation(
        evidence_id="ev_02",
        capture_time=_dt("2026-08-10T10:00:00Z"),
        system_id="service_b",
        resource_id="res_B",
        extracted_facts={"linked_resources": ["res_A"]},
    )

    index = CorpusIndex(observations=[obs1, obs2], activity_events=[])
    retrieval_svc = EvidenceRetrievalService(index=index, identity_service=id_svc, max_depth=3)

    req = DeletionRequest(
        case_id="case_01",
        email="elena.current@example.com",
        requested_at=_dt("2026-08-15T10:00:00Z"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=_dt("2026-08-16T10:00:00Z"),
        audit_at=_dt("2026-08-20T10:00:00Z"),
        request_text="Delete my data.",
    )

    pkt = retrieval_svc.retrieve_for_case(req, diagnostic_mode=True)
    assert "service_a:res_A" in pkt.grounded_resources
    assert "service_b:res_B" in pkt.grounded_resources
    assert len(pkt.diagnostics.cycles_detected) >= 1
    assert len(pkt.selected_observations) == 2


def test_determinism(sample_user_bundle):
    """Multiple retrieval runs on identical input must produce identical serialization."""
    identities, audit_logs = sample_user_bundle
    id_svc = IdentityResolutionService.from_data(identities, audit_logs)

    obs = EvidenceObservation(
        evidence_id="ev_01",
        capture_time=_dt("2026-08-10T10:00:00Z"),
        system_id="account_service",
        resource_id="acc_01",
        subject_references=["user_01"],
    )
    index = CorpusIndex(observations=[obs], activity_events=[])
    retrieval_svc = EvidenceRetrievalService(index=index, identity_service=id_svc)

    req = DeletionRequest(
        case_id="case_01",
        email="elena.current@example.com",
        requested_at=_dt("2026-08-15T10:00:00Z"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=_dt("2026-08-16T10:00:00Z"),
        audit_at=_dt("2026-08-20T10:00:00Z"),
        request_text="Delete my data.",
    )

    pkt1 = retrieval_svc.retrieve_for_case(req, diagnostic_mode=True)
    pkt2 = retrieval_svc.retrieve_for_case(req, diagnostic_mode=True)

    dump1 = pkt1.model_dump_json(exclude={"diagnostics": {"execution_time_ms"}})
    dump2 = pkt2.model_dump_json(exclude={"diagnostics": {"execution_time_ms"}})
    assert dump1 == dump2


def test_authorization_and_identity_blocking(sample_user_bundle):
    """Unresolved identities and non-deletion requests block packet generation."""
    identities, audit_logs = sample_user_bundle
    id_svc = IdentityResolutionService.from_data(identities, audit_logs)
    index = CorpusIndex(observations=[], activity_events=[])
    retrieval_svc = EvidenceRetrievalService(index=index, identity_service=id_svc)

    # Unknown email
    req_unknown = DeletionRequest(
        case_id="case_999",
        email="stranger@example.com",
        requested_at=_dt("2026-08-15T10:00:00Z"),
        reported_status=ReportedStatus.NOT_STARTED,
        reported_at=_dt("2026-08-16T10:00:00Z"),
        audit_at=_dt("2026-08-20T10:00:00Z"),
        request_text="Please delete my data.",
    )

    pkt = retrieval_svc.retrieve_for_case(req_unknown, diagnostic_mode=True)
    assert pkt.is_blocked
    assert pkt.identity_status == IdentityResolutionStatus.UNRESOLVED
    assert "IDENTITY_UNRESOLVED" in pkt.blocking_reason
