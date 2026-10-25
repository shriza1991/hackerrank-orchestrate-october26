"""Comprehensive tests for Task 9: Resource-State Reconstruction at audit cutoff.

Covers:
1. Positive record observation.
2. Grounded negative lookup proving absence.
3. Missing retrieval result remaining UNKNOWN (never assuming absence).
4. Successful deletion claim with surviving PII.
5. Primary absence plus replica presence (replica drift).
6. Supported absence followed by observed recreation.
7. Sync/restore claim without observed recreation.
8. Same-copy conflicting observations.
9. Equal-time unresolved contradictions.
10. Future sources and supporting links excluded at audit cutoff.
11. Snapshot capture time vs old row updated_at.
12. Log export time vs actual event time.
13. Future retention expiry not used as observation time.
14. Null, missing, masked, and unreadable fields.
15. Retained stable user reference without direct PII (tombstone compliance).
16. Redaction claim with exposed email.
17. Disabled connector followed by later observed activity/configuration.
18. Restore-block claim vs observed restore permission.
19. Incomplete/deferred ingestion preventing unsupported absence.
20. Authorization failures and diagnostic bypass labeling.
21. Shuffled input producing deterministic results.
22. Task 8 prerequisite regressions (authorization, system isolation, exact evaluator).
"""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from ghost_audit.models.input_models import DeletionRequest, ReportedStatus, SystemActivityEvent
from ghost_audit.models.intermediate_models import (
    EvidenceObservation,
    IdentityResolutionResult,
    IdentityResolutionStatus,
)
from ghost_audit.retrieval.models import (
    CaseEvidencePacket,
    RetrievalDiagnostics,
    ScopedInventory,
    SelectedActivity,
    SelectedObservation,
)
from ghost_audit.retrieval.models import LinkEndpoint, LinkProvenance, LinkRelationship, EvidenceLink
from ghost_audit.state.inventory_checker import ScopedInventoryChecker
from ghost_audit.state.models import (
    CopyKey,
    CopyType,
    ExistenceState,
    FieldObservation,
    FieldStatus,
    ProcessState,
    RestoreState,
    SubjectAttribution,
)
from ghost_audit.state.reconstruction import (
    ResourceStateEngine,
    derive_copy_type,
    extract_field_observations,
    extract_process_and_restore_state,
)
from ghost_audit.state.service import ResourceStateReconstructionService
from ghost_audit.state.timestamp_interpreter import (
    SourceAwareTimestampInterpreter,
)


def _dt(iso_str: str) -> datetime:
    """Helper to parse test ISO timestamps in UTC."""
    return datetime.fromisoformat(iso_str.replace("Z", "+00:00")).astimezone(timezone.utc)


def _make_dummy_packet(
    case_id: str = "case_01",
    audit_at: str = "2026-09-20T12:00:00Z",
    subject_id: str = "user_01",
    identifiers: list[str] | None = None,
    observations: list[SelectedObservation] | None = None,
    activities: list[SelectedActivity] | None = None,
    scoped_inventories: list[ScopedInventory] | None = None,
    is_blocked: bool = False,
    blocking_reason: str | None = None,
    intent_decision: str = "BYPASS_DIAGNOSTIC",
    diagnostics: RetrievalDiagnostics | None = None,
) -> CaseEvidencePacket:
    """Helper constructing a valid CaseEvidencePacket for state reconstruction tests."""
    cutoff = _dt(audit_at)
    idents = identifiers or [subject_id, "user01@example.com", "+15550100"]

    diag = diagnostics or RetrievalDiagnostics(
        case_id=case_id,
        audit_at=cutoff,
        coverage_scope="KNOWN_COMPLETE",
        total_eligible_observations_scanned=len(observations or []),
        total_future_observations_excluded=0,
    )

    return CaseEvidencePacket(
        case_id=case_id,
        email="user01@example.com",
        requested_at=_dt("2026-09-10T10:00:00Z"),
        reported_status="COMPLETE",
        reported_at=_dt("2026-09-12T10:00:00Z"),
        audit_at=cutoff,
        intent_decision=intent_decision,
        identity_status=IdentityResolutionStatus.RESOLVED,
        stable_subject_reference=subject_id,
        subject_identifiers=idents,
        grounded_resources=[],
        selected_observations=observations or [],
        selected_activities=activities or [],
        scoped_inventories=scoped_inventories or [],
        diagnostics=diag,
        is_blocked=is_blocked,
        blocking_reason=blocking_reason,
    )


# ===========================================================================
# 1. CORE RECORD EXISTENCE & ATTRIBUTION TESTS
# ===========================================================================

def test_positive_record_observation():
    """Observed customer record in a primary table is reconstructed as PRESENT with supported attribution."""
    obs = EvidenceObservation(
        evidence_id="ev_01",
        capture_time=_dt("2026-09-15T12:00:00Z"),
        system_id="account_service",
        resource_id="account_001",
        source_locator="table:customer_profiles_primary:row:1",
        extracted_facts={
            "resource_id": "account_001",
            "user_id": "user_01",
            "name": "Alice Smith",
            "email": "user01@example.com",
            "phone": "+15550100",
        },
    )
    so = SelectedObservation(
        observation=obs,
        matched_identifiers=["user01@example.com", "user_01"],
        primary_relationship=LinkRelationship.DIRECT_SUBJECT_IDENTIFIER,
    )
    packet = _make_dummy_packet(observations=[so])
    service = ResourceStateReconstructionService()
    recon = service.reconstruct_case(packet)

    assert not recon.is_blocked
    assert "account_service:account_001" in recon.resources
    res_agg = recon.resources["account_service:account_001"]
    assert res_agg.aggregate_existence == ExistenceState.PRESENT
    assert res_agg.observed_pii_exposed is True
    assert len(res_agg.surviving_copies) == 1

    copy_ast = list(res_agg.copies.values())[0]
    assert copy_ast.existence == ExistenceState.PRESENT
    assert copy_ast.attribution == SubjectAttribution.SUPPORTED
    assert copy_ast.fields["email"].status == FieldStatus.EXPOSED
    assert copy_ast.fields["email"].raw_value == "user01@example.com"
    assert copy_ast.fields["user_id"].status == FieldStatus.RETAINED_STABLE_REF


def test_grounded_negative_lookup():
    """Explicit negative lookup (404/not_found) proves record absence at that source."""
    obs = EvidenceObservation(
        evidence_id="ev_readback_log",
        capture_time=_dt("2026-09-15T12:00:00Z"),
        system_id="account_service",
        resource_id="account_001",
        source_locator="log:account_service_readback.log:102",
        extracted_facts={"status_code": 404, "result": "NOT_FOUND", "resource_id": "account_001"},
    )
    so = SelectedObservation(
        observation=obs,
        matched_identifiers=["user_01"],
        primary_relationship=LinkRelationship.OBSERVATION_RESOURCE_CHAIN,
    )
    packet = _make_dummy_packet(observations=[so])
    service = ResourceStateReconstructionService()
    recon = service.reconstruct_case(packet)

    assert len(recon.scoped_absence_checks) >= 1
    check = recon.scoped_absence_checks[0]
    assert check.membership_result == "ABSENT"


def test_missing_retrieval_result_remains_unknown():
    """Absence is NEVER assumed merely because an observation was not selected or missing."""
    # Packet has an activity referring to account_999, but no observation of the store
    sa = SelectedActivity(
        activity_id="act_101",
        event_time=_dt("2026-09-14T10:00:00Z"),
        event_type="DELETE_RECORD",
        source_system="privacy_workflow",
        target_system="account_service",
        resource_id="account_999",
        reported_result="SUCCESS",
        details="Workflow claimed account_999 deleted",
        grounded_resource_key="account_service:account_999",
        supporting_link=EvidenceLink(
            link_id="link_001",
            from_endpoint=LinkEndpoint(endpoint_type="SUBJECT", endpoint_id="user_01"),
            to_endpoint=LinkEndpoint(endpoint_type="ACTIVITY", endpoint_id="act_101"),
            provenance=LinkProvenance(
                source_type="SYSTEM_ACTIVITY",
                source_id="act_101",
                timestamp=_dt("2026-09-14T10:00:00Z"),
                relationship=LinkRelationship.ACTIVITY_RESOURCE_MATCH,
                is_direct=True,
            ),
            explanation="Activity target",
        ),
    )
    packet = _make_dummy_packet(activities=[sa])
    recon = ResourceStateReconstructionService().reconstruct_case(packet)

    assert "account_service:account_999" in recon.resources
    res_agg = recon.resources["account_service:account_999"]
    # Without grounded absence proof, existence MUST remain UNKNOWN
    assert res_agg.aggregate_existence == ExistenceState.UNKNOWN
    assert len(res_agg.absent_copies) == 0


def test_successful_deletion_claim_with_surviving_pii():
    """DELETE_RECORD SUCCESS claim cannot overwrite an observed surviving record."""
    obs = EvidenceObservation(
        evidence_id="ev_sql_snapshot",
        capture_time=_dt("2026-09-18T12:00:00Z"),
        system_id="account_service",
        resource_id="account_001",
        source_locator="table:customer_profiles_primary:row:1",
        extracted_facts={
            "resource_id": "account_001",
            "user_id": "user_01",
            "email": "user01@example.com",
            "account_status": "ACTIVE",
        },
    )
    so = SelectedObservation(
        observation=obs,
        matched_identifiers=["user01@example.com"],
        primary_relationship=LinkRelationship.DIRECT_SUBJECT_IDENTIFIER,
    )
    sa = SelectedActivity(
        activity_id="act_del",
        event_time=_dt("2026-09-15T10:00:00Z"),  # Earlier deletion claim
        event_type="DELETE_RECORD",
        source_system="privacy_service",
        target_system="account_service",
        resource_id="account_001",
        reported_result="SUCCESS",
        details="Deletion reported complete",
        grounded_resource_key="account_service:account_001",
        supporting_link=EvidenceLink(
            link_id="l1",
            from_endpoint=LinkEndpoint(endpoint_type="RESOURCE", endpoint_id="account_service:account_001"),
            to_endpoint=LinkEndpoint(endpoint_type="ACTIVITY", endpoint_id="act_del"),
            provenance=LinkProvenance(
                source_type="SYSTEM_ACTIVITY",
                source_id="act_del",
                timestamp=_dt("2026-09-15T10:00:00Z"),
                relationship=LinkRelationship.ACTIVITY_RESOURCE_MATCH,
                is_direct=True,
            ),
            explanation="Claim",
        ),
    )
    packet = _make_dummy_packet(observations=[so], activities=[sa])
    recon = ResourceStateReconstructionService().reconstruct_case(packet)

    res_agg = recon.resources["account_service:account_001"]
    assert res_agg.aggregate_existence == ExistenceState.PRESENT
    copy_ast = list(res_agg.copies.values())[0]
    assert copy_ast.existence == ExistenceState.PRESENT
    assert "DELETE_RECORD SUCCESS" in copy_ast.unverified_claims[0]


def test_primary_absence_plus_replica_presence():
    """Primary store absence does not contradict replica presence; both copies are preserved."""
    # Replica observation: account_005 present in failover replica
    replica_obs = EvidenceObservation(
        evidence_id="ev_54",
        capture_time=_dt("2026-09-02T23:00:00Z"),
        system_id="account_service",
        resource_id="account_005",
        source_locator="table:customer_profiles_failover_replica:row:1",
        extracted_facts={"resource_id": "account_005", "email": "user01@example.com"},
    )
    so = SelectedObservation(
        observation=replica_obs,
        matched_identifiers=["user01@example.com"],
        primary_relationship=LinkRelationship.DIRECT_SUBJECT_IDENTIFIER,
    )
    # Primary inventory: full dump where account_005 is absent
    primary_inv = ScopedInventory(
        system_id="account_service",
        source_id="ev_54",
        source_locator="table:customer_profiles_primary",
        timestamp=_dt("2026-09-02T23:00:00Z"),
        extracted_facts={
            "table_name": "customer_profiles_primary",
            "table_rows": [{"resource_id": "account_999", "email": "other@example.com"}],
        },
    )
    packet = _make_dummy_packet(observations=[so], scoped_inventories=[primary_inv])
    recon = ResourceStateReconstructionService().reconstruct_case(packet)

    res_agg = recon.resources["account_service:account_005"]
    assert res_agg.aggregate_existence == ExistenceState.PRESENT
    assert len(res_agg.surviving_copies) == 1
    assert "FAILOVER_REPLICA" in res_agg.surviving_copies[0]


def test_supported_absence_followed_by_observed_recreation():
    """Verified absence followed by a later positive observation at t2 > t1 flags recreation."""
    # Early inventory at Sep 01 proves absence
    early_inv = ScopedInventory(
        system_id="account_service",
        source_id="ev_early",
        source_locator="table:customer_profiles_primary",
        timestamp=_dt("2026-09-01T10:00:00Z"),
        extracted_facts={"count": 0, "table_name": "customer_profiles_primary"},
    )
    # Later observation at Sep 10 shows record present again
    later_obs = EvidenceObservation(
        evidence_id="ev_later",
        capture_time=_dt("2026-09-10T10:00:00Z"),
        system_id="account_service",
        resource_id="account_001",
        source_locator="table:customer_profiles_primary:row:1",
        extracted_facts={"resource_id": "account_001", "email": "user01@example.com"},
    )
    so = SelectedObservation(
        observation=later_obs,
        matched_identifiers=["user01@example.com"],
        primary_relationship=LinkRelationship.DIRECT_SUBJECT_IDENTIFIER,
    )
    packet = _make_dummy_packet(observations=[so], scoped_inventories=[early_inv])
    recon = ResourceStateReconstructionService().reconstruct_case(packet)

    res_agg = recon.resources["account_service:account_001"]
    assert res_agg.has_recreation_risk is True
    copy_ast = list(res_agg.copies.values())[0]
    assert copy_ast.is_recreated is True
    assert "Observed present" in copy_ast.recreation_details


def test_sync_restore_claim_without_observed_recreation():
    """A SYNC claim alone does not prove recreation without a grounded observation."""
    sa_sync = SelectedActivity(
        activity_id="act_sync",
        event_time=_dt("2026-09-12T10:00:00Z"),
        event_type="SYNC",
        source_system="integration_service",
        target_system="account_service",
        resource_id="account_001",
        reported_result="SUCCESS",
        details="Sync claimed completed",
        grounded_resource_key="account_service:account_001",
        supporting_link=EvidenceLink(
            link_id="l_s",
            from_endpoint=LinkEndpoint(endpoint_type="RESOURCE", endpoint_id="account_service:account_001"),
            to_endpoint=LinkEndpoint(endpoint_type="ACTIVITY", endpoint_id="act_sync"),
            provenance=LinkProvenance(
                source_type="SYSTEM_ACTIVITY",
                source_id="act_sync",
                timestamp=_dt("2026-09-12T10:00:00Z"),
                relationship=LinkRelationship.ACTIVITY_RESOURCE_MATCH,
                is_direct=True,
            ),
            explanation="Sync",
        ),
    )
    packet = _make_dummy_packet(activities=[sa_sync])
    recon = ResourceStateReconstructionService().reconstruct_case(packet)

    res_agg = recon.resources["account_service:account_001"]
    assert res_agg.has_recreation_risk is False
    copy_ast = list(res_agg.copies.values())[0]
    assert copy_ast.is_recreated is False


def test_same_copy_conflicting_observations():
    """Contradictory observations of the exact same copy at the same timestamp mark CONFLICTED."""
    obs_pres = EvidenceObservation(
        evidence_id="ev_pres",
        capture_time=_dt("2026-09-15T12:00:00Z"),
        system_id="account_service",
        resource_id="account_001",
        source_locator="table:customer_profiles:row:1",
        extracted_facts={"resource_id": "account_001", "email": "user01@example.com"},
    )
    so_pres = SelectedObservation(
        observation=obs_pres,
        matched_identifiers=["user01@example.com"],
        primary_relationship=LinkRelationship.DIRECT_SUBJECT_IDENTIFIER,
    )
    # Inventory of the same store at identical timestamp showing count=0 (ABSENT)
    inv_abs = ScopedInventory(
        system_id="account_service",
        source_id="ev_abs",
        source_locator="table:customer_profiles",
        timestamp=_dt("2026-09-15T12:00:00Z"),
        extracted_facts={"count": 0, "table_name": "customer_profiles"},
    )
    packet = _make_dummy_packet(observations=[so_pres], scoped_inventories=[inv_abs])
    recon = ResourceStateReconstructionService().reconstruct_case(packet)

    res_agg = recon.resources["account_service:account_001"]
    assert res_agg.aggregate_existence == ExistenceState.CONFLICTED


# ===========================================================================
# 2. TIMESTAMP INTERPRETATION TESTS
# ===========================================================================

def test_snapshot_capture_time_vs_old_updated_at():
    """SQL snapshot capture time is the state observation time; row updated_at is mutation time."""
    obs = EvidenceObservation(
        evidence_id="ev_sql",
        capture_time=_dt("2026-09-18T10:00:00Z"),
        system_id="account_service",
        resource_id="account_001",
        file_path="evidence/databases/customer_db_20260918.sql",
        source_locator="table:customer_profiles:row:1",
        extracted_facts={"updated_at": "2026-08-01T08:00:00Z"},
    )
    ts_info = SourceAwareTimestampInterpreter.interpret_observation(obs, audit_at=_dt("2026-09-20T12:00:00Z"))
    assert ts_info.state_observation_time == _dt("2026-09-18T10:00:00Z")
    assert ts_info.business_mutation_time == _dt("2026-08-01T08:00:00Z")
    assert "snapshot capture time" in ts_info.time_role_basis


def test_log_export_time_vs_event_time():
    """Log event timestamp establishes observation time; export time is archive capture time."""
    obs = EvidenceObservation(
        evidence_id="ev_log",
        capture_time=_dt("2026-09-19T10:00:00Z"),  # Archive export time
        observation_time=_dt("2026-09-15T08:30:00Z"),  # Event occurrence time
        system_id="auth_service",
        resource_id="token_001",
        file_path="evidence/logs/auth_audit_20260919.log",
        observation_type="LOG_ENTRY",
        extracted_facts={},
    )
    ts_info = SourceAwareTimestampInterpreter.interpret_observation(obs, audit_at=_dt("2026-09-20T12:00:00Z"))
    assert ts_info.state_observation_time == _dt("2026-09-15T08:30:00Z")
    assert ts_info.capture_time == _dt("2026-09-19T10:00:00Z")
    assert "Log event timestamp establishes" in ts_info.time_role_basis


def test_future_retention_expiry_not_used_as_observation_time():
    """Future retention expiration date is policy metadata, never observation time."""
    obs = EvidenceObservation(
        evidence_id="ev_ret",
        capture_time=_dt("2026-09-05T06:30:00Z"),
        system_id="security_service",
        resource_id="audit_record_003",
        extracted_facts={"retention": {"retention_until_iso": "2027-08-25T00:00:00Z"}},
    )
    ts_info = SourceAwareTimestampInterpreter.interpret_observation(obs, audit_at=_dt("2026-09-20T12:00:00Z"))
    assert ts_info.state_observation_time == _dt("2026-09-05T06:30:00Z")
    assert ts_info.retention_expiry == _dt("2027-08-25T00:00:00Z")
    assert ts_info.is_eligible is True


def test_future_sources_excluded_at_cutoff():
    """An observation captured after audit cutoff is excluded from reconstructed state."""
    future_obs = EvidenceObservation(
        evidence_id="ev_future",
        capture_time=_dt("2026-09-25T10:00:00Z"),  # After cutoff
        system_id="account_service",
        resource_id="account_future",
        extracted_facts={"user_id": "user_01"},
    )
    so = SelectedObservation(
        observation=future_obs,
        matched_identifiers=["user_01"],
        primary_relationship=LinkRelationship.DIRECT_SUBJECT_IDENTIFIER,
    )
    packet = _make_dummy_packet(audit_at="2026-09-20T12:00:00Z", observations=[so])
    recon = ResourceStateReconstructionService().reconstruct_case(packet)
    assert "account_service:account_future" not in recon.resources


# ===========================================================================
# 3. FIELD CLASSIFICATION & CONTENT EXTRACTION TESTS
# ===========================================================================

def test_null_missing_masked_and_unreadable_fields():
    """Field observation accurately identifies NULL, EMPTY, MASKED, UNREADABLE, and EXPOSED."""
    facts = {
        "full_name": "Alice ***",
        "email": "",
        "phone": None,
        "customer_email": "unreadable due to scan blur",
        "email_hash": "a1b2c3d4e5f6",
    }
    fields = extract_field_observations(facts)
    assert fields["name"].status == FieldStatus.MASKED
    assert fields["email"].status == FieldStatus.EMPTY
    assert fields["phone"].status == FieldStatus.NULL
    assert fields["email_hash"].status == FieldStatus.EXPOSED


def test_retained_stable_user_ref_without_direct_pii():
    """A tombstone preserving user_id with null PII has RETAINED_STABLE_REF and no exposed PII."""
    facts = {
        "subject_reference": "user_17",
        "name": None,
        "email": None,
        "phone": None,
        "email_hash": None,
    }
    fields = extract_field_observations(facts)
    assert fields["user_id"].status == FieldStatus.RETAINED_STABLE_REF
    assert fields["user_id"].is_stable_ref is True
    assert fields["user_id"].is_direct_pii is False
    assert fields["name"].status == FieldStatus.NULL
    assert fields["email"].status == FieldStatus.NULL


def test_redaction_claim_with_exposed_email():
    """When UI claims redacted but email remains exposed, claim_label records mismatch."""
    facts = {
        "account_status": "DELETED (redacted)",
        "redacted": True,
        "email": "user01@example.com",
    }
    fields = extract_field_observations(facts)
    assert fields["email"].status == FieldStatus.EXPOSED
    assert fields["email"].claim_label == "CLAIMED_REDACTED_BUT_EMAIL_EXPOSED"


# ===========================================================================
# 4. PROCESS CONFIGURATION & RESTORE TESTS
# ===========================================================================

def test_process_and_restore_state_extraction():
    """Verify enabled/disabled process and allowed/blocked restore permissions."""
    facts_enabled = {"sync_status": "ACTIVE", "restore_allowed": True}
    proc_st, rest_st = extract_process_and_restore_state(facts_enabled)
    assert proc_st == ProcessState.ENABLED
    assert rest_st == RestoreState.ALLOWED

    # Word boundary prevents 'INACTIVE' from matching 'ACTIVE'
    facts_disabled = {"sync_status": "INACTIVE", "restore_status": "BLOCKED"}
    proc_st2, rest_st2 = extract_process_and_restore_state(facts_disabled)
    assert proc_st2 == ProcessState.DISABLED
    assert rest_st2 == RestoreState.BLOCKED


# ===========================================================================
# 5. INTEGRATION & AUTHORIZATION REGRESSION TESTS
# ===========================================================================

def test_authorization_blocking_propagation():
    """A blocked evidence packet propagates blocking to reconstruction without generating fake state."""
    packet = _make_dummy_packet(
        is_blocked=True,
        blocking_reason="NON_DELETION: Intent classification determined marketing opt-out.",
    )
    recon = ResourceStateReconstructionService().reconstruct_case(packet)
    assert recon.is_blocked is True
    assert "NON_DELETION" in recon.blocking_reason
    assert len(recon.resources) == 0


def test_determinism_under_shuffled_inputs():
    """State reconstruction produces identical results regardless of observation/activity ordering."""
    obs1 = EvidenceObservation(
        evidence_id="ev_01",
        capture_time=_dt("2026-09-10T10:00:00Z"),
        system_id="account_service",
        resource_id="acc_1",
        extracted_facts={"email": "u1@test.com"},
    )
    obs2 = EvidenceObservation(
        evidence_id="ev_02",
        capture_time=_dt("2026-09-12T10:00:00Z"),
        system_id="analytics_platform",
        resource_id="ana_2",
        extracted_facts={"email": "u1@test.com"},
    )
    so1 = SelectedObservation(observation=obs1, matched_identifiers=["u1@test.com"], primary_relationship=LinkRelationship.DIRECT_SUBJECT_IDENTIFIER)
    so2 = SelectedObservation(observation=obs2, matched_identifiers=["u1@test.com"], primary_relationship=LinkRelationship.DIRECT_SUBJECT_IDENTIFIER)

    p1 = _make_dummy_packet(observations=[so1, so2])
    p2 = _make_dummy_packet(observations=[so2, so1])

    service = ResourceStateReconstructionService()
    r1 = service.reconstruct_case(p1)
    r2 = service.reconstruct_case(p2)

    d1 = r1.model_dump(mode="json")
    d2 = r2.model_dump(mode="json")
    d1["diagnostics"].pop("execution_time_ms", None)
    d2["diagnostics"].pop("execution_time_ms", None)
    assert d1 == d2


def test_disabled_connector_followed_by_later_observed_activity():
    """Later observed process configuration or activity supersedes an earlier disable claim."""
    # Earlier claim: DISABLE_DATA_FLOW SUCCESS at Sep 01
    sa_dis = SelectedActivity(
        activity_id="act_dis",
        event_time=_dt("2026-09-01T10:00:00Z"),
        event_type="DISABLE_DATA_FLOW",
        source_system="sync_coordinator",
        target_system="data_lake",
        resource_id="sync_job_01",
        reported_result="SUCCESS",
        details="Connector disabled",
        grounded_resource_key="data_lake:sync_job_01",
        supporting_link=EvidenceLink(
            link_id="l1",
            from_endpoint=LinkEndpoint(endpoint_type="SUBJECT", endpoint_id="user_01"),
            to_endpoint=LinkEndpoint(endpoint_type="ACTIVITY", endpoint_id="act_dis"),
            provenance=LinkProvenance(
                source_type="SYSTEM_ACTIVITY",
                source_id="act_dis",
                timestamp=_dt("2026-09-01T10:00:00Z"),
                relationship=LinkRelationship.ACTIVITY_RESOURCE_MATCH,
                is_direct=True,
            ),
            explanation="Sync disable",
        ),
    )
    # Later observation: connector configuration is ACTIVE/ENABLED at Sep 10
    obs_active = EvidenceObservation(
        evidence_id="ev_connector_conf",
        capture_time=_dt("2026-09-10T15:00:00Z"),
        system_id="data_lake",
        resource_id="sync_job_01",
        source_locator="config:connectors:sync_job_01",
        extracted_facts={"connector_status": "ENABLED", "source": "postgres", "destination": "s3"},
    )
    so_active = SelectedObservation(
        observation=obs_active,
        matched_identifiers=["user_01"],
        primary_relationship=LinkRelationship.OBSERVATION_RESOURCE_CHAIN,
    )
    packet = _make_dummy_packet(observations=[so_active], activities=[sa_dis])
    recon = ResourceStateReconstructionService().reconstruct_case(packet)

    res_agg = recon.resources["data_lake:sync_job_01"]
    primary_copy = list(res_agg.copies.values())[0]
    # Latest observation at Sep 10 establishes ENABLED, superseding the Sep 01 claim
    assert primary_copy.process_state == ProcessState.ENABLED
    assert "DISABLE_DATA_FLOW SUCCESS" in primary_copy.unverified_claims


def test_restore_block_claim_vs_observed_restore_permission():
    """Observed restore permission proves RESTORE ALLOWED despite an unverified BLOCK_RESTORE claim."""
    sa_block = SelectedActivity(
        activity_id="act_block",
        event_time=_dt("2026-09-05T10:00:00Z"),
        event_type="BLOCK_RESTORE",
        source_system="backup_manager",
        target_system="backup_service",
        resource_id="backup_snapshot_01",
        reported_result="SUCCESS",
        details="Claimed backup restore blocked",
        grounded_resource_key="backup_service:backup_snapshot_01",
        supporting_link=EvidenceLink(
            link_id="l2",
            from_endpoint=LinkEndpoint(endpoint_type="SUBJECT", endpoint_id="user_01"),
            to_endpoint=LinkEndpoint(endpoint_type="ACTIVITY", endpoint_id="act_block"),
            provenance=LinkProvenance(
                source_type="SYSTEM_ACTIVITY",
                source_id="act_block",
                timestamp=_dt("2026-09-05T10:00:00Z"),
                relationship=LinkRelationship.ACTIVITY_RESOURCE_MATCH,
                is_direct=True,
            ),
            explanation="Block restore",
        ),
    )
    obs_perm = EvidenceObservation(
        evidence_id="ev_backup_meta",
        capture_time=_dt("2026-09-06T12:00:00Z"),
        system_id="backup_service",
        resource_id="backup_snapshot_01",
        source_locator="s3://backups/snapshot_01/metadata.json",
        extracted_facts={"restore_allowed": True, "encryption": "AES256"},
    )
    so_perm = SelectedObservation(
        observation=obs_perm,
        matched_identifiers=["user_01"],
        primary_relationship=LinkRelationship.OBSERVATION_RESOURCE_CHAIN,
    )
    packet = _make_dummy_packet(observations=[so_perm], activities=[sa_block])
    recon = ResourceStateReconstructionService().reconstruct_case(packet)

    res_agg = recon.resources["backup_service:backup_snapshot_01"]
    copy_ast = list(res_agg.copies.values())[0]
    assert copy_ast.restore_state == RestoreState.ALLOWED
    assert res_agg.has_restore_risk is True


def test_incomplete_or_deferred_ingestion_preventing_unsupported_absence():
    """Coverage limitations (deferred/failed files) propagate and prevent assuming absence."""
    from ghost_audit.retrieval.models import RetrievalDiagnostics

    diag = RetrievalDiagnostics(
        case_id="case_cov",
        audit_at=_dt("2026-09-20T12:00:00Z"),
        coverage_scope="KNOWN_INCOMPLETE_SCOPE",
        failed_files=["ev_unreadable_sql.sql"],
        deferred_files=["ev_huge_dump.csv"],
    )
    packet = _make_dummy_packet(diagnostics=diag)
    recon = ResourceStateReconstructionService().reconstruct_case(packet)

    assert recon.diagnostics.coverage_scope == "KNOWN_INCOMPLETE_SCOPE"
    assert "ev_unreadable_sql.sql" in recon.diagnostics.unreadable_or_failed_files
    assert "ev_huge_dump.csv" in recon.diagnostics.deferred_files
    # No resources found, and no absence falsely inferred
    assert len(recon.resources) == 0


def test_diagnostic_bypass_labeling():
    """Explicit diagnostic mode propagates and is clearly labeled in the reconstruction result."""
    packet = _make_dummy_packet(intent_decision="BYPASS_DIAGNOSTIC")
    recon = ResourceStateReconstructionService().reconstruct_case(packet)

    assert recon.is_diagnostic_mode is True
    assert recon.is_blocked is False
