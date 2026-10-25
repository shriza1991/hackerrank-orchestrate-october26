"""Regression tests demonstrating and verifying fixes for Task 9 state reconstruction defects.

Covers:
1. Negative lookup for resource B cannot affect resource A.
2. Primary negative lookup cannot prove replica absence.
3. Negative-only observation establishes absence without inventing a contradictory PRESENT event.
4. Inventory/schema metadata alone does not establish record presence.
5. Operational claims do not establish stored record presence.
6. Embedded record_json identifiers are properly parsed and extracted.
7. Stable physical store identity (row locators as evidence provenance, not separate replicas).
8. Historical conflicts resolved by later definitive observations.
"""

from datetime import datetime, timezone
import pytest

from ghost_audit.models.intermediate_models import EvidenceObservation, IdentityResolutionStatus
from ghost_audit.retrieval.models import (
    CaseEvidencePacket,
    EvidenceLink,
    LinkEndpoint,
    LinkProvenance,
    LinkRelationship,
    RetrievalDiagnostics,
    ScopedInventory,
    SelectedActivity,
    SelectedObservation,
)
from ghost_audit.state.inventory_checker import ScopedInventoryChecker
from ghost_audit.state.models import CopyType, ExistenceState, FieldStatus
from ghost_audit.state.reconstruction import (
    ResourceStateEngine,
    derive_copy_type,
    extract_field_observations,
)
from ghost_audit.state.service import ResourceStateReconstructionService


def _dt(iso_str: str) -> datetime:
    return datetime.fromisoformat(iso_str.replace("Z", "+00:00")).astimezone(timezone.utc)


def _make_packet(
    case_id: str = "case_01",
    audit_at: str = "2026-09-20T12:00:00Z",
    subject_id: str = "user_01",
    observations: list[SelectedObservation] | None = None,
    activities: list[SelectedActivity] | None = None,
    scoped_inventories: list[ScopedInventory] | None = None,
) -> CaseEvidencePacket:
    cutoff = _dt(audit_at)
    diag = RetrievalDiagnostics(
        case_id=case_id,
        audit_at=cutoff,
        coverage_scope="KNOWN_COMPLETE",
    )
    return CaseEvidencePacket(
        case_id=case_id,
        email="user01@example.com",
        requested_at=_dt("2026-09-10T10:00:00Z"),
        reported_status="COMPLETE",
        reported_at=_dt("2026-09-12T10:00:00Z"),
        audit_at=cutoff,
        intent_decision="BYPASS_DIAGNOSTIC",
        identity_status=IdentityResolutionStatus.RESOLVED,
        stable_subject_reference=subject_id,
        subject_identifiers=[subject_id, "user01@example.com"],
        grounded_resources=[],
        selected_observations=observations or [],
        selected_activities=activities or [],
        scoped_inventories=scoped_inventories or [],
        diagnostics=diag,
    )


def test_negative_lookup_for_resource_b_does_not_affect_resource_a():
    """Defect A: Negative lookup for account_B must NEVER prove account_A absent."""
    obs_neg_b = EvidenceObservation(
        evidence_id="ev_api_log",
        capture_time=_dt("2026-09-15T10:00:00Z"),
        system_id="account_service",
        resource_id="account_B",
        source_locator="api:get_account:account_B",
        extracted_facts={"status_code": 404, "result": "NOT_FOUND"},
    )
    so = SelectedObservation(
        observation=obs_neg_b,
        matched_identifiers=["user01@example.com"],
        primary_relationship=LinkRelationship.DIRECT_SUBJECT_IDENTIFIER,
    )

    # We check absence for account_A
    check = ScopedInventoryChecker.check_negative_lookup(
        selected_observations=[so],
        system_id="account_service",
        target_resource_id="account_A",
        audit_at=_dt("2026-09-20T12:00:00Z"),
    )
    # Must be None, because the lookup was for account_B, not account_A!
    assert check is None


def test_primary_negative_lookup_does_not_prove_replica_absence():
    """Defect A: A primary negative lookup cannot establish absence in a replica."""
    obs_primary_404 = EvidenceObservation(
        evidence_id="ev_primary_api",
        capture_time=_dt("2026-09-15T10:00:00Z"),
        system_id="account_service",
        resource_id="account_A",
        source_locator="primary:api:get_account",
        extracted_facts={"status_code": 404, "store": "primary"},
    )
    so = SelectedObservation(
        observation=obs_primary_404,
        matched_identifiers=["user01@example.com"],
        primary_relationship=LinkRelationship.DIRECT_SUBJECT_IDENTIFIER,
    )

    # Checking negative lookup for failover replica store locator
    check = ScopedInventoryChecker.check_negative_lookup(
        selected_observations=[so],
        system_id="account_service",
        target_resource_id="account_A",
        audit_at=_dt("2026-09-20T12:00:00Z"),
        store_locator="customer_profiles_failover_replica",
    )
    assert check is None


def test_negative_only_evidence_establishes_absence_without_false_conflict():
    """Defect B: An explicit negative lookup establishes ABSENT without creating a false PRESENT event."""
    obs_neg = EvidenceObservation(
        evidence_id="ev_api_404",
        capture_time=_dt("2026-09-15T12:00:00Z"),
        system_id="account_service",
        resource_id="account_A",
        source_locator="api:accounts:account_A",
        extracted_facts={"status_code": 404, "result": "NOT_FOUND"},
    )
    so = SelectedObservation(
        observation=obs_neg,
        matched_identifiers=["user01@example.com"],
        primary_relationship=LinkRelationship.DIRECT_SUBJECT_IDENTIFIER,
    )
    packet = _make_packet(observations=[so])
    recon = ResourceStateReconstructionService().reconstruct_case(packet)

    assert "account_service:account_A" in recon.resources
    res_agg = recon.resources["account_service:account_A"]
    # Must be ABSENT, and NOT CONFLICTED!
    assert res_agg.aggregate_existence == ExistenceState.ABSENT
    copy_ast = list(res_agg.copies.values())[0]
    assert copy_ast.existence == ExistenceState.ABSENT
    assert len(copy_ast.conflicts) == 0


def test_inventory_metadata_alone_does_not_establish_record_presence():
    """Defect B: An inventory scope/schema observation alone does not establish record presence."""
    obs_schema = EvidenceObservation(
        evidence_id="ev_schema",
        capture_time=_dt("2026-09-01T10:00:00Z"),
        system_id="account_service",
        resource_id=None,
        source_locator="table:customer_profiles",
        observation_type="INVENTORY_SCOPE",
        extracted_facts={
            "table_name": "customer_profiles",
            "columns": ["id", "email"],
            "row_count": 100,
        },
    )
    so = SelectedObservation(
        observation=obs_schema,
        matched_identifiers=[],
        primary_relationship=LinkRelationship.SCOPED_INVENTORY,
    )
    packet = _make_packet(observations=[so])
    recon = ResourceStateReconstructionService().reconstruct_case(packet)

    # No specific record presence should be created
    assert len(recon.resources) == 0


def test_operational_claims_do_not_establish_stored_record_presence():
    """Defect B: Operational activity claims remain claims, not stored record observations."""
    sa_del = SelectedActivity(
        activity_id="act_del_claim",
        event_time=_dt("2026-09-10T10:00:00Z"),
        event_type="DELETE_RECORD",
        source_system="worker",
        target_system="account_service",
        resource_id="account_001",
        reported_result="SUCCESS",
        details="Claimed deleted",
        grounded_resource_key="account_service:account_001",
        supporting_link=EvidenceLink(
            link_id="l1",
            from_endpoint=LinkEndpoint(endpoint_type="SUBJECT", endpoint_id="user_01"),
            to_endpoint=LinkEndpoint(endpoint_type="ACTIVITY", endpoint_id="act_del_claim"),
            provenance=LinkProvenance(
                source_type="SYSTEM_ACTIVITY",
                source_id="act_del_claim",
                timestamp=_dt("2026-09-10T10:00:00Z"),
                relationship=LinkRelationship.ACTIVITY_RESOURCE_MATCH,
                is_direct=True,
            ),
            explanation="Claim",
        ),
    )
    packet = _make_packet(activities=[sa_del])
    recon = ResourceStateReconstructionService().reconstruct_case(packet)

    res_agg = recon.resources["account_service:account_001"]
    assert res_agg.aggregate_existence == ExistenceState.UNKNOWN
    copy_ast = list(res_agg.copies.values())[0]
    assert len(copy_ast.unverified_claims) == 1
    assert copy_ast.existence == ExistenceState.UNKNOWN


def test_embedded_record_json_extraction():
    """Defect C: Embedded record_json (string or dict) is properly parsed without broad exceptions."""
    facts = {
        "resource_id": "account_99",
        "record_json": '{"email": "embedded@test.com", "customer_name": "Embedded User", "phone": "+123456789"}',
    }
    fields = extract_field_observations(facts)
    assert fields["email"].status == FieldStatus.EXPOSED
    assert fields["email"].raw_value == "embedded@test.com"
    assert fields["name"].status == FieldStatus.EXPOSED
    assert fields["name"].raw_value == "Embedded User"
    assert fields["phone"].status == FieldStatus.EXPOSED


def test_stable_physical_store_identity_across_row_locators():
    """Defect D: Differing row locators describe the same physical store, not different replicas."""
    c_type1, loc1 = derive_copy_type("account_service", "table:customer_data_primary:row:1")
    c_type2, loc2 = derive_copy_type("account_service", "table:customer_data_primary:row:2")

    assert c_type1 == CopyType.PRIMARY
    assert c_type2 == CopyType.PRIMARY
    assert loc1 == "customer_data_primary"
    assert loc2 == "customer_data_primary"


def test_historical_conflict_resolved_by_later_observation():
    """Defect D: Earlier disagreement at t1 resolved by definitive later observation at t2."""
    obs_t1_pres = EvidenceObservation(
        evidence_id="ev_t1_pres",
        capture_time=_dt("2026-09-01T10:00:00Z"),
        system_id="account_service",
        resource_id="account_X",
        source_locator="table:customer_profiles:row:1",
        extracted_facts={"email": "u1@test.com"},
    )
    so_t1 = SelectedObservation(
        observation=obs_t1_pres,
        matched_identifiers=["u1@test.com"],
        primary_relationship=LinkRelationship.DIRECT_SUBJECT_IDENTIFIER,
    )
    # At t2 > t1, definitive negative lookup proves it absent
    obs_t2_abs = EvidenceObservation(
        evidence_id="ev_t2_404",
        capture_time=_dt("2026-09-10T12:00:00Z"),
        system_id="account_service",
        resource_id="account_X",
        source_locator="table:customer_profiles:api",
        extracted_facts={"status_code": 404, "result": "NOT_FOUND"},
    )
    so_t2 = SelectedObservation(
        observation=obs_t2_abs,
        matched_identifiers=["u1@test.com"],
        primary_relationship=LinkRelationship.DIRECT_SUBJECT_IDENTIFIER,
    )
    packet = _make_packet(observations=[so_t1, so_t2])
    recon = ResourceStateReconstructionService().reconstruct_case(packet)

    res_agg = recon.resources["account_service:account_X"]
    # The later observation at t2 resolved the state to ABSENT
    assert res_agg.aggregate_existence == ExistenceState.ABSENT
    assert len(res_agg.conflicts) == 0
