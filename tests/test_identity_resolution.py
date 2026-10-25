"""Comprehensive tests for Task 5: Historical Identity Resolution."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghost_audit.identity.index import IdentityIndex
from ghost_audit.identity.models import SourceType
from ghost_audit.identity.normalization import (
    normalize_email,
    normalize_email_hash,
    normalize_phone,
    normalize_user_id,
)
from ghost_audit.identity.service import IdentityResolutionService
from ghost_audit.models.input_models import DeletionRequest, UserAuditLogEntry, UserIdentity
from ghost_audit.models.intermediate_models import IdentityResolutionStatus
from ghost_audit.timestamps import parse_iso_timestamp


def _make_identity(
    user_id: str = "user_01",
    name: str = "Alice Smith",
    email: str = "alice@example.com",
    phone: str = "+1 555 123 4567",
    email_hash: str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    updated_at: str = "2026-06-01T10:00:00Z",
) -> UserIdentity:
    return UserIdentity(
        user_id=user_id,
        name=name,
        email=email,
        phone=phone,
        email_hash=email_hash,
        updated_at=updated_at,
    )


def _make_audit(
    audit_id: str,
    user_id: str,
    field_name: str,
    old_value: str,
    new_value: str,
    event_time: str,
) -> UserAuditLogEntry:
    return UserAuditLogEntry(
        audit_id=audit_id,
        user_id=user_id,
        field_name=field_name,
        old_value=old_value,
        new_value=new_value,
        event_time=event_time,
    )


def test_current_email_match():
    """Current snapshot email matches and returns RESOLVED with stable user_id and snapshot provenance."""
    user = _make_identity(
        user_id="user_10",
        email="current@example.com",
        updated_at="2026-05-01T12:00:00Z",
    )
    service = IdentityResolutionService.from_data(identities=[user], audit_logs=[])
    res = service.resolve_email("current@example.com", audit_at="2026-06-01T00:00:00Z")

    assert res.resolution_status == IdentityResolutionStatus.RESOLVED
    assert res.stable_subject_reference == "user_10"
    assert res.match_method == "CURRENT_SNAPSHOT_EMAIL"
    assert res.current_identifiers["email"] == "current@example.com"
    assert "user_10" in res.searchable_identifiers
    assert any(p["source_file"] == "user_identities.csv" for p in res.provenance)


def test_historical_email_match_after_change():
    """Historical old email matches after an email change event; current email reflects new_value."""
    user = _make_identity(
        user_id="user_20",
        email="new_email@example.com",
        updated_at="2026-04-10T15:00:00Z",
    )
    audit = _make_audit(
        audit_id="audit_100",
        user_id="user_20",
        field_name="email",
        old_value="old_email@example.com",
        new_value="new_email@example.com",
        event_time="2026-04-10T15:00:00Z",
    )
    service = IdentityResolutionService.from_data(identities=[user], audit_logs=[audit])
    res = service.resolve_email("old_email@example.com", audit_at="2026-05-01T00:00:00Z")

    assert res.resolution_status == IdentityResolutionStatus.RESOLVED
    assert res.stable_subject_reference == "user_20"
    assert res.match_method == "HISTORICAL_AUDIT_LOG_OLD_EMAIL"
    assert res.current_identifiers["email"] == "new_email@example.com"
    assert any(h["raw_value"] == "old_email@example.com" for h in res.historical_identifiers)
    assert "audit_100" in res.supporting_references


def test_multiple_sequential_email_changes():
    """Sequential email changes A -> B -> C: resolving A recovers B and A as historical, C as current."""
    user = _make_identity(
        user_id="user_30",
        email="email_c@example.com",
        updated_at="2026-06-01T10:00:00Z",
    )
    audit1 = _make_audit(
        audit_id="audit_01",
        user_id="user_30",
        field_name="email",
        old_value="email_a@example.com",
        new_value="email_b@example.com",
        event_time="2026-02-01T10:00:00Z",
    )
    audit2 = _make_audit(
        audit_id="audit_02",
        user_id="user_30",
        field_name="email",
        old_value="email_b@example.com",
        new_value="email_c@example.com",
        event_time="2026-06-01T10:00:00Z",
    )
    service = IdentityResolutionService.from_data(identities=[user], audit_logs=[audit1, audit2])

    res = service.resolve_email("email_a@example.com", audit_at="2026-07-01T00:00:00Z")
    assert res.resolution_status == IdentityResolutionStatus.RESOLVED
    assert res.stable_subject_reference == "user_30"
    assert res.current_identifiers["email"] == "email_c@example.com"
    hist_raw = [h["raw_value"] for h in res.historical_identifiers if h["field_name"] == "email"]
    assert "email_a@example.com" in hist_raw
    assert "email_b@example.com" in hist_raw
    assert set(res.supporting_references) == {"audit_01", "audit_02"}


def test_case_and_whitespace_normalization():
    """Surrounding whitespace and casing differences are normalized without changing original spelling."""
    user = _make_identity(user_id="user_40", email="John.Doe@Example.COM")
    service = IdentityResolutionService.from_data(identities=[user], audit_logs=[])

    raw_req = "  JOHN.DOE@example.com  "
    res = service.resolve_email(raw_req, audit_at="2026-09-01T00:00:00Z")
    assert res.resolution_status == IdentityResolutionStatus.RESOLVED
    assert res.stable_subject_reference == "user_40"
    assert res.request_email == raw_req
    assert res.normalized_request_email == "john.doe@example.com"


def test_plus_tag_and_dotted_email_distinctions():
    """Plus tags and Gmail dots are preserved; provider-specific folding is strictly forbidden."""
    user = _make_identity(user_id="user_50", email="johndoe@gmail.com")
    service = IdentityResolutionService.from_data(identities=[user], audit_logs=[])

    # john.doe@gmail.com must NOT match johndoe@gmail.com
    res_dot = service.resolve_email("john.doe@gmail.com", audit_at="2026-09-01T00:00:00Z")
    assert res_dot.resolution_status == IdentityResolutionStatus.UNRESOLVED

    # johndoe+tag@gmail.com must NOT match johndoe@gmail.com
    res_plus = service.resolve_email("johndoe+tag@gmail.com", audit_at="2026-09-01T00:00:00Z")
    assert res_plus.resolution_status == IdentityResolutionStatus.UNRESOLVED


def test_historical_phone_and_hash_recovery():
    """Previous phones and hashes are recovered into historical_identifiers with proper provenance."""
    user = _make_identity(
        user_id="user_60",
        phone="+1 555 999 0000",
        email_hash="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        updated_at="2026-05-01T12:00:00Z",
    )
    p_audit = _make_audit(
        audit_id="audit_p1",
        user_id="user_60",
        field_name="phone",
        old_value="+1 555 111 2222",
        new_value="+1 555 999 0000",
        event_time="2026-04-01T08:00:00Z",
    )
    h_audit = _make_audit(
        audit_id="audit_h1",
        user_id="user_60",
        field_name="email_hash",
        old_value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        new_value="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        event_time="2026-04-01T08:00:00Z",
    )
    service = IdentityResolutionService.from_data(identities=[user], audit_logs=[p_audit, h_audit])
    res = service.resolve_email(user.email, audit_at="2026-06-01T00:00:00Z")

    assert res.resolution_status == IdentityResolutionStatus.RESOLVED
    assert res.current_identifiers["phone"] == "+1 555 999 0000"
    assert res.current_identifiers["email_hash"] == "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

    hist_phones = [h["raw_value"] for h in res.historical_identifiers if h["field_name"] == "phone"]
    assert "+1 555 111 2222" in hist_phones
    hist_hashes = [h["raw_value"] for h in res.historical_identifiers if h["field_name"] == "email_hash"]
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in hist_hashes


def test_no_match_returns_unresolved():
    """An email with no matching pre-cutoff snapshot or history returns UNRESOLVED."""
    service = IdentityResolutionService.from_data(identities=[], audit_logs=[])
    res = service.resolve_email("unknown@example.com", audit_at="2026-06-01T00:00:00Z")
    assert res.resolution_status == IdentityResolutionStatus.UNRESOLVED
    assert res.stable_subject_reference is None
    assert "unknown@example.com" in res.notes


def test_multiple_users_sharing_alias_returns_ambiguous():
    """If multiple users have pre-cutoff claims to an email, status remains AMBIGUOUS without mixing data."""
    user1 = _make_identity(user_id="user_01", email="shared@example.com")
    user2 = _make_identity(user_id="user_02", email="shared@example.com")
    service = IdentityResolutionService.from_data(identities=[user1, user2], audit_logs=[])

    res = service.resolve_email("shared@example.com", audit_at="2026-09-01T00:00:00Z")
    assert res.resolution_status == IdentityResolutionStatus.AMBIGUOUS
    assert res.stable_subject_reference is None
    assert res.candidates == ["user_01", "user_02"]
    assert res.current_identifiers == {}
    assert res.historical_identifiers == []


def test_shared_phone_numbers_without_cross_user_merging():
    """Two users sharing a phone number are never merged; resolution by email only recovers that user."""
    user_a = _make_identity(user_id="user_a", email="alice@example.com", phone="+1 555 888 8888")
    user_b = _make_identity(user_id="user_b", email="bob@example.com", phone="+1 555 888 8888")
    service = IdentityResolutionService.from_data(identities=[user_a, user_b], audit_logs=[])

    res = service.resolve_email("alice@example.com", audit_at="2026-09-01T00:00:00Z")
    assert res.resolution_status == IdentityResolutionStatus.RESOLVED
    assert res.stable_subject_reference == "user_a"
    assert "bob@example.com" not in res.searchable_identifiers
    assert "user_b" not in res.searchable_identifiers


def test_future_change_exclusion():
    """An audit event after audit_at is completely excluded from resolution and identifiers."""
    user = _make_identity(user_id="user_70", email="old@example.com", updated_at="2026-01-01T00:00:00Z")
    future_audit = _make_audit(
        audit_id="audit_future",
        user_id="user_70",
        field_name="email",
        old_value="old@example.com",
        new_value="future_new@example.com",
        event_time="2026-08-01T00:00:00Z",
    )
    service = IdentityResolutionService.from_data(identities=[user], audit_logs=[future_audit])

    # Cutoff before future change
    res = service.resolve_email("old@example.com", audit_at="2026-06-01T00:00:00Z")
    assert res.resolution_status == IdentityResolutionStatus.RESOLVED
    assert res.current_identifiers["email"] == "old@example.com"
    assert "future_new@example.com" not in res.searchable_identifiers
    assert "audit_future" not in res.supporting_references

    # Querying future_new at pre-cutoff must be UNRESOLVED
    res_future = service.resolve_email("future_new@example.com", audit_at="2026-06-01T00:00:00Z")
    assert res_future.resolution_status == IdentityResolutionStatus.UNRESOLVED


def test_change_exactly_at_cutoff():
    """An event occurring exactly at audit_at is inclusively eligible."""
    user = _make_identity(user_id="user_80", email="email_new@example.com", updated_at="2026-05-01T12:00:00Z")
    audit = _make_audit(
        audit_id="audit_exact",
        user_id="user_80",
        field_name="email",
        old_value="email_old@example.com",
        new_value="email_new@example.com",
        event_time="2026-05-01T12:00:00Z",
    )
    service = IdentityResolutionService.from_data(identities=[user], audit_logs=[audit])

    res = service.resolve_email("email_old@example.com", audit_at="2026-05-01T12:00:00Z")
    assert res.resolution_status == IdentityResolutionStatus.RESOLVED
    assert res.stable_subject_reference == "user_80"
    assert "audit_exact" in res.supporting_references


def test_future_snapshot_without_sufficient_earlier_evidence():
    """A snapshot updated after cutoff cannot establish pre-cutoff identity without prior evidence."""
    user = _make_identity(user_id="user_90", email="future_snap@example.com", updated_at="2026-10-01T00:00:00Z")
    service = IdentityResolutionService.from_data(identities=[user], audit_logs=[])

    res = service.resolve_email("future_snap@example.com", audit_at="2026-06-01T00:00:00Z")
    assert res.resolution_status == IdentityResolutionStatus.UNRESOLVED


def test_earlier_history_establishing_subject_despite_later_snapshot():
    """Pre-cutoff audit log establishes identity even when snapshot is in the future."""
    user = _make_identity(user_id="user_95", email="future_email@example.com", updated_at="2026-10-01T00:00:00Z")
    audit = _make_audit(
        audit_id="audit_past",
        user_id="user_95",
        field_name="email",
        old_value="past_email@example.com",
        new_value="intermediate@example.com",
        event_time="2026-03-01T12:00:00Z",
    )
    service = IdentityResolutionService.from_data(identities=[user], audit_logs=[audit])

    res = service.resolve_email("past_email@example.com", audit_at="2026-06-01T00:00:00Z")
    assert res.resolution_status == IdentityResolutionStatus.RESOLVED
    assert res.stable_subject_reference == "user_95"
    assert res.current_identifiers["email"] == "intermediate@example.com"
    assert "future_email@example.com" not in res.searchable_identifiers


def test_cleared_identifier_values():
    """Empty old or new values represent clearing/absence and never become searchable identifiers."""
    user = _make_identity(user_id="user_clr", phone="", updated_at="2026-05-01T00:00:00Z")
    audit = _make_audit(
        audit_id="audit_clr",
        user_id="user_clr",
        field_name="phone",
        old_value="+1 555 123 4567",
        new_value="",
        event_time="2026-04-01T00:00:00Z",
    )
    service = IdentityResolutionService.from_data(identities=[user], audit_logs=[audit])
    res = service.resolve_email(user.email, audit_at="2026-06-01T00:00:00Z")

    assert res.resolution_status == IdentityResolutionStatus.RESOLVED
    assert "" not in res.searchable_identifiers
    # Phone was cleared, so not present in current_identifiers
    assert "phone" not in res.current_identifiers


def test_conflicting_or_broken_change_chains():
    """Broken transition chain is recorded as a warning while preserving both values."""
    user = _make_identity(user_id="user_brk", email="val_c@example.com", updated_at="2026-06-01T00:00:00Z")
    a1 = _make_audit("a1", "user_brk", "email", "val_a@example.com", "val_b@example.com", "2026-02-01T00:00:00Z")
    a2 = _make_audit("a2", "user_brk", "email", "val_gap@example.com", "val_c@example.com", "2026-05-01T00:00:00Z")
    service = IdentityResolutionService.from_data(identities=[user], audit_logs=[a1, a2])

    res = service.resolve_email("val_a@example.com", audit_at="2026-07-01T00:00:00Z")
    assert res.resolution_status == IdentityResolutionStatus.RESOLVED
    assert any("Discontinuous audit chain" in w for w in res.warnings)
    assert "val_a@example.com" in res.searchable_identifiers
    assert "val_b@example.com" in res.searchable_identifiers
    assert "val_gap@example.com" in res.searchable_identifiers
    assert "val_c@example.com" in res.searchable_identifiers


def test_equal_time_conflicting_events():
    """Conflicting events at identical timestamps surface a conflict diagnostic."""
    user = _make_identity(user_id="user_eq", email="eq@example.com", updated_at="2026-05-01T00:00:00Z")
    a1 = _make_audit("eq1", "user_eq", "email", "v0@example.com", "v1@example.com", "2026-03-01T10:00:00Z")
    a2 = _make_audit("eq2", "user_eq", "email", "v0@example.com", "v2@example.com", "2026-03-01T10:00:00Z")
    service = IdentityResolutionService.from_data(identities=[user], audit_logs=[a1, a2])

    res = service.resolve_email("eq@example.com", audit_at="2026-06-01T00:00:00Z")
    assert res.resolution_status == IdentityResolutionStatus.RESOLVED
    assert len(res.conflicts) > 0
    assert any("Conflicting audit events" in c for c in res.conflicts)


def test_shuffled_input_producing_identical_results():
    """Shuffling audit log input rows produces strictly deterministic, identical results."""
    user = _make_identity(user_id="user_shf", email="c@example.com", updated_at="2026-06-01T00:00:00Z")
    logs_ordered = [
        _make_audit("a1", "user_shf", "email", "a@example.com", "b@example.com", "2026-02-01T00:00:00Z"),
        _make_audit("a2", "user_shf", "email", "b@example.com", "c@example.com", "2026-05-01T00:00:00Z"),
    ]
    logs_reversed = list(reversed(logs_ordered))

    s1 = IdentityResolutionService.from_data(identities=[user], audit_logs=logs_ordered)
    s2 = IdentityResolutionService.from_data(identities=[user], audit_logs=logs_reversed)

    r1 = s1.resolve_email("a@example.com", audit_at="2026-07-01T00:00:00Z")
    r2 = s2.resolve_email("a@example.com", audit_at="2026-07-01T00:00:00Z")

    assert r1.model_dump() == r2.model_dump()


def test_exact_stable_id_boundaries():
    """user_10 does not match user_100 or user_1."""
    u10 = _make_identity(user_id="user_10", email="u10@example.com")
    u100 = _make_identity(user_id="user_100", email="u100@example.com")
    service = IdentityResolutionService.from_data(identities=[u10, u100], audit_logs=[])

    r10 = service.resolve_email("u10@example.com", audit_at="2026-09-01T00:00:00Z")
    assert r10.stable_subject_reference == "user_10"
    assert "user_100" not in r10.searchable_identifiers

    r100 = service.resolve_email("u100@example.com", audit_at="2026-09-01T00:00:00Z")
    assert r100.stable_subject_reference == "user_100"
    assert "user_10" not in r100.searchable_identifiers


def test_provenance_preserved_after_deduplication():
    """When an identifier appears across snapshot and audit logs, both sources are retained."""
    user = _make_identity(user_id="user_dup", email="same@example.com", updated_at="2026-05-01T00:00:00Z")
    audit = _make_audit(
        "dup_audit", "user_dup", "email", "initial@example.com", "same@example.com", "2026-04-01T00:00:00Z"
    )
    service = IdentityResolutionService.from_data(identities=[user], audit_logs=[audit])

    res = service.resolve_email("same@example.com", audit_at="2026-06-01T00:00:00Z")
    assert res.resolution_status == IdentityResolutionStatus.RESOLVED

    # Check that provenance records include both SNAPSHOT and AUDIT_LOG
    source_types = {p["source_type"] for p in res.provenance if p["field_name"] == "email"}
    assert SourceType.SNAPSHOT in source_types
    assert SourceType.AUDIT_LOG in source_types


def test_cli_execution_and_options(tmp_path: Path):
    """Test CLI subcommands: --case, --sample, --email, --batch, and exit codes."""
    code_main = Path(__file__).resolve().parent.parent / "code" / "main.py"

    # Test 1: Sample case resolution as JSON
    cmd1 = [sys.executable, str(code_main), "resolve-identity", "--case", "case_01", "--sample", "--json"]
    proc1 = subprocess.run(cmd1, capture_output=True, text=True, check=True)
    data1 = json.loads(proc1.stdout)
    assert data1["resolution_status"] == "RESOLVED"
    assert data1["stable_subject_reference"] == "user_01"

    # Test 2: Direct email resolution
    cmd2 = [
        sys.executable,
        str(code_main),
        "resolve-identity",
        "--email",
        "amina.elmasri@gmail.com",
        "--audit-at",
        "2026-09-03T11:30:00Z",
        "--json",
    ]
    proc2 = subprocess.run(cmd2, capture_output=True, text=True, check=True)
    data2 = json.loads(proc2.stdout)
    assert data2["resolution_status"] == "RESOLVED"
    assert data2["stable_subject_reference"] == "user_01"

    # Test 3: Batch sample resolution
    cmd3 = [sys.executable, str(code_main), "resolve-identity", "--batch", "--sample", "--json"]
    proc3 = subprocess.run(cmd3, capture_output=True, text=True, check=True)
    data3 = json.loads(proc3.stdout)
    assert data3["total_requests"] == 32
    assert data3["status_counts"]["RESOLVED"] == 32

    # Test 4: Execution from another working directory
    proc4 = subprocess.run(
        [sys.executable, str(code_main), "resolve-identity", "--case", "case_01", "--sample", "--json"],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        check=True,
    )
    data4 = json.loads(proc4.stdout)
    assert data4["resolution_status"] == "RESOLVED"

    # Test 5: Missing audit-at with email produces exit code 2
    proc5 = subprocess.run(
        [sys.executable, str(code_main), "resolve-identity", "--email", "test@example.com"],
        capture_output=True,
        text=True,
    )
    assert proc5.returncode == 2


def test_batch_resolution_on_dataset_files():
    """Verify that all 518 evaluation requests and 32 sample requests resolve cleanly without crashing."""
    code_main = Path(__file__).resolve().parent.parent / "code" / "main.py"

    # Evaluation requests
    cmd_eval = [sys.executable, str(code_main), "resolve-identity", "--batch", "--json"]
    proc_eval = subprocess.run(cmd_eval, capture_output=True, text=True, check=True)
    eval_data = json.loads(proc_eval.stdout)

    assert eval_data["total_requests"] == 518
    assert eval_data["status_counts"]["RESOLVED"] == 518
    assert eval_data["match_methods"]["CURRENT_SNAPSHOT_EMAIL"] == 417
    assert eval_data["match_methods"]["HISTORICAL_AUDIT_LOG_OLD_EMAIL"] == 100
    assert eval_data["match_methods"]["SNAPSHOT_AND_HISTORICAL_EMAIL"] == 1

    # Sample requests
    cmd_sample = [sys.executable, str(code_main), "resolve-identity", "--batch", "--sample", "--json"]
    proc_sample = subprocess.run(cmd_sample, capture_output=True, text=True, check=True)
    sample_data = json.loads(proc_sample.stdout)

    assert sample_data["total_requests"] == 32
    assert sample_data["status_counts"]["RESOLVED"] == 32
    assert sample_data["match_methods"]["CURRENT_SNAPSHOT_EMAIL"] == 28
    assert sample_data["match_methods"]["HISTORICAL_AUDIT_LOG_OLD_EMAIL"] == 3
    assert sample_data["match_methods"]["SNAPSHOT_AND_HISTORICAL_EMAIL"] == 1
