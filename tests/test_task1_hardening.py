"""Regression cases for Task 1 review findings; no prediction logic."""

import csv
import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from ghost_audit.loader import DataLoader
from ghost_audit.models.input_models import DeletionRequest, UserAuditLogEntry, UserIdentity
from ghost_audit.models.intermediate_models import EvidenceObservation, IdentityResolutionResult
from ghost_audit.models.output_models import OutputRow, Step
from ghost_audit.timestamps import format_iso_timestamp, is_within_audit_cutoff, parse_iso_timestamp


REQUEST = {
    "case_id": "case_test", "email": "person@example.test",
    "requested_at": "2026-01-01T00:00:00Z", "reported_status": "COMPLETE",
    "reported_at": "2026-01-02T00:00:00Z", "audit_at": "2026-01-03T00:00:00Z",
    "request_text": "Please delete my account.",
}
VERIFY = {
    "step_no": 1, "phase": "VERIFICATION", "system_id": "account_service",
    "resource_id": "account_test", "operation": "VERIFY_RECORD_ABSENT",
    "state": "ABSENT", "evidence_id": "evidence_test",
}


def write_requests(path, records, headers=None):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers or list(REQUEST))
        writer.writeheader()
        writer.writerows(records)


@pytest.mark.parametrize("field", ["case_id", "email", "request_text"])
@pytest.mark.parametrize("value", ["", "  \t"])
def test_required_request_values_are_nonblank(field, value, tmp_path):
    data = {**REQUEST, field: value}
    with pytest.raises(ValidationError):
        DeletionRequest.model_validate(data)
    path = tmp_path / "deletion_requests.csv"
    write_requests(path, [data])
    records, issues = DataLoader().load_deletion_requests(path)
    assert records == []
    assert any(i.severity == "ERROR" and i.field_name == field and i.row_index == 2 for i in issues)


def test_optional_identity_fields_and_cleared_historical_values_are_preserved():
    identity = UserIdentity(user_id="user_test", name="Test Person", email="p@example.test",
                            phone="", email_hash="", updated_at=REQUEST["audit_at"])
    assert identity.phone == identity.email_hash == ""
    change = UserAuditLogEntry(audit_id="audit_test", user_id="user_test",
                               event_time=REQUEST["audit_at"], field_name="phone",
                               old_value="+1234", new_value="")
    assert change.new_value == ""


def test_duplicate_header_cannot_overwrite_email(tmp_path):
    path = tmp_path / "deletion_requests.csv"
    headers = list(REQUEST) + ["email"]
    write_requests(path, [REQUEST], headers)
    records, issues = DataLoader().load_deletion_requests(path)
    assert not records
    assert any(i.row_index == 1 and "duplicate headers" in i.message for i in issues)


def test_duplicate_primary_ids_do_not_enter_validated_records(tmp_path):
    path = tmp_path / "deletion_requests.csv"
    write_requests(path, [REQUEST, REQUEST])
    records, issues = DataLoader().load_deletion_requests(path)
    assert len(records) == 1
    assert any(i.row_index == 3 and "Duplicate primary" in i.message for i in issues)


def test_physical_error_lines_survive_skipped_and_multiline_rows(tmp_path):
    path = tmp_path / "deletion_requests.csv"
    write_requests(path, [dict(REQUEST, request_text="First line\nSecond line")])
    with path.open("a", encoding="utf-8", newline="") as handle:
        handle.write("too,few,cells\n\n")
        csv.DictWriter(handle, fieldnames=list(REQUEST)).writerow(dict(REQUEST, case_id="case_bad", email=""))
    records, issues = DataLoader().load_deletion_requests(path)
    assert len(records) == 1
    assert any(i.row_index == 4 and "Malformed row" in i.message for i in issues)
    assert any(i.row_index == 6 and i.field_name == "email" for i in issues)


def test_unterminated_quoted_csv_is_fatal(tmp_path):
    path = tmp_path / "deletion_requests.csv"
    path.write_text(",".join(REQUEST) + '\n"unterminated', encoding="utf-8")
    records, issues = DataLoader().load_deletion_requests(path)
    assert not records
    assert any(i.severity == "ERROR" and "Malformed CSV syntax" in i.message for i in issues)


@pytest.mark.parametrize("field", ["capture_time", "observation_time"])
def test_observation_rejects_naive_timestamps(field):
    data = {"evidence_id": "evidence_test", "capture_time": REQUEST["audit_at"],
            field: "2026-01-01T00:00:00"}
    with pytest.raises(ValidationError, match="timezone-naive"):
        EvidenceObservation(**data)


def test_intermediate_timestamps_normalize_offsets_and_allow_retention_expiry():
    observation = EvidenceObservation(evidence_id="evidence_test",
        capture_time="2026-01-01T05:30:00+05:30", observation_time=None)
    assert observation.capture_time == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert observation.observation_time is None
    result = IdentityResolutionResult(applicable_timestamps={
        "snapshot": "2026-01-01T05:30:00+05:30", "retention_until": "2031-01-01T00:00:00Z"})
    assert result.applicable_timestamps["snapshot"] == observation.capture_time
    assert result.applicable_timestamps["retention_until"].year == 2031
    with pytest.raises(ValidationError, match="timezone-naive"):
        IdentityResolutionResult(applicable_timestamps={"change": "2026-01-01T00:00:00"})


def test_resolved_identity_requires_subject():
    with pytest.raises(ValidationError, match="stable subject reference"):
        IdentityResolutionResult(resolution_status="RESOLVED")
    assert IdentityResolutionResult().resolution_status == "UNRESOLVED"


@pytest.mark.parametrize("status,steps", [
    ("COMPLETE", []), ("INCOMPLETE", []), ("NOT_APPLICABLE", [VERIFY]),
    ("COMPLETE", [{**VERIFY, "evidence_id": ""}]),
    ("COMPLETE", [{**VERIFY, "step_no": 2}]),
])
def test_invalid_output_rejected_at_construction(status, steps):
    with pytest.raises(ValidationError):
        OutputRow(case_id="case_test", deletion_status=status, steps=steps)


def test_serialization_revalidates_mutable_step_list():
    row = OutputRow(case_id="case_test", deletion_status="COMPLETE", steps=[Step(**VERIFY)])
    row.steps.clear()
    with pytest.raises(ValidationError):
        row.steps_json_string()
    with pytest.raises(ValidationError):
        row.to_csv_record()


@pytest.mark.parametrize("field,value", [
    ("system_id", " "), ("resource_id", ""), ("evidence_id", " \t"),
    ("step_no", True), ("step_no", "1"), ("step_no", 1.0),
])
def test_step_fields_are_strict(field, value):
    with pytest.raises(ValidationError):
        Step(**{**VERIFY, field: value})


def test_duplicate_steps_are_rejected():
    with pytest.raises(ValidationError, match="Duplicate operation"):
        OutputRow(case_id="case_test", deletion_status="COMPLETE",
                  steps=[VERIFY, {**VERIFY, "step_no": 2}])


def test_all_public_sample_answers_satisfy_output_contract(real_dataset_dir):
    # Schema checking only: reference answers are never loaded by DataLoader.
    with (real_dataset_dir / "sample_output.csv").open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 32
    for item in rows:
        row = OutputRow(case_id=item["case_id"], deletion_status=item["deletion_status"],
                        steps=json.loads(item["steps_json"]))
        assert json.loads(row.to_csv_record()[2]) == json.loads(item["steps_json"])


@pytest.mark.parametrize("value", ["2026-01-01T00:00:00.000001Z", "2026-01-01T05:30:00.900000+05:30"])
def test_fractional_seconds_round_trip_without_moving_cutoff(value):
    original = parse_iso_timestamp(value)
    restored = parse_iso_timestamp(format_iso_timestamp(original))
    assert restored == original
    cutoff = parse_iso_timestamp("2026-01-01T00:00:00Z")
    assert not is_within_audit_cutoff(restored, cutoff)
