"""Tests for CSV loader, Unicode/BOM handling, header and row validation, and model validation."""

from pathlib import Path
import pytest

from ghost_audit.config import Settings
from ghost_audit.loader import DataLoader
from ghost_audit.models.input_models import (
    DataCategory,
    DeletionRequest,
    ReportedStatus,
    RequiredAction,
    UserIdentity,
)


def test_unicode_and_bom_support(tmp_path: Path):
    csv_path = tmp_path / "user_identities.csv"
    # Write with UTF-8 BOM and non-ASCII Unicode names
    content = (
        "\ufeffuser_id,name,email,phone,email_hash,updated_at\n"
        'user_01,"Mateo Ríos",mateo.rios@outlook.com,+34 612 847 593,hash1,2026-04-24T07:44:00Z\n'
        'user_02,"Amina El-Masri",amina@gmail.com,+971 50 482 7316,hash2,2026-05-28T04:03:00Z\n'
    )
    csv_path.write_bytes(content.encode("utf-8"))

    loader = DataLoader(Settings(dataset_dir=tmp_path))
    records, issues = loader.load_user_identities(csv_path)

    assert len(issues) == 0
    assert len(records) == 2
    assert records[0].name == "Mateo Ríos"
    assert records[1].name == "Amina El-Masri"


def test_missing_required_headers(tmp_path: Path):
    csv_path = tmp_path / "user_identities.csv"
    # Missing 'phone' and 'email_hash'
    content = "user_id,name,email,updated_at\nuser_01,Test,test@example.com,2026-01-01T00:00:00Z\n"
    csv_path.write_text(content, encoding="utf-8")

    loader = DataLoader(Settings(dataset_dir=tmp_path))
    records, issues = loader.load_user_identities(csv_path)

    assert len(records) == 0
    assert any(i.severity == "ERROR" and "Missing required headers" in i.message for i in issues)


def test_malformed_csv_row_surplus_or_missing_cells(tmp_path: Path):
    csv_path = tmp_path / "user_identities.csv"
    content = (
        "user_id,name,email,phone,email_hash,updated_at\n"
        "user_01,Test,test@example.com,+1234,hash,2026-01-01T00:00:00Z\n"
        "user_02,Test2,test2@example.com,+1234\n"  # Missing cells
        "user_03,Test3,test3@example.com,+1234,hash,2026-01-01T00:00:00Z,extra_cell\n"  # Surplus cell
    )
    csv_path.write_text(content, encoding="utf-8")

    loader = DataLoader(Settings(dataset_dir=tmp_path))
    records, issues = loader.load_user_identities(csv_path)

    assert len(records) == 1
    malformed_issues = [i for i in issues if "Malformed row" in i.message]
    assert len(malformed_issues) == 2
    assert malformed_issues[0].row_index == 3
    assert malformed_issues[1].row_index == 4


def test_duplicate_primary_identifier(tmp_path: Path):
    csv_path = tmp_path / "deletion_requests.csv"
    content = (
        "case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\n"
        "case_01,a@example.com,2026-08-01T00:00:00Z,COMPLETE,2026-08-02T00:00:00Z,2026-08-03T00:00:00Z,delete\n"
        "case_01,b@example.com,2026-08-01T00:00:00Z,COMPLETE,2026-08-02T00:00:00Z,2026-08-03T00:00:00Z,delete\n"
    )
    csv_path.write_text(content, encoding="utf-8")

    loader = DataLoader(Settings(dataset_dir=tmp_path))
    records, issues = loader.load_deletion_requests(csv_path)

    assert any(i.severity == "ERROR" and "Duplicate primary identifier" in i.message for i in issues)


def test_invalid_enum_value(tmp_path: Path):
    csv_path = tmp_path / "deletion_requests.csv"
    content = (
        "case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\n"
        "case_01,a@example.com,2026-08-01T00:00:00Z,INVALID_STATUS,2026-08-02T00:00:00Z,2026-08-03T00:00:00Z,delete\n"
    )
    csv_path.write_text(content, encoding="utf-8")

    loader = DataLoader(Settings(dataset_dir=tmp_path))
    records, issues = loader.load_deletion_requests(csv_path)

    assert len(records) == 0
    assert any(i.severity == "ERROR" and "reported_status" in (i.field_name or "") for i in issues)


def test_separation_of_sample_reference_answers(real_dataset_dir: Path):
    # Ensure DataLoader does NOT load sample_output.csv when loading dataset bundle
    loader = DataLoader(Settings(dataset_dir=real_dataset_dir))
    bundle_eval = loader.load_bundle(sample=False)
    bundle_sample = loader.load_bundle(sample=True)

    # Neither bundle should contain sample_output answers
    assert not hasattr(bundle_eval, "sample_output")
    assert not hasattr(bundle_sample, "sample_output")
    assert len(bundle_eval.requests) == 518
    assert len(bundle_sample.requests) == 32
