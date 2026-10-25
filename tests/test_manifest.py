"""Tests for evidence manifest validation, path traversal detection, and file presence."""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from ghost_audit.manifest import validate_evidence_manifest
from ghost_audit.models.input_models import EvidenceManifestEntry


def test_valid_manifest_resolution(tmp_path: Path):
    dataset_dir = tmp_path / "dataset"
    evidence_dir = dataset_dir / "evidence" / "logs"
    evidence_dir.mkdir(parents=True)

    log_file = evidence_dir / "test.log"
    log_file.write_text("log content", encoding="utf-8")

    entries = [
        EvidenceManifestEntry(
            file_id="evidence_01",
            file_path="evidence/logs/test.log",
            origin="test_service",
            captured_at=datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc),
        )
    ]

    result = validate_evidence_manifest(entries, dataset_dir)
    assert result.is_valid is True
    assert result.total_entries == 1
    assert result.valid_files == 1
    assert result.extension_counts == {".log": 1}
    assert result.errors == []


def test_missing_evidence_file(tmp_path: Path):
    dataset_dir = tmp_path / "dataset"
    evidence_dir = dataset_dir / "evidence"
    evidence_dir.mkdir(parents=True)

    entries = [
        EvidenceManifestEntry(
            file_id="evidence_missing",
            file_path="evidence/logs/nonexistent.log",
            origin="test_service",
            captured_at=datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc),
        )
    ]

    result = validate_evidence_manifest(entries, dataset_dir)
    assert result.is_valid is False
    assert len(result.missing_files) == 1
    assert "Evidence file missing" in result.missing_files[0]


def test_path_traversal_detection(tmp_path: Path):
    dataset_dir = tmp_path / "dataset"
    evidence_dir = dataset_dir / "evidence"
    evidence_dir.mkdir(parents=True)

    # File outside evidence dir
    outside_file = dataset_dir / "secret.txt"
    outside_file.write_text("secret", encoding="utf-8")

    entries = [
        EvidenceManifestEntry(
            file_id="evidence_traversal",
            file_path="../secret.txt",
            origin="malicious",
            captured_at=datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc),
        )
    ]

    result = validate_evidence_manifest(entries, dataset_dir)
    assert result.is_valid is False
    assert len(result.path_traversal_errors) == 1
    assert "Path traversal error" in result.path_traversal_errors[0]


def test_duplicate_file_id_detection(tmp_path: Path):
    dataset_dir = tmp_path / "dataset"
    evidence_dir = dataset_dir / "evidence"
    evidence_dir.mkdir(parents=True)

    f = evidence_dir / "file.txt"
    f.write_text("content", encoding="utf-8")

    entries = [
        EvidenceManifestEntry(
            file_id="evidence_dup",
            file_path="evidence/file.txt",
            origin="svc1",
            captured_at=datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc),
        ),
        EvidenceManifestEntry(
            file_id="evidence_dup",
            file_path="evidence/file.txt",
            origin="svc2",
            captured_at=datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc),
        ),
    ]

    result = validate_evidence_manifest(entries, dataset_dir)
    assert result.is_valid is False
    assert "evidence_dup" in result.duplicate_ids
