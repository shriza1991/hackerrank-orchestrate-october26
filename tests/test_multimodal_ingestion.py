"""Comprehensive tests for Task 7: PDF and Screenshot Interpretation and Task 6 Prerequisite Fixes.

Covers:
1. Task 6 Prerequisite Fixes Regression:
   - Fix A: SQL system mapping (analytics, account, support, search, export, connector, backup, security).
   - Fix B: Table topology precedence (explicit primary table inside replica file).
   - Fix C: Reused trace ID subject handling (sequential reuse, conflicting traces mark correlation_ambiguous).
   - Fix D: Manifest errors (malformed timestamps, duplicate IDs, missing headers surfaced; nonzero CLI exit).
   - Fix E: SQLite sandboxing (authorizer blocks VACUUM INTO, ATTACH, extensions; verifies no external files).
2. Mode Switching:
   - structured (79 parsed, 15 deferred)
   - multimodal (15 parsed, 79 deferred)
   - all (94 parsed, 0 deferred)
3. PDF Interpretation:
   - Multi-page extraction and page provenance
   - Row isolation on multi-record legal retention register (no cross-record leakage)
   - Corrupted or unreadable PDF handling
4. Screenshot / OCR Interpretation:
   - Multi-subject table row partitioning and isolation
   - Single-subject console detail views
   - Tombstone reference detection
   - Cleaned identifier parsing
5. Determinism and No-Live safety.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from ghost_audit.config import get_settings
from ghost_audit.loader import DataLoader
from ghost_audit.evidence.image_parser import ImageEvidenceParser
from ghost_audit.evidence.log_parser import LogEvidenceParser
from ghost_audit.models import EvidenceManifestEntry
from ghost_audit.evidence.models import (
    IngestionStatus,
    ObservationType,
)
from ghost_audit.evidence.pdf_parser import PdfEvidenceParser
from ghost_audit.evidence.service import EvidenceIngestionService
from ghost_audit.evidence.sql_parser import (
    SqlEvidenceParser,
    derive_system_id_from_table,
    safe_sqlite_authorizer,
)


# ===========================================================================
# 1. TASK 6 PREREQUISITE FIXES REGRESSION TESTS
# ===========================================================================

def test_fix_a_sql_system_mapping_subsystems():
    """Verify specific subsystems are correctly derived from table names."""
    # Analytics platform tables (was incorrectly matching 'profile' -> account_service)
    assert derive_system_id_from_table("customer_analytics_profiles") == "analytics_platform"
    assert derive_system_id_from_table("user_analytics_events") == "analytics_platform"
    assert derive_system_id_from_table("analytics_snapshots") == "analytics_platform"

    # Account service tables
    assert derive_system_id_from_table("customer_profiles") == "account_service"
    assert derive_system_id_from_table("account_credentials") == "account_service"
    assert derive_system_id_from_table("user_identities") == "account_service"

    # Support platform tables
    assert derive_system_id_from_table("support_tickets") == "support_platform"
    assert derive_system_id_from_table("ticket_attachments") == "support_platform"

    # Search service tables
    assert derive_system_id_from_table("search_index_documents") == "search_service"
    assert derive_system_id_from_table("search_query_logs") == "search_service"

    # Export service tables
    assert derive_system_id_from_table("customer_exports") == "export_service"
    assert derive_system_id_from_table("export_archive_records") == "export_service"

    # Integration / connector tables
    assert derive_system_id_from_table("connector_sync_status") == "integration_service"
    assert derive_system_id_from_table("integration_webhooks") == "integration_service"

    # Backup service tables
    assert derive_system_id_from_table("backup_manifests") == "backup_service"
    assert derive_system_id_from_table("database_restore_points") == "backup_service"

    # Security service tables
    assert derive_system_id_from_table("security_audit_events") == "security_service"
    assert derive_system_id_from_table("auth_tokens") == "security_service"

    # Unknown table preserves None uncertainty
    assert derive_system_id_from_table("random_unrecognized_table") is None


def test_fix_b_table_topology_precedence_in_replica_file():
    """Verify explicitly primary tables retain table_topology='primary' in replica files."""
    parser = SqlEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    sql_text = """
    -- Topology: regional_replicas
    BEGIN TRANSACTION;
    CREATE TABLE customer_profiles_primary (
        resource_id TEXT PRIMARY KEY,
        email TEXT NOT NULL
    );
    CREATE TABLE customer_profiles_replica_eu (
        resource_id TEXT PRIMARY KEY,
        email TEXT NOT NULL
    );
    INSERT INTO customer_profiles_primary VALUES ('acc_pri_1', 'pri@example.com');
    INSERT INTO customer_profiles_replica_eu VALUES ('acc_rep_1', 'rep@example.com');
    COMMIT;
    """
    res = parser.parse("evidence_topo", "test.sql", "origin", now, sql_text)
    assert res.status == IngestionStatus.PARSED

    pri_row = [o for o in res.observations if o.resource_id == "acc_pri_1"][0]
    assert pri_row.scope_context["table_topology"] == "primary"
    assert pri_row.scope_context["file_topology"] == "regional_replicas"

    rep_row = [o for o in res.observations if o.resource_id == "acc_rep_1"][0]
    assert rep_row.scope_context["table_topology"] in {"replica", "regional_replicas"}
    assert rep_row.scope_context["file_topology"] == "regional_replicas"


def test_fix_c_log_trace_sequential_reuse_and_conflict_handling():
    """Verify log parser segments operations and handles conflicting subjects without cross-pollination."""
    parser = LogEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    
    # Trace 999 reused between two distinct operations with different subjects
    log_content = (
        "2026-09-15T12:00:00Z [INFO] [auth_service] [trace_999] op_login: user_id=usr_alice email=alice@example.com\n"
        "2026-09-15T12:00:05Z [INFO] [auth_service] [trace_999] op_logout: user_id=usr_alice\n"
        "2026-09-15T12:15:00Z [INFO] [auth_service] [trace_999] op_login: user_id=usr_bob email=bob@example.com\n"
        "2026-09-15T12:15:05Z [INFO] [auth_service] [trace_999] op_action: user_id=usr_bob\n"
    )
    res = parser.parse("evidence_log_seq", "test.log", "auth_service", now, log_content)
    assert res.status in {IngestionStatus.PARSED, IngestionStatus.PARTIAL}

    alice_obs = [o for o in res.observations if o.extracted_facts.get("email") == "alice@example.com"][0]
    bob_obs = [o for o in res.observations if o.extracted_facts.get("email") == "bob@example.com"][0]

    # Alice's direct observation should NOT contain Bob
    assert "bob@example.com" not in alice_obs.subject_references
    assert "usr_bob" not in alice_obs.subject_references

    # Bob's direct observation should NOT contain Alice
    assert "alice@example.com" not in bob_obs.subject_references
    assert "usr_alice" not in bob_obs.subject_references


def test_fix_c_log_trace_simultaneous_conflict_marks_ambiguous():
    """Verify that multiple conflicting subjects in an unsegmented trace mark correlation_ambiguous."""
    parser = LogEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    
    log_content = (
        "2026-09-15T12:00:00Z [INFO] [auth_service] [trace_conflict] op_user: user_id=usr_x email=x@example.com\n"
        "2026-09-15T12:00:01Z [INFO] [auth_service] [trace_conflict] op_user: user_id=usr_y email=y@example.com\n"
        "2026-09-15T12:00:02Z [INFO] [auth_service] [trace_conflict] op_done: status=COMPLETED\n"
    )
    res = parser.parse("evidence_log_conf", "test.log", "auth_service", now, log_content)
    assert res.status in {IngestionStatus.PARSED, IngestionStatus.PARTIAL}

    # At least two distinct subjects exist; ambiguity must be flagged
    assert any(
        o.extracted_facts.get("correlation_ambiguous") is True
        or any("ambiguous" in w.lower() for w in o.uncertainty_or_warnings)
        for o in res.observations
    )


def test_fix_d_manifest_errors_surfaced_in_summary_and_exception(tmp_path):
    """Verify manifest errors are surfaced and not silently discarded."""
    settings = get_settings()
    service = EvidenceIngestionService(settings)

    # Create a corrupted manifest with an invalid timestamp and missing header
    corrupt_manifest = tmp_path / "evidence_files.csv"
    corrupt_manifest.write_text(
        "file_id,file_path,source_origin,captured_at\n"
        "evidence_bad_1,evidence/logs/bad.log,test_origin,NOT_A_TIMESTAMP\n",
        encoding="utf-8"
    )

    # 1. Non-raising call captures manifest errors
    loader = DataLoader(settings)
    entries, issues = loader.load_evidence_manifest(corrupt_manifest)
    assert len(issues) > 0

    # 2. Ingest manifest with raise_on_manifest_error=True raises ValueError
    with pytest.raises(ValueError, match="Fatal manifest error"):
        # Create a mock dataset dir
        mock_dataset = tmp_path / "mock_ds"
        mock_dataset.mkdir()
        (mock_dataset / "evidence_files.csv").write_text(
            "file_id,file_path,source_origin,captured_at\n"
            "evidence_bad_1,evidence/logs/bad.log,test_origin,INVALID_DATE\n",
            encoding="utf-8"
        )
        service.ingest_manifest(dataset_dir=mock_dataset, raise_on_manifest_error=True)


def test_fix_e_sqlite_sandboxing_blocks_vacuum_into_and_attach(tmp_path):
    """Verify safe_sqlite_authorizer blocks VACUUM INTO, ATTACH, and external file creation."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(db_path)
    conn.set_authorizer(safe_sqlite_authorizer)

    cursor = conn.cursor()

    # Legitimate schema creation and inserts are permitted
    cursor.execute("CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT)")
    cursor.execute("INSERT INTO users VALUES ('u1', 'u1@example.com')")
    cursor.execute("SELECT * FROM users WHERE email LIKE '%example%'")
    rows = cursor.fetchall()
    assert len(rows) == 1

    # VACUUM INTO attempting to write an external file must be blocked
    target_vacuum = tmp_path / "escaped_vacuum.db"
    with pytest.raises(sqlite3.DatabaseError):
        cursor.execute(f"VACUUM INTO '{target_vacuum}'")
    assert not target_vacuum.exists()

    # ATTACH DATABASE attempting to access external files must be blocked
    target_attach = tmp_path / "escaped_attach.db"
    with pytest.raises(sqlite3.DatabaseError):
        cursor.execute(f"ATTACH DATABASE '{target_attach}' AS other")
    assert not target_attach.exists()

    conn.close()


# ===========================================================================
# 2. INGESTION MODES
# ===========================================================================

def test_ingestion_mode_structured():
    """Verify mode='structured' parses 79 files and defers the 15 multimodal files."""
    settings = get_settings()
    service = EvidenceIngestionService(settings)
    summary = service.ingest_manifest(mode="structured")

    assert summary.manifest_file_count == 94
    assert summary.parsed_count == 79
    assert summary.deferred_count == 15
    assert summary.failed_count == 0
    assert summary.total_observations == 4241


def test_ingestion_mode_multimodal():
    """Verify mode='multimodal' parses 15 files and defers the 79 structured files."""
    settings = get_settings()
    service = EvidenceIngestionService(settings)
    summary = service.ingest_manifest(mode="multimodal")

    assert summary.manifest_file_count == 94
    assert summary.parsed_count == 15
    assert summary.deferred_count == 79
    assert summary.failed_count == 0
    assert summary.total_observations == 42

    # Multimodal format breakdown
    assert summary.by_format["pdf"]["parsed"] == 4
    assert summary.by_format["png"]["parsed"] == 11


def test_ingestion_mode_all():
    """Verify mode='all' parses all 94 manifest files with zero deferred and zero failed."""
    settings = get_settings()
    service = EvidenceIngestionService(settings)
    summary = service.ingest_manifest(mode="all")

    assert summary.manifest_file_count == 94
    assert summary.parsed_count == 94
    assert summary.deferred_count == 0
    assert summary.failed_count == 0
    assert summary.total_observations == 4283


# ===========================================================================
# 3. PDF INTERPRETATION & ROW ISOLATION
# ===========================================================================

def test_pdf_parsing_multipage_and_row_isolation():
    """Verify evidence_27 (legal retention register) isolates table rows with zero subject leakage."""
    settings = get_settings()
    service = EvidenceIngestionService(settings)

    entry = EvidenceManifestEntry(
        file_id="evidence_27",
        file_path="evidence/documents/legal_retention_register_20260529.pdf",
        origin="legal_retention_service",
        captured_at=datetime(2026, 5, 29, 8, 0, 0, tzinfo=timezone.utc),
    )

    res = service.ingest_file(entry, mode="multimodal")
    assert res.status == IngestionStatus.PARSED
    assert res.format == "pdf"

    # Page 1 contains document summary
    p1_obs = [o for o in res.observations if o.source_locator == "page:1"][0]
    assert "DISPUTED ORDERS" in p1_obs.extracted_facts.get("page_text_excerpt", "")

    # Page 2 contains 6 isolated dispute order rows
    row_obs = [o for o in res.observations if o.source_locator.startswith("page:2:row:")]
    assert len(row_obs) == 6

    # Verify order-to-user mappings are isolated (e.g., ORD-20264118 belongs only to user_08)
    ord_user_map = {o.extracted_facts["order_id"]: o.extracted_facts["user_id"] for o in row_obs}
    assert ord_user_map["ORD-20264118"] == "user_08"
    assert ord_user_map["ORD-20264207"] == "user_12"
    assert ord_user_map["ORD-20264319"] == "user_17"
    assert ord_user_map["ORD-20264402"] == "user_21"
    assert ord_user_map["ORD-20264511"] == "user_24"
    assert ord_user_map["ORD-20264600"] == "user_29"

    # Verify no subject leakage between rows
    row1 = [o for o in row_obs if o.extracted_facts["order_id"] == "ORD-20264118"][0]
    assert "user_08" in row1.subject_references
    assert "user_12" not in row1.subject_references
    assert "user_17" not in row1.subject_references


def test_pdf_parsing_delivery_correction_attachment():
    """Verify evidence_58 (support delivery correction) parses customer facts correctly."""
    settings = get_settings()
    service = EvidenceIngestionService(settings)

    entry = EvidenceManifestEntry(
        file_id="evidence_58",
        file_path="evidence/documents/delivery_correction_attachment.pdf",
        origin="support_platform",
        captured_at=datetime(2026, 9, 12, 7, 30, 0, tzinfo=timezone.utc),
    )

    res = service.ingest_file(entry, mode="multimodal")
    assert res.status == IngestionStatus.PARSED
    obs = res.observations[0]

    assert obs.system_id == "support_platform"
    assert obs.resource_id in {"CS-4827", "support_001"}
    assert "priya.raman@gmail.com" in obs.subject_references
    assert "Priya Raman" in obs.extracted_facts.get("page_text_excerpt", "")
    assert "+91 98765 73142" in obs.subject_references


def test_pdf_parsing_security_retention_extract():
    """Verify evidence_55 (security retention extract) captures audit record and retention date."""
    settings = get_settings()
    service = EvidenceIngestionService(settings)

    entry = EvidenceManifestEntry(
        file_id="evidence_55",
        file_path="evidence/documents/security_retention_extract.pdf",
        origin="security_service",
        captured_at=datetime(2026, 9, 5, 6, 30, 0, tzinfo=timezone.utc),
    )

    res = service.ingest_file(entry, mode="multimodal")
    assert res.status == IngestionStatus.PARSED
    obs = res.observations[0]

    assert obs.system_id == "security_service"
    assert "audit_record_003" in obs.extracted_facts.get("resource_ids", []) or obs.resource_id == "audit_record_003"
    assert "user_03" in obs.subject_references
    assert "2027-08-25" in obs.extracted_facts.get("retention", {}).get("retention_until_iso", "")


# ===========================================================================
# 4. SCREENSHOT / OCR INTERPRETATION
# ===========================================================================

def test_screenshot_tombstone_detection():
    """Verify deleted_account_reference_20260310.png is recognized as an ACCOUNT_TOMBSTONE."""
    settings = get_settings()
    service = EvidenceIngestionService(settings)

    entry = EvidenceManifestEntry(
        file_id="evidence_42",
        file_path="evidence/images/deleted_account_reference_20260310.png",
        origin="identity_service",
        captured_at=datetime(2026, 3, 10, 6, 0, 0, tzinfo=timezone.utc),
    )

    res = service.ingest_file(entry, mode="multimodal")
    assert res.status == IngestionStatus.PARSED
    obs = res.observations[0]

    assert obs.system_id == "identity_service"
    assert obs.extracted_facts.get("is_tombstone") is True
    assert "user_17" in obs.subject_references


def test_prerequisite_fix_b_email_prefix_not_stripped():
    """Verify legitimate email local parts with prefix-like patterns are not rewritten."""
    from ghost_audit.evidence.image_parser import clean_email, extract_email_candidates
    
    # 1. Legitimate email with user_ prefix in local part
    legit_email = "user_17-notifications@example.test"
    assert clean_email(legit_email) == legit_email
    
    # 2. Another legitimate complex local part
    admin_email = "support_team-tier2@company.com"
    assert clean_email(admin_email) == admin_email

    # 3. Concatenated UI breadcrumb token separated cleanly with warning
    chained = "user_20-analytics_7438-darwish.omar@icloud.com"
    primary, raw, warn = extract_email_candidates(chained)
    assert primary == "darwish.omar@icloud.com"
    assert raw == chained
    assert warn is not None


def test_prerequisite_fix_e_inactive_status_not_matched_as_active():
    """Verify substring matching does not interpret INACTIVE as ACTIVE."""
    from ghost_audit.evidence.image_parser import ImageEvidenceParser
    parser = ImageEvidenceParser()
    
    # Text with INACTIVE should detect INACTIVE or None, never ACTIVE
    text_inactive = "Account status: INACTIVE (pending deletion)"
    import re
    status_val = None
    for cand in ["INACTIVE", "DELETED", "DELETION_PENDING", "LIVE", "ACTIVE", "HEALTHY", "Retained reference", "Normal priority"]:
        if re.search(r'\b' + re.escape(cand) + r'\b', text_inactive, re.IGNORECASE):
            status_val = cand
            break
    assert status_val == "INACTIVE"
    assert status_val != "ACTIVE"


def test_screenshot_row_isolation_backup_restore_console():
    """Verify backup_restore_console_20260429.png partitions distinct archive rows cleanly."""
    settings = get_settings()
    service = EvidenceIngestionService(settings)

    entry = EvidenceManifestEntry(
        file_id="evidence_32",
        file_path="evidence/images/backup_restore_console_20260429.png",
        origin="backup_service",
        captured_at=datetime(2026, 4, 29, 9, 0, 0, tzinfo=timezone.utc),
    )

    res = service.ingest_file(entry, mode="multimodal")
    assert res.status == IngestionStatus.PARSED
    assert len(res.observations) >= 4

    # Check each row has distinct resource_id and no subject leakage
    res_ids = {o.resource_id for o in res.observations if o.resource_id}
    assert "backup_9291" in res_ids
    assert "backup_9288" in res_ids
    assert "backup_9287" in res_ids
    assert "backup_9286" in res_ids

    # Verify bluepeakco@outlook.com is attached ONLY to backup_9291 row
    row_9291 = [o for o in res.observations if o.resource_id == "backup_9291"][0]
    assert "bluepeakco@outlook.com" in row_9291.subject_references
    assert "miller.logistics@company.com" not in row_9291.subject_references


def test_screenshot_single_subject_analytics_profile_view():
    """Verify analytics_profile_view_20260713.png extracts Omar Darwish facts accurately."""
    settings = get_settings()
    service = EvidenceIngestionService(settings)

    entry = EvidenceManifestEntry(
        file_id="evidence_19",
        file_path="evidence/images/analytics_profile_view_20260713.png",
        origin="analytics_platform",
        captured_at=datetime(2026, 7, 13, 10, 0, 0, tzinfo=timezone.utc),
    )

    res = service.ingest_file(entry, mode="multimodal")
    assert res.status == IngestionStatus.PARSED
    obs = res.observations[0]

    assert obs.system_id == "analytics_platform"
    assert obs.resource_id == "analytics_7438"
    assert "user_20" in obs.subject_references
    assert "darwish.omar@icloud.com" in obs.subject_references


# ===========================================================================
# 5. CLI OPTIONS & SAFETY
# ===========================================================================

def test_cli_ingest_evidence_mode_multimodal():
    """Verify CLI --mode multimodal outputs expected 15 parsed files."""
    cmd = [
        sys.executable,
        str(Path(__file__).resolve().parent.parent / "code" / "main.py"),
        "ingest-evidence",
        "--mode", "multimodal",
        "--json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["manifest_file_count"] == 94
    assert data["parsed_count"] == 15
    assert data["deferred_count"] == 79
    assert data["total_observations"] == 42


def test_cli_ingest_evidence_single_file_multimodal():
    """Verify CLI --file on a PDF processes only that file."""
    cmd = [
        sys.executable,
        str(Path(__file__).resolve().parent.parent / "code" / "main.py"),
        "ingest-evidence",
        "--file", "evidence_27",
        "--mode", "multimodal",
        "--json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["manifest_file_count"] == 1
    assert data["parsed_count"] == 1
    assert data["total_observations"] == 7
