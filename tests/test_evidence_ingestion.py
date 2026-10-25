"""Tests for structured evidence ingestion (JSON, SQL, Logs, Text) and deferrals."""

import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghost_audit.config import Settings, get_settings
from ghost_audit.evidence.common import compute_content_digest, extract_subject_references
from ghost_audit.evidence.json_parser import JsonEvidenceParser
from ghost_audit.evidence.log_parser import LogEvidenceParser
from ghost_audit.evidence.models import IngestionStatus, ObservationType
from ghost_audit.evidence.service import EvidenceIngestionService
from ghost_audit.evidence.sql_parser import SqlEvidenceParser
from ghost_audit.models.input_models import EvidenceManifestEntry
from ghost_audit.timestamps import parse_iso_timestamp


# ---------------------------------------------------------------------------
# JSON Ingestion Tests
# ---------------------------------------------------------------------------

def test_json_parent_context_inheritance():
    """Verify nested records inherit service, collection, and scope context."""
    parser = JsonEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    raw_json = json.dumps({
        "exported_at": "2026-09-15T12:00:00Z",
        "region": "eu-west-1",
        "source": "assurance_gateway",
        "service_exports": {
            "account_service": {
                "profile_lookups": [
                    {
                        "observed_at": "2026-09-15T11:00:00Z",
                        "resource_id": "account_999",
                        "status_code": 200,
                        "profile": {"email": "user@example.com", "full_name": "Test User"},
                    }
                ]
            }
        }
    })

    res = parser.parse("evidence_test_1", "evidence/records/test.json", "test_origin", now, raw_json)
    assert res.status == IngestionStatus.PARSED
    assert res.observation_count == 1
    obs = res.observations[0]
    assert obs.system_id == "account_service"
    assert obs.resource_id == "account_999"
    assert obs.source_locator == "$.service_exports.account_service.profile_lookups[0]"
    assert obs.scope_context["service"] == "account_service"
    assert obs.scope_context["collection"] == "profile_lookups"
    assert obs.scope_context["region"] == "eu-west-1"
    assert "user@example.com" in obs.subject_references


def test_json_nested_records_and_stable_paths():
    """Verify stable JSON paths and preservation of nested objects."""
    parser = JsonEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    raw_json = json.dumps({
        "exported_at": "2026-09-15T12:00:00Z",
        "snapshots": [
            {
                "data_store": "analytics_platform",
                "collection": "profiles",
                "captured_at": "2026-09-15T10:00:00Z",
                "records": [
                    {"resource_id": "analytics_01", "email": "a@example.com", "cohort": "vip"},
                    {"resource_id": "analytics_02", "email": "b@example.com", "cohort": "standard"},
                ]
            }
        ]
    })

    res = parser.parse("evidence_test_2", "evidence/records/test2.json", "test_origin", now, raw_json)
    assert res.status == IngestionStatus.PARSED
    assert res.observation_count == 2
    assert res.observations[0].source_locator == "$.snapshots[0].records[0]"
    assert res.observations[1].source_locator == "$.snapshots[0].records[1]"
    assert res.observations[0].resource_id == "analytics_01"
    assert res.observations[1].resource_id == "analytics_02"


def test_json_explicit_null_versus_missing_field():
    """Verify explicit null, false, 0, and empty strings are preserved intact."""
    parser = JsonEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    raw_json = json.dumps({
        "exported_at": "2026-09-15T12:00:00Z",
        "records": [
            {
                "resource_id": "account_01",
                "full_name": None,
                "email": "null_test@example.com",
                "phone": "",
                "is_active": False,
                "retry_count": 0,
            }
        ]
    })

    res = parser.parse("evidence_test_3", "evidence/records/test3.json", "test_origin", now, raw_json)
    assert res.status == IngestionStatus.PARSED
    facts = res.observations[0].extracted_facts
    assert facts["full_name"] is None
    assert facts["phone"] == ""
    assert facts["is_active"] is False
    assert facts["retry_count"] == 0
    assert "missing_field" not in facts


def test_json_empty_inventories_and_zero_hit_queries():
    """Verify empty inventories and zero-hit queries emit scoped INVENTORY_SCOPE / LOOKUP_RESULT."""
    parser = JsonEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    raw_json = json.dumps({
        "exported_at": "2026-09-15T12:00:00Z",
        "service_exports": {
            "search_service": {
                "empty_collection": [],
                "index_queries": [
                    {
                        "resource_id": "search_101",
                        "query": "nonexistent@example.com",
                        "hits": {"documents": [], "total": 0},
                    }
                ]
            }
        }
    })

    res = parser.parse("evidence_test_4", "evidence/records/test4.json", "test_origin", now, raw_json)
    assert res.status == IngestionStatus.PARSED
    assert res.observation_count == 2

    # Empty collection emitted INVENTORY_SCOPE
    empty_obs = [o for o in res.observations if o.observation_type == ObservationType.INVENTORY_SCOPE.value][0]
    assert empty_obs.source_locator == "$.service_exports.search_service.empty_collection"
    assert empty_obs.extracted_facts["count"] == 0

    # Zero-hit query preserved as LOOKUP_RESULT
    query_obs = [o for o in res.observations if o.observation_type == ObservationType.LOOKUP_RESULT.value][0]
    assert query_obs.resource_id == "search_101"
    assert query_obs.extracted_facts["hits"]["total"] == 0
    assert query_obs.extracted_facts["hits"]["documents"] == []


def test_json_malformed_syntax_fails_cleanly():
    """Verify malformed JSON syntax results in FAILED status without raising an exception."""
    parser = JsonEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    malformed = '{"exported_at": "2026-09-15T12:00:00Z", "records": [{"resource_id": "bad"'

    res = parser.parse("evidence_bad_json", "bad.json", "origin", now, malformed)
    assert res.status == IngestionStatus.FAILED
    assert res.observation_count == 0
    assert len(res.errors) == 1
    assert "Malformed JSON" in res.errors[0]
    assert len(res.unparsed_fragments) == 1


# ---------------------------------------------------------------------------
# SQL Ingestion Tests
# ---------------------------------------------------------------------------

def test_sql_empty_primary_table_plus_surviving_replica_row():
    """Verify primary and replica tables remain distinguishable, even when primary is empty."""
    parser = SqlEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    sql_text = """
    -- Dialect: SQLite-compatible SQL
    -- Captured at: 2026-09-15T12:00:00Z
    -- Database topology: failover_replica
    BEGIN TRANSACTION;
    CREATE TABLE customer_profiles_primary (
        resource_id TEXT PRIMARY KEY, email TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE customer_profiles_failover_replica (
        resource_id TEXT PRIMARY KEY, email TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    INSERT INTO customer_profiles_failover_replica VALUES ('account_005', 'leila@example.com', '2026-09-15T11:45:00Z');
    COMMIT;
    """

    res = parser.parse("evidence_sql_1", "evidence/databases/test.sql", "origin", now, sql_text)
    assert res.status == IngestionStatus.PARSED
    
    # customer_profiles_primary has table inventory scope (count=0), 0 rows
    primary_scope = [o for o in res.observations if o.source_locator == "table:customer_profiles_primary"][0]
    assert primary_scope.extracted_facts["row_count"] == 0
    assert primary_scope.resource_id is None

    # customer_profiles_failover_replica has table scope + 1 row
    replica_scope = [o for o in res.observations if o.source_locator == "table:customer_profiles_failover_replica"][0]
    assert replica_scope.extracted_facts["row_count"] == 1

    replica_row = [o for o in res.observations if o.source_locator == "table:customer_profiles_failover_replica:row:1"][0]
    assert replica_row.resource_id == "account_005"
    assert replica_row.extracted_facts["email"] == "leila@example.com"
    assert replica_row.scope_context["topology"] == "failover_replica"
    assert "leila@example.com" in replica_row.subject_references


def test_sql_distinct_topology_context():
    """Verify regional replica tables preserve distinct topology context."""
    parser = SqlEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    sql_text = """
    -- Topology: regional_replicas
    BEGIN TRANSACTION;
    CREATE TABLE customer_data_replica_ap_south (resource_id TEXT PRIMARY KEY, val TEXT);
    CREATE TABLE customer_data_replica_eu_west (resource_id TEXT PRIMARY KEY, val TEXT);
    INSERT INTO customer_data_replica_ap_south VALUES ('res_ap', 'val_ap');
    COMMIT;
    """

    res = parser.parse("evidence_sql_2", "test.sql", "origin", now, sql_text)
    assert res.status == IngestionStatus.PARSED
    row_ap = [o for o in res.observations if o.resource_id == "res_ap"][0]
    assert row_ap.scope_context["table_name"] == "customer_data_replica_ap_south"
    assert row_ap.scope_context["topology"] == "regional_replicas"


def test_sql_null_and_quoted_unicode_values():
    """Verify SQLite NULL and Unicode values are preserved intact."""
    parser = SqlEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    sql_text = """
    CREATE TABLE users (resource_id TEXT PRIMARY KEY, name TEXT, email TEXT);
    INSERT INTO users VALUES ('usr_1', 'René Müller', NULL);
    """

    res = parser.parse("evidence_sql_3", "test.sql", "origin", now, sql_text)
    assert res.status == IngestionStatus.PARSED
    row = [o for o in res.observations if o.resource_id == "usr_1"][0]
    assert row.extracted_facts["name"] == "René Müller"
    assert row.extracted_facts["email"] is None


def test_sql_required_harmless_directives():
    """Verify harmless pragmas like foreign_keys and transactions execute cleanly."""
    parser = SqlEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    sql_text = """
    PRAGMA foreign_keys=ON;
    BEGIN TRANSACTION;
    CREATE TABLE test (id TEXT PRIMARY KEY);
    INSERT INTO test VALUES ('id_1');
    COMMIT;
    """

    res = parser.parse("evidence_sql_4", "test.sql", "origin", now, sql_text)
    assert res.status == IngestionStatus.PARSED
    assert res.observation_count == 2  # 1 inventory scope + 1 row


def test_sql_invalid_syntax_fails_cleanly():
    """Verify invalid SQL syntax fails with FAILED status and recorded error."""
    parser = SqlEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    sql_text = "INVALID SQL STATEMENT;"

    res = parser.parse("evidence_sql_5", "test.sql", "origin", now, sql_text)
    assert res.status == IngestionStatus.FAILED
    assert res.observation_count == 0
    assert len(res.errors) == 1
    assert "SQLite execution failed" in res.errors[0]


def test_sql_blocked_filesystem_attachment():
    """Verify ATTACH DATABASE is blocked before execution."""
    parser = SqlEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    sql_text = "ATTACH DATABASE 'external.db' AS ext;"

    res = parser.parse("evidence_sql_6", "test.sql", "origin", now, sql_text)
    assert res.status == IngestionStatus.FAILED
    assert "Unsafe SQL operation blocked" in res.errors[0]


# ---------------------------------------------------------------------------
# Log and Text Ingestion Tests
# ---------------------------------------------------------------------------

def test_log_split_trace_correlation():
    """Verify split traces link identifier start event to resource completion event."""
    parser = LogEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    content = (
        '2026-09-15T11:51:18Z [DEBUG] [account_service] [tr-100] profile_lookup_started: lookup_key="alice@example.com"\n'
        '2026-09-15T11:51:21Z [INFO] [account_service] [tr-100] profile_lookup_completed: resource_id="account_100" rows="0" http_status="404"\n'
    )

    res = parser.parse("evidence_log_1", "test.log", "origin", now, content)
    assert res.status == IngestionStatus.PARSED
    assert res.observation_count == 2

    start_obs = res.observations[0]
    end_obs = res.observations[1]

    # Verify both observations share correlated information
    assert "alice@example.com" in start_obs.subject_references
    assert "alice@example.com" in end_obs.subject_references
    assert start_obs.extracted_facts.get("correlated_resource_id") == "account_100"
    assert end_obs.resource_id == "account_100"
    assert end_obs.extracted_facts.get("correlated_trace_start_line") == 1
    assert end_obs.observation_type == ObservationType.LOOKUP_RESULT.value


def test_log_unrelated_traces_sharing_adjacent_lines():
    """Verify unrelated traces on adjacent lines do not cross-pollinate identifiers."""
    parser = LogEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    content = (
        '2026-09-15T11:51:18Z [DEBUG] [account_service] [tr-AAA] profile_lookup_started: lookup_key="user_a@example.com"\n'
        '2026-09-15T11:51:19Z [DEBUG] [account_service] [tr-BBB] profile_lookup_started: lookup_key="user_b@example.com"\n'
        '2026-09-15T11:51:21Z [INFO] [account_service] [tr-AAA] profile_lookup_completed: resource_id="acc_A" rows="1"\n'
        '2026-09-15T11:51:22Z [INFO] [account_service] [tr-BBB] profile_lookup_completed: resource_id="acc_B" rows="1"\n'
    )

    res = parser.parse("evidence_log_2", "test.log", "origin", now, content)
    assert res.status == IngestionStatus.PARSED
    
    obs_a_end = res.observations[2]
    obs_b_end = res.observations[3]

    assert obs_a_end.resource_id == "acc_A"
    assert obs_a_end.subject_references == ["user_a@example.com"]

    assert obs_b_end.resource_id == "acc_B"
    assert obs_b_end.subject_references == ["user_b@example.com"]


def test_log_escaped_values_and_unicode():
    """Verify escaped quotes and Unicode characters in log messages are correctly extracted."""
    parser = LogEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    content = (
        r'2026-09-15T11:51:01Z requestId=tr-999 level=INFO function=support message="user=\"Élodie D\'Souza\" email=\"elodie@test.fr\" status=\"active\""'
    )

    res = parser.parse("evidence_log_3", "test.log", "origin", now, content)
    assert res.status == IngestionStatus.PARSED
    obs = res.observations[0]
    assert obs.extracted_facts["user"] == "Élodie D'Souza"
    assert obs.extracted_facts["email"] == "elodie@test.fr"
    assert "elodie@test.fr" in obs.subject_references


def test_log_zero_row_results():
    """Verify zero-row query results and 404 misses are preserved as LOOKUP_RESULT."""
    parser = LogEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    content = (
        '2026-09-15T07:00:00Z INFO service=search_service event=record_lookup resource_id="search_55" result="NOT_FOUND" subject_reference="missing@test.com"\n'
    )

    res = parser.parse("evidence_log_4", "test.log", "origin", now, content)
    assert res.status == IngestionStatus.PARSED
    obs = res.observations[0]
    assert obs.observation_type == ObservationType.LOOKUP_RESULT.value
    assert obs.resource_id == "search_55"
    assert obs.extracted_facts["result"] == "NOT_FOUND"


def test_log_disabled_blocked_configuration():
    """Verify disabled connectors and blocked restores are preserved as PROCESS_CONFIG."""
    parser = LogEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    content = (
        '2026-09-15T07:00:00Z level=INFO service=integration_service resource_id="data_flow_01" enabled=false last_delivery_status="disabled"\n'
    )

    res = parser.parse("evidence_log_5", "test.log", "origin", now, content)
    assert res.status == IngestionStatus.PARSED
    obs = res.observations[0]
    assert obs.observation_type == ObservationType.PROCESS_CONFIG.value
    assert obs.extracted_facts["enabled"] is False


def test_log_unknown_fragments_retained_with_diagnostics():
    """Verify unrecognized log lines are retained as RAW_FRAGMENT with status PARTIAL."""
    parser = LogEvidenceParser()
    now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    content = (
        '2026-09-15T07:00:00Z INFO service=search_service event=record_lookup resource_id="s1" result="hit"\n'
        'CORRUPTED AND UNPARSABLE RANDOM BYTES 0xDEADBEEF\n'
    )

    res = parser.parse("evidence_log_6", "test.log", "origin", now, content)
    assert res.status == IngestionStatus.PARTIAL
    assert res.observation_count == 2
    raw_obs = [o for o in res.observations if o.observation_type == ObservationType.RAW_FRAGMENT.value][0]
    assert raw_obs.source_locator == "line:2"
    assert raw_obs.extracted_facts["raw_text"] == "CORRUPTED AND UNPARSABLE RANDOM BYTES 0xDEADBEEF"
    assert len(res.warnings) == 1


def test_text_handover_parsing():
    """Verify customer_account_handover shift checks are parsed with line locators."""
    parser = LogEvidenceParser()
    now = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
    content = (
        "CUSTOMER PLATFORM - SHIFT HANDOVER\n"
        "Snapshot: 2026-10-01T12:00:00Z\n"
        "\n"
        "Account and downstream checks completed during the shift:\n"
        "\n"
        "- 2026-10-01T12:00:00Z | account_service | account_146 | USER_PROFILE | NOT_FOUND | e.lindberg18@yahoo.com\n"
        "- 2026-10-01T12:00:00Z | backup_service | backup_706 | BACKUP_ARCHIVE | BLOCKED | user_39\n"
    )

    res = parser.parse("evidence_03", "evidence/records/handover.txt", "account_service", now, content)
    assert res.status == IngestionStatus.PARSED
    assert res.observation_count == 2
    obs1 = res.observations[0]
    assert obs1.source_locator == "line:6"
    assert obs1.system_id == "account_service"
    assert obs1.resource_id == "account_146"
    assert obs1.extracted_facts["status"] == "NOT_FOUND"
    assert obs1.subject_references == ["e.lindberg18@yahoo.com"]

    obs2 = res.observations[1]
    assert obs2.source_locator == "line:7"
    assert obs2.system_id == "backup_service"
    assert obs2.resource_id == "backup_706"
    assert obs2.extracted_facts["status"] == "BLOCKED"
    assert obs2.subject_references == ["user_39"]


# ---------------------------------------------------------------------------
# Integration and Manifest Coverage Tests
# ---------------------------------------------------------------------------

def test_all_79_supported_files_ingested_cleanly():
    """Verify all 79 supported structured files in the dataset manifest parse cleanly."""
    settings = get_settings()
    service = EvidenceIngestionService(settings)
    summary = service.ingest_manifest()

    assert summary.manifest_file_count == 94
    assert summary.parsed_count == 79
    assert summary.partial_count == 0
    assert summary.failed_count == 0
    assert summary.deferred_count == 15
    assert summary.total_observations == 4241

    # Exact format counts
    assert summary.by_format["sql"]["parsed"] == 24
    assert summary.by_format["json"]["parsed"] == 28
    assert summary.by_format["log"]["parsed"] == 26
    assert summary.by_format["txt"]["parsed"] == 1


def test_all_15_multimodal_files_deferred():
    """Verify all 15 PDF and PNG files are explicitly marked DEFERRED with 0 observations."""
    settings = get_settings()
    service = EvidenceIngestionService(settings)
    summary = service.ingest_manifest()

    deferred = [r for r in summary.file_results if r.status == IngestionStatus.DEFERRED]
    assert len(deferred) == 15
    for d in deferred:
        assert d.observation_count == 0
        assert d.format in {"pdf", "png"}
        assert any("deferred to Task 7" in w for w in d.warnings)


def test_repeated_ingestion_determinism():
    """Verify repeated ingestion produces identical observation counts and content digests."""
    settings = get_settings()
    service = EvidenceIngestionService(settings)
    
    # Run twice on a subset of 3 files
    entry = EvidenceManifestEntry(
        file_id="evidence_01",
        file_path="evidence/logs/service_events_ap_south_20260915.log",
        origin="test",
        captured_at=datetime(2026, 9, 15, 11, 59, 39, tzinfo=timezone.utc),
    )

    res1 = service.ingest_file(entry)
    res2 = service.ingest_file(entry)

    assert res1.content_digest == res2.content_digest
    assert res1.observation_count == res2.observation_count
    assert [o.internal_id for o in res1.observations] == [o.internal_id for o in res2.observations]


def test_cli_ingest_evidence_working_from_another_dir(tmp_path):
    """Verify CLI works when invoked with --dataset pointing to repo dataset."""
    cmd = [
        sys.executable,
        str(Path(__file__).resolve().parent.parent / "code" / "main.py"),
        "ingest-evidence",
        "--file", "evidence_01",
        "--json",
    ]
    proc = subprocess.run(cmd, cwd=str(tmp_path), capture_output=True, text=True)
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["manifest_file_count"] == 1
    assert data["total_observations"] == 104


def test_representative_real_file_facts_extraction():
    """Verify ground truth extraction against hand-verified facts in evidence_05 and evidence_03."""
    settings = get_settings()
    service = EvidenceIngestionService(settings)

    # 1. evidence_03: shift handover text
    entry_ho = EvidenceManifestEntry(
        file_id="evidence_03",
        file_path="evidence/records/customer_account_handover_20261001.txt",
        origin="customer_account_service",
        captured_at=datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc),
    )
    res_ho = service.ingest_file(entry_ho)
    assert res_ho.status == IngestionStatus.PARSED
    # Check account_146 is NOT_FOUND
    obs_146 = [o for o in res_ho.observations if o.resource_id == "account_146"][0]
    assert obs_146.extracted_facts["status"] == "NOT_FOUND"
    assert "e.lindberg18@yahoo.com" in obs_146.subject_references

    # 2. evidence_05: customer_data_read_replica_20260921.sql
    entry_sql = EvidenceManifestEntry(
        file_id="evidence_05",
        file_path="evidence/databases/customer_data_read_replica_20260921.sql",
        origin="customer_data_read_replica_capture",
        captured_at=datetime(2026, 9, 21, 10, 0, 0, tzinfo=timezone.utc),
    )
    res_sql = service.ingest_file(entry_sql)
    assert res_sql.status == IngestionStatus.PARSED
    # Check that table customer_data_primary and customer_data_read_replica were parsed
    locators = {o.source_locator for o in res_sql.observations}
    assert "table:customer_data_primary" in locators
    assert "table:customer_data_read_replica" in locators
