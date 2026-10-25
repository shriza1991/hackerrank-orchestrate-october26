"""SQL snapshot evidence parser executing isolated in-memory SQLite instances."""

import re
import sqlite3
from datetime import datetime
from typing import Any, Optional

from ghost_audit.evidence.common import (
    compute_content_digest,
    extract_subject_references,
    make_observation_id,
)
from ghost_audit.evidence.models import (
    FileIngestionResult,
    IngestionStatus,
    ObservationType,
)
from ghost_audit.models.intermediate_models import EvidenceObservation
from ghost_audit.timestamps import parse_iso_timestamp


PARSER_NAME = "SqlEvidenceParser"
PARSER_VERSION = "1.0.0"

# Maximum SQLite VM opcode progress steps to prevent denial-of-service / hanging
MAX_SQLITE_STEPS = 500_000

# Block unsafe SQLite statements that could interact with the filesystem or load extensions
BLOCKED_SQL_PATTERNS = [
    re.compile(r'\bATTACH\b(?:\s+DATABASE)?', re.IGNORECASE),
    re.compile(r'\bDETACH\b(?:\s+DATABASE)?', re.IGNORECASE),
    re.compile(r'\bLOAD_EXTENSION\b', re.IGNORECASE),
]


def derive_system_id_from_table(table_name: str, default_origin: str) -> str:
    """Infer the system identity from the table name convention."""
    tbl_lower = table_name.lower()
    if "profile" in tbl_lower or "account" in tbl_lower:
        return "account_service"
    elif "search" in tbl_lower:
        return "search_service"
    elif "analytics" in tbl_lower:
        return "analytics_platform"
    elif "support" in tbl_lower:
        return "support_platform"
    elif "export" in tbl_lower:
        return "export_service"
    elif "connector" in tbl_lower:
        return "integration_service"
    elif "backup" in tbl_lower:
        return "backup_service"
    elif "audit" in tbl_lower or "security" in tbl_lower:
        return "security_service"
    return default_origin


class SqlEvidenceParser:
    """Parser for SQLite-compatible SQL database snapshot dumps."""

    def __init__(self):
        self.parser_name = PARSER_NAME
        self.parser_version = PARSER_VERSION

    def parse(
        self,
        file_id: str,
        file_path: str,
        origin: str,
        manifest_captured_at: datetime,
        content: str,
    ) -> FileIngestionResult:
        """Execute and inspect SQL snapshot in an isolated in-memory SQLite database."""
        content_digest = compute_content_digest(content)

        # Check for blocked unsafe operations
        for pattern in BLOCKED_SQL_PATTERNS:
            if pattern.search(content):
                return FileIngestionResult(
                    file_id=file_id,
                    file_path=file_path,
                    origin=origin,
                    format="sql",
                    status=IngestionStatus.FAILED,
                    parser_name=self.parser_name,
                    parser_version=self.parser_version,
                    observation_count=0,
                    observations=[],
                    warnings=[],
                    errors=["Unsafe SQL operation blocked (e.g. ATTACH, DETACH, or LOAD_EXTENSION)"],
                    unparsed_fragments=[{"blocked_content": content[:200]}],
                    content_digest=content_digest,
                )

        # Extract header metadata from comments
        captured_at_match = re.search(r'--\s*Captured at:\s*(\S+)', content, re.IGNORECASE)
        topology_match = re.search(r'--\s*(?:Database topology|Topology|Role):\s*([^\n\r]+)', content, re.IGNORECASE)

        header_captured_at = manifest_captured_at
        if captured_at_match:
            try:
                header_captured_at = parse_iso_timestamp(captured_at_match.group(1).strip())
            except Exception:
                pass

        topology_label = topology_match.group(1).strip() if topology_match else None

        # Execute in memory
        step_counter = [0]

        def progress_handler():
            step_counter[0] += 1000
            if step_counter[0] > MAX_SQLITE_STEPS:
                return 1  # Abort query
            return 0

        conn = None
        try:
            conn = sqlite3.connect(":memory:", uri=False)
            conn.set_progress_handler(progress_handler, 1000)
            conn.executescript(content)
        except sqlite3.Error as e:
            if conn:
                conn.close()
            return FileIngestionResult(
                file_id=file_id,
                file_path=file_path,
                origin=origin,
                format="sql",
                status=IngestionStatus.FAILED,
                parser_name=self.parser_name,
                parser_version=self.parser_version,
                observation_count=0,
                observations=[],
                warnings=[],
                errors=[f"SQLite execution failed: {e}"],
                unparsed_fragments=[{"error": str(e)}],
                content_digest=content_digest,
            )

        observations: list[EvidenceObservation] = []
        warnings: list[str] = []
        obs_idx = 0

        try:
            cursor = conn.cursor()

            # Discover user tables
            cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            tables = cursor.fetchall()

            # Inspect snapshot_scope if present
            scope_map: dict[str, str] = {}
            if any(t[0] == "snapshot_scope" for t in tables):
                cursor.execute("SELECT origin_system, captured_at FROM snapshot_scope")
                for sys_k, cap_v in cursor.fetchall():
                    scope_map[sys_k] = cap_v

            for table_name, schema_sql in tables:
                cursor.execute(f'PRAGMA table_info("{table_name}")')
                col_info = cursor.fetchall()
                col_names = [c[1] for c in col_info]

                cursor.execute(f'SELECT COUNT(*) FROM "{table_name}"')
                row_count = cursor.fetchone()[0]

                table_sys_id = derive_system_id_from_table(table_name, origin)

                # Determine table topology role from name if not globally set
                table_topology = topology_label
                if not table_topology:
                    if "failover" in table_name:
                        table_topology = "failover_replica"
                    elif "read_replica" in table_name:
                        table_topology = "read_replica"
                    elif "regional" in table_name or "replica_" in table_name:
                        table_topology = "regional_replica"
                    elif "reporting" in table_name:
                        table_topology = "reporting_replica"
                    elif "primary" in table_name:
                        table_topology = "primary"

                table_scope_ctx = {
                    "table_name": table_name,
                    "topology": table_topology,
                    "columns": col_names,
                    "row_count": row_count,
                }

                # 1. Emit INVENTORY_SCOPE observation for the table
                obs_idx += 1
                observations.append(
                    EvidenceObservation(
                        evidence_id=file_id,
                        source_locator=f"table:{table_name}",
                        capture_time=manifest_captured_at,
                        observation_time=header_captured_at,
                        system_id=table_sys_id,
                        resource_id=None,
                        extracted_facts={
                            "table_name": table_name,
                            "row_count": row_count,
                            "columns": col_names,
                            "schema_sql": schema_sql,
                        },
                        extraction_method=self.parser_name,
                        uncertainty_or_warnings=[],
                        internal_id=make_observation_id(file_id, obs_idx),
                        file_path=file_path,
                        observation_type=ObservationType.INVENTORY_SCOPE.value,
                        scope_context=table_scope_ctx,
                        subject_references=[],
                        content_digest=content_digest,
                    )
                )

                # 2. Emit row observations if any exist
                if row_count > 0:
                    cursor.execute(f'SELECT * FROM "{table_name}"')
                    rows = cursor.fetchall()
                    for r_idx, row in enumerate(rows, start=1):
                        obs_idx += 1
                        row_dict = dict(zip(col_names, row))
                        res_id = row_dict.get("resource_id")
                        
                        # Determine timestamp
                        row_time = header_captured_at
                        row_ts_str = row_dict.get("updated_at") or row_dict.get("captured_at")
                        if not row_ts_str and table_sys_id in scope_map:
                            row_ts_str = scope_map[table_sys_id]
                        if row_ts_str:
                            try:
                                row_time = parse_iso_timestamp(row_ts_str)
                            except Exception:
                                pass

                        # Determine observation type
                        if table_name == "snapshot_scope":
                            obs_type = ObservationType.INVENTORY_SCOPE.value
                        elif table_name in {"connector_subscriptions", "backup_restore_entries"} or "enabled" in row_dict or "restore_allowed" in row_dict:
                            obs_type = ObservationType.PROCESS_CONFIG.value
                        else:
                            obs_type = ObservationType.STORED_RECORD.value

                        row_scope_ctx = {
                            "table_name": table_name,
                            "topology": table_topology,
                            "row_index": r_idx,
                        }

                        observations.append(
                            EvidenceObservation(
                                evidence_id=file_id,
                                source_locator=f"table:{table_name}:row:{r_idx}",
                                capture_time=manifest_captured_at,
                                observation_time=row_time,
                                system_id=table_sys_id,
                                resource_id=res_id,
                                extracted_facts=row_dict,
                                extraction_method=self.parser_name,
                                uncertainty_or_warnings=[],
                                internal_id=make_observation_id(file_id, obs_idx),
                                file_path=file_path,
                                observation_type=obs_type,
                                scope_context=row_scope_ctx,
                                subject_references=extract_subject_references(row_dict),
                                content_digest=content_digest,
                            )
                        )
        finally:
            conn.close()

        status = IngestionStatus.PARSED if not warnings else IngestionStatus.PARTIAL

        return FileIngestionResult(
            file_id=file_id,
            file_path=file_path,
            origin=origin,
            format="sql",
            status=status,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            observation_count=len(observations),
            observations=observations,
            warnings=warnings,
            errors=[],
            unparsed_fragments=[],
            content_digest=content_digest,
        )
