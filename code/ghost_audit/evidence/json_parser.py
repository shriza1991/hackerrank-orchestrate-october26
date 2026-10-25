"""JSON evidence parser supporting flat records, snapshot bundles, and service exports."""

import json
from datetime import datetime
from typing import Any

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


PARSER_NAME = "JsonEvidenceParser"
PARSER_VERSION = "1.0.0"


class JsonEvidenceParser:
    """Parser for structured JSON evidence files."""

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
        """Parse JSON content into structured EvidenceObservation records."""
        content_digest = compute_content_digest(content)

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            return FileIngestionResult(
                file_id=file_id,
                file_path=file_path,
                origin=origin,
                format="json",
                status=IngestionStatus.FAILED,
                parser_name=self.parser_name,
                parser_version=self.parser_version,
                observation_count=0,
                observations=[],
                warnings=[],
                errors=[f"Malformed JSON: {e}"],
                unparsed_fragments=[{"error": str(e), "line": e.lineno, "col": e.colno}],
                content_digest=content_digest,
            )

        observations: list[EvidenceObservation] = []
        warnings: list[str] = []
        obs_idx = 0

        # Determine file-level timestamps
        root_captured_str = None
        if isinstance(data, dict):
            root_captured_str = data.get("captured_at") or data.get("exported_at")
        
        file_captured_at = manifest_captured_at
        if root_captured_str:
            try:
                file_captured_at = parse_iso_timestamp(root_captured_str)
            except Exception as e:
                warnings.append(f"Could not parse root timestamp '{root_captured_str}': {e}")

        # Case 1: Root has "records" list (e.g. connector configs, customer analytics report)
        if isinstance(data, dict) and "records" in data:
            records = data.get("records")
            root_scope = {k: v for k, v in data.items() if k != "records"}
            sys_id = data.get("origin") or data.get("source") or origin

            if isinstance(records, list):
                if len(records) == 0:
                    obs_idx += 1
                    observations.append(
                        EvidenceObservation(
                            evidence_id=file_id,
                            source_locator="$.records",
                            capture_time=manifest_captured_at,
                            observation_time=file_captured_at,
                            system_id=sys_id,
                            resource_id=None,
                            extracted_facts={"collection": data.get("collection", "records"), "count": 0},
                            extraction_method=self.parser_name,
                            uncertainty_or_warnings=[],
                            internal_id=make_observation_id(file_id, obs_idx),
                            file_path=file_path,
                            observation_type=ObservationType.INVENTORY_SCOPE.value,
                            scope_context=root_scope,
                            subject_references=[],
                            content_digest=content_digest,
                        )
                    )
                else:
                    for i, r in enumerate(records):
                        if not isinstance(r, dict):
                            warnings.append(f"Non-dict record at $.records[{i}]")
                            continue
                        obs_idx += 1
                        rec_res_id = r.get("resource_id")
                        rec_sys = r.get("system") or sys_id
                        rec_time_str = r.get("recorded_at") or r.get("observed_at") or r.get("updated_at")
                        rec_time = file_captured_at
                        if rec_time_str:
                            try:
                                rec_time = parse_iso_timestamp(rec_time_str)
                            except Exception:
                                pass

                        obs_type = ObservationType.STORED_RECORD.value
                        if "result" in r:
                            obs_type = ObservationType.LOOKUP_RESULT.value
                        elif "enabled" in r or "restore_allowed" in r:
                            obs_type = ObservationType.PROCESS_CONFIG.value

                        observations.append(
                            EvidenceObservation(
                                evidence_id=file_id,
                                source_locator=f"$.records[{i}]",
                                capture_time=manifest_captured_at,
                                observation_time=rec_time,
                                system_id=rec_sys,
                                resource_id=rec_res_id,
                                extracted_facts=dict(r),
                                extraction_method=self.parser_name,
                                uncertainty_or_warnings=[],
                                internal_id=make_observation_id(file_id, obs_idx),
                                file_path=file_path,
                                observation_type=obs_type,
                                scope_context=root_scope,
                                subject_references=extract_subject_references(r),
                                content_digest=content_digest,
                            )
                        )

        # Case 2: Root has "snapshots" list (e.g. customer_data_snapshot_bundle)
        elif isinstance(data, dict) and "snapshots" in data:
            snapshots = data.get("snapshots")
            root_scope = {k: v for k, v in data.items() if k != "snapshots"}
            if isinstance(snapshots, list):
                if len(snapshots) == 0:
                    obs_idx += 1
                    observations.append(
                        EvidenceObservation(
                            evidence_id=file_id,
                            source_locator="$.snapshots",
                            capture_time=manifest_captured_at,
                            observation_time=file_captured_at,
                            system_id=origin,
                            resource_id=None,
                            extracted_facts={"collection": "snapshots", "count": 0},
                            extraction_method=self.parser_name,
                            uncertainty_or_warnings=[],
                            internal_id=make_observation_id(file_id, obs_idx),
                            file_path=file_path,
                            observation_type=ObservationType.INVENTORY_SCOPE.value,
                            scope_context=root_scope,
                            subject_references=[],
                            content_digest=content_digest,
                        )
                    )
                else:
                    for s_idx, snap in enumerate(snapshots):
                        if not isinstance(snap, dict):
                            continue
                        data_store = snap.get("data_store") or origin
                        coll = snap.get("collection")
                        snap_time_str = snap.get("captured_at")
                        snap_time = file_captured_at
                        if snap_time_str:
                            try:
                                snap_time = parse_iso_timestamp(snap_time_str)
                            except Exception:
                                pass
                        
                        snap_scope = {
                            "data_store": data_store,
                            "collection": coll,
                            "captured_at": snap_time_str,
                        }
                        records = snap.get("records", [])
                        if len(records) == 0:
                            obs_idx += 1
                            observations.append(
                                EvidenceObservation(
                                    evidence_id=file_id,
                                    source_locator=f"$.snapshots[{s_idx}].records",
                                    capture_time=manifest_captured_at,
                                    observation_time=snap_time,
                                    system_id=data_store,
                                    resource_id=None,
                                    extracted_facts={"data_store": data_store, "collection": coll, "count": 0},
                                    extraction_method=self.parser_name,
                                    uncertainty_or_warnings=[],
                                    internal_id=make_observation_id(file_id, obs_idx),
                                    file_path=file_path,
                                    observation_type=ObservationType.INVENTORY_SCOPE.value,
                                    scope_context=snap_scope,
                                    subject_references=[],
                                    content_digest=content_digest,
                                )
                            )
                        else:
                            for r_idx, r in enumerate(records):
                                if not isinstance(r, dict):
                                    continue
                                obs_idx += 1
                                rec_res_id = r.get("resource_id")
                                rec_time_str = r.get("updated_at") or r.get("recorded_at")
                                rec_time = snap_time
                                if rec_time_str:
                                    try:
                                        rec_time = parse_iso_timestamp(rec_time_str)
                                    except Exception:
                                        pass

                                observations.append(
                                    EvidenceObservation(
                                        evidence_id=file_id,
                                        source_locator=f"$.snapshots[{s_idx}].records[{r_idx}]",
                                        capture_time=manifest_captured_at,
                                        observation_time=rec_time,
                                        system_id=data_store,
                                        resource_id=rec_res_id,
                                        extracted_facts=dict(r),
                                        extraction_method=self.parser_name,
                                        uncertainty_or_warnings=[],
                                        internal_id=make_observation_id(file_id, obs_idx),
                                        file_path=file_path,
                                        observation_type=ObservationType.STORED_RECORD.value,
                                        scope_context=snap_scope,
                                        subject_references=extract_subject_references(r),
                                        content_digest=content_digest,
                                    )
                                )

        # Case 3: Root has "service_exports" (e.g. service_resource_export)
        elif isinstance(data, dict) and "service_exports" in data:
            exports = data.get("service_exports")
            root_scope = {k: v for k, v in data.items() if k != "service_exports"}
            if isinstance(exports, dict):
                for svc_name, svc_data in sorted(exports.items()):
                    if not isinstance(svc_data, dict):
                        continue
                    for coll_name, items in sorted(svc_data.items()):
                        coll_scope = {
                            "service": svc_name,
                            "collection": coll_name,
                            "region": data.get("region"),
                        }
                        if not isinstance(items, list) or len(items) == 0:
                            obs_idx += 1
                            observations.append(
                                EvidenceObservation(
                                    evidence_id=file_id,
                                    source_locator=f"$.service_exports.{svc_name}.{coll_name}",
                                    capture_time=manifest_captured_at,
                                    observation_time=file_captured_at,
                                    system_id=svc_name,
                                    resource_id=None,
                                    extracted_facts={"service": svc_name, "collection": coll_name, "count": 0},
                                    extraction_method=self.parser_name,
                                    uncertainty_or_warnings=[],
                                    internal_id=make_observation_id(file_id, obs_idx),
                                    file_path=file_path,
                                    observation_type=ObservationType.INVENTORY_SCOPE.value,
                                    scope_context=coll_scope,
                                    subject_references=[],
                                    content_digest=content_digest,
                                )
                            )
                        else:
                            for r_idx, r in enumerate(items):
                                if not isinstance(r, dict):
                                    continue
                                obs_idx += 1
                                rec_res_id = r.get("resource_id")
                                rec_time_str = r.get("observed_at") or r.get("recorded_at") or r.get("updated_at")
                                rec_time = file_captured_at
                                if rec_time_str:
                                    try:
                                        rec_time = parse_iso_timestamp(rec_time_str)
                                    except Exception:
                                        pass

                                obs_type = ObservationType.STORED_RECORD.value
                                if coll_name in {"index_queries", "profile_lookups"} or "result" in r or "status_code" in r:
                                    obs_type = ObservationType.LOOKUP_RESULT.value
                                elif coll_name in {"connectors", "restore_entries"} or "enabled" in r or "restore_allowed" in r:
                                    obs_type = ObservationType.PROCESS_CONFIG.value

                                observations.append(
                                    EvidenceObservation(
                                        evidence_id=file_id,
                                        source_locator=f"$.service_exports.{svc_name}.{coll_name}[{r_idx}]",
                                        capture_time=manifest_captured_at,
                                        observation_time=rec_time,
                                        system_id=svc_name,
                                        resource_id=rec_res_id,
                                        extracted_facts=dict(r),
                                        extraction_method=self.parser_name,
                                        uncertainty_or_warnings=[],
                                        internal_id=make_observation_id(file_id, obs_idx),
                                        file_path=file_path,
                                        observation_type=obs_type,
                                        scope_context=coll_scope,
                                        subject_references=extract_subject_references(r),
                                        content_digest=content_digest,
                                    )
                                )

        # Case 4: Root is a list (flat records)
        elif isinstance(data, list):
            if len(data) == 0:
                obs_idx += 1
                observations.append(
                    EvidenceObservation(
                        evidence_id=file_id,
                        source_locator="$",
                        capture_time=manifest_captured_at,
                        observation_time=manifest_captured_at,
                        system_id=origin,
                        resource_id=None,
                        extracted_facts={"count": 0},
                        extraction_method=self.parser_name,
                        uncertainty_or_warnings=[],
                        internal_id=make_observation_id(file_id, obs_idx),
                        file_path=file_path,
                        observation_type=ObservationType.INVENTORY_SCOPE.value,
                        scope_context={},
                        subject_references=[],
                        content_digest=content_digest,
                    )
                )
            else:
                for i, r in enumerate(data):
                    if not isinstance(r, dict):
                        continue
                    obs_idx += 1
                    rec_res_id = r.get("resource_id")
                    rec_sys = r.get("system") or origin
                    rec_time_str = r.get("recorded_at") or r.get("observed_at") or r.get("updated_at")
                    rec_time = manifest_captured_at
                    if rec_time_str:
                        try:
                            rec_time = parse_iso_timestamp(rec_time_str)
                        except Exception:
                            pass
                    obs_type = ObservationType.STORED_RECORD.value
                    if "result" in r:
                        obs_type = ObservationType.LOOKUP_RESULT.value
                    elif "enabled" in r or "restore_allowed" in r:
                        obs_type = ObservationType.PROCESS_CONFIG.value

                    observations.append(
                        EvidenceObservation(
                            evidence_id=file_id,
                            source_locator=f"$[{i}]",
                            capture_time=manifest_captured_at,
                            observation_time=rec_time,
                            system_id=rec_sys,
                            resource_id=rec_res_id,
                            extracted_facts=dict(r),
                            extraction_method=self.parser_name,
                            uncertainty_or_warnings=[],
                            internal_id=make_observation_id(file_id, obs_idx),
                            file_path=file_path,
                            observation_type=obs_type,
                            scope_context={},
                            subject_references=extract_subject_references(r),
                            content_digest=content_digest,
                        )
                    )

        # Case 5: Other arbitrary dict
        elif isinstance(data, dict):
            obs_idx += 1
            observations.append(
                EvidenceObservation(
                    evidence_id=file_id,
                    source_locator="$",
                    capture_time=manifest_captured_at,
                    observation_time=file_captured_at,
                    system_id=origin,
                    resource_id=data.get("resource_id"),
                    extracted_facts=dict(data),
                    extraction_method=self.parser_name,
                    uncertainty_or_warnings=[],
                    internal_id=make_observation_id(file_id, obs_idx),
                    file_path=file_path,
                    observation_type=ObservationType.STORED_RECORD.value,
                    scope_context={},
                    subject_references=extract_subject_references(data),
                    content_digest=content_digest,
                )
            )

        status = IngestionStatus.PARSED if not warnings else IngestionStatus.PARTIAL

        return FileIngestionResult(
            file_id=file_id,
            file_path=file_path,
            origin=origin,
            format="json",
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
