"""Image evidence parser extracting text, bounding boxes, and visual console facts."""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ghost_audit.evidence.common import (
    compute_content_digest,
    make_observation_id,
)
from ghost_audit.evidence.models import (
    FileIngestionResult,
    IngestionStatus,
    ObservationType,
)
from ghost_audit.models.intermediate_models import EvidenceObservation


PARSER_NAME = "ImageEvidenceParser"
PARSER_VERSION = "1.0.0"

# Mapping from manifest origin to canonical platform subsystem
ORIGIN_SYSTEM_MAP = {
    "account_admin_portal": "account_service",
    "account_history_service": "account_service",
    "identity_service": "account_service",
    "legal_retention_service": "account_service",
    "search_index_admin": "search_service",
    "integration_admin": "integration_service",
    "analytics_platform": "analytics_platform",
    "marketing_platform": "analytics_platform",
    "export_service": "export_service",
    "object_storage": "export_service",
    "support_platform": "support_platform",
    "customer_support_service": "support_platform",
    "backup_service": "backup_service",
    "security_service": "security_service",
    "security_compliance_service": "security_service",
}

# Regex extractors for grounded identifiers
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
PHONE_PATTERN = re.compile(r'\+\d{1,3}(?:[\s-]?\(?\d{1,4}\)?)+[\s-]?\d{3,5}[\s-]?\d{3,5}')
USER_ID_PATTERN = re.compile(r'\buser_\d+\b')
RESOURCE_ID_PATTERN = re.compile(
    r'(?:account|analytics|support|marketing|backup|export|search|audit_record|data_flow)_[0-9a-zA-Z]+'
    r'|\bCS-[0-9]+\b|\bORD-[0-9]+\b|\bNST-[0-9a-zA-Z-]+\b|\bCJX-[0-9a-zA-Z-]+\b'
)


def select_primary_resource_id(resource_ids: list[str], system_id: str) -> Optional[str]:
    """Select the primary resource ID matching the system role."""
    if not resource_ids:
        return None
    pref_map = {
        "account_service": ["account_"],
        "integration_service": ["data_flow_"],
        "backup_service": ["backup_"],
        "export_service": ["export_"],
        "search_service": ["search_"],
        "security_service": ["audit_record_", "CJX-"],
        "support_platform": ["support_", "CS-"],
        "analytics_platform": ["analytics_", "marketing_"],
    }
    prefixes = pref_map.get(system_id, [])
    for pfx in prefixes:
        for rid in resource_ids:
            if rid.startswith(pfx):
                return rid
    return resource_ids[0]


def clean_email(candidate: str) -> str:
    """Strip system prefixes like user_20- or marketing_001- from OCR-extracted emails."""
    match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', candidate)
    if not match:
        return candidate
    val = match.group(0)
    # Strip resource or user prefix before email if present (e.g. user_20-analytics_7438-darwish.omar@icloud.com)
    val = re.sub(r'^(?:user_\w+-|analytics_\w+-|marketing_\w+-|account_\w+-|support_\w+-)+', '', val)
    return val


def parse_human_readable_date(text: str) -> Optional[datetime]:
    """Parse common document and screenshot timestamps into UTC datetime."""
    cleaned = re.sub(r'\s+', ' ', text.strip())
    # Normalise things like "07Aug 2026 08:00 UTC" -> "07 Aug 2026 08:00 UTC"
    cleaned = re.sub(r'(\d{2})([A-Za-z]{3})', r'\1 \2', cleaned)
    cleaned = re.sub(r'(\d{2})\s+(\d{2})\s+UTC', r'\1:\2 UTC', cleaned)

    formats = [
        "%d %b %Y %H:%M:%S UTC",
        "%d %b %Y %H:%M UTC",
        "%d %b %Y %H:%M:%S",
        "%d %b %Y %H:%M",
        "%d %b %Y",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(cleaned, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


class ImageEvidenceParser:
    """Parser for evidence provided as PNG screenshots (internal product and ops consoles)."""

    def __init__(self) -> None:
        self.parser_name = PARSER_NAME
        self.parser_version = PARSER_VERSION
        self._ocr_instance: Any = None

    def _get_ocr(self) -> Any:
        """Lazy initialization of RapidOCR engine."""
        if self._ocr_instance is None:
            from rapidocr_onnxruntime import RapidOCR
            self._ocr_instance = RapidOCR()
        return self._ocr_instance

    def parse(
        self,
        file_id: str,
        file_path: str,
        origin: str,
        manifest_captured_at: datetime,
        full_path: Path,
    ) -> FileIngestionResult:
        """Parse text and spatial bounding boxes from screenshot, emitting structured observations."""
        if not full_path.exists():
            return FileIngestionResult(
                file_id=file_id,
                file_path=file_path,
                origin=origin,
                format="png",
                status=IngestionStatus.FAILED,
                parser_name=self.parser_name,
                parser_version=self.parser_version,
                observation_count=0,
                observations=[],
                warnings=[],
                errors=[f"Image file does not exist at {full_path}"],
                unparsed_fragments=[],
                content_digest="",
            )

        try:
            content_bytes = full_path.read_bytes()
            content_digest = compute_content_digest(content_bytes)
        except Exception as exc:
            return FileIngestionResult(
                file_id=file_id,
                file_path=file_path,
                origin=origin,
                format="png",
                status=IngestionStatus.FAILED,
                parser_name=self.parser_name,
                parser_version=self.parser_version,
                observation_count=0,
                observations=[],
                warnings=[],
                errors=[f"Failed to read image bytes: {exc}"],
                unparsed_fragments=[],
                content_digest="",
            )

        # Lazy OCR invocation
        try:
            ocr = self._get_ocr()
            ocr_result, _ = ocr(str(full_path.resolve()))
        except ImportError:
            return FileIngestionResult(
                file_id=file_id,
                file_path=file_path,
                origin=origin,
                format="png",
                status=IngestionStatus.FAILED,
                parser_name=self.parser_name,
                parser_version=self.parser_version,
                observation_count=0,
                observations=[],
                warnings=[],
                errors=["rapidocr_onnxruntime is not installed. Install it with 'pip install rapidocr_onnxruntime'."],
                unparsed_fragments=[],
                content_digest=content_digest,
            )
        except Exception as exc:
            return FileIngestionResult(
                file_id=file_id,
                file_path=file_path,
                origin=origin,
                format="png",
                status=IngestionStatus.FAILED,
                parser_name=self.parser_name,
                parser_version=self.parser_version,
                observation_count=0,
                observations=[],
                warnings=[],
                errors=[f"OCR execution failed: {exc}"],
                unparsed_fragments=[],
                content_digest=content_digest,
            )

        if not ocr_result:
            return FileIngestionResult(
                file_id=file_id,
                file_path=file_path,
                origin=origin,
                format="png",
                status=IngestionStatus.FAILED,
                parser_name=self.parser_name,
                parser_version=self.parser_version,
                observation_count=0,
                observations=[],
                warnings=["No text detected by OCR backend."],
                errors=["Empty OCR text result."],
                unparsed_fragments=[],
                content_digest=content_digest,
            )

        # Parse OCR items: filter low confidence
        parsed_boxes: list[dict[str, Any]] = []
        full_text_lines: list[str] = []
        all_x: list[float] = []
        all_y: list[float] = []

        for item in ocr_result:
            box, text, score = item
            score_f = float(score)
            if score_f < 0.40:
                continue
            text_str = text.strip()
            if not text_str:
                continue

            # box is [[x1, y1], [x2, y1], [x2, y2], [x1, y2]]
            x_coords = [p[0] for p in box]
            y_coords = [p[1] for p in box]
            min_x, max_x = min(x_coords), max(x_coords)
            min_y, max_y = min(y_coords), max(y_coords)

            all_x.extend([min_x, max_x])
            all_y.extend([min_y, max_y])

            parsed_boxes.append({
                "text": text_str,
                "score": score_f,
                "bbox": [int(min_x), int(min_y), int(max_x), int(max_y)],
                "top_y": min_y,
                "left_x": min_x,
            })
            full_text_lines.append(text_str)

        full_text = "\n".join(full_text_lines)
        overall_bbox = [int(min(all_x)), int(min(all_y)), int(max(all_x)), int(max(all_y))] if all_x else [0, 0, 0, 0]

        # Authoritative system ID from manifest origin or console UI
        system_id = ORIGIN_SYSTEM_MAP.get(origin) or self._derive_system_id_from_text(origin, full_text)

        # Check for visible timestamps in screenshot
        visible_time = manifest_captured_at
        time_match = re.search(
            r'([0-9]{1,2}\s+[A-Za-z]{3}\s+[0-9]{4}(?:\s+[0-9]{1,2}(?::|\s+)[0-9]{2}(?:\s+UTC)?)?)',
            full_text,
        )
        if time_match:
            parsed = parse_human_readable_date(time_match.group(1))
            if parsed:
                visible_time = parsed

        # Detect multi-row table structure (e.g. in connector_management_console, backup_restore_console, customer_export_console)
        # Table rows typically sit in left_x < 1400 and top_y between 380 and 580
        table_items = [b for b in parsed_boxes if 380 <= b["top_y"] <= 580 and b["left_x"] < 1380]
        detail_items = [b for b in parsed_boxes if b["left_x"] >= 1380 and 320 <= b["top_y"] <= 900]

        # Group table items into horizontal rows (cluster tolerance: 22 pixels)
        table_items.sort(key=lambda b: b["top_y"])
        clustered_rows: list[list[dict[str, Any]]] = []
        for item in table_items:
            if not clustered_rows or abs(item["top_y"] - clustered_rows[-1][0]["top_y"]) > 22:
                clustered_rows.append([item])
            else:
                clustered_rows[-1].append(item)

        # Check whether clustered rows contain multiple distinct subjects.
        # Only treat as multi-record table if multiple distinct rows have subject identifiers (preventing
        # order lists on single-customer consoles from splitting the account identity).
        rows_with_subjects = [r for r in clustered_rows if any(EMAIL_PATTERN.findall(x["text"]) or USER_ID_PATTERN.findall(x["text"]) for x in r)]
        is_multi_record_table = len(rows_with_subjects) >= 2

        observations: list[EvidenceObservation] = []
        obs_idx = 0

        if is_multi_record_table:
            # Multi-record table: isolate each table row to avoid cross-subject leakage
            for r_idx, row in enumerate(clustered_rows, start=1):
                row.sort(key=lambda b: b["left_x"])
                row_text = " | ".join(b["text"] for b in row)

                # Extract identifiers strictly belonging to this row
                raw_emails = EMAIL_PATTERN.findall(row_text)
                cleaned_emails = sorted(set(clean_email(e) for e in raw_emails))
                row_phones = sorted(set(PHONE_PATTERN.findall(row_text)))
                row_users = sorted(set(USER_ID_PATTERN.findall(row_text)))
                row_resources = sorted(set(RESOURCE_ID_PATTERN.findall(row_text)))

                row_subjects = sorted(set(row_users + cleaned_emails + row_phones))
                primary_res = select_primary_resource_id(row_resources, system_id)

                # Compute row bounding box
                r_min_x = min(b["bbox"][0] for b in row)
                r_min_y = min(b["bbox"][1] for b in row)
                r_max_x = max(b["bbox"][2] for b in row)
                r_max_y = max(b["bbox"][3] for b in row)

                obs_idx += 1
                observations.append(
                    EvidenceObservation(
                        evidence_id=file_id,
                        source_locator=f"region:row:{r_idx}",
                        capture_time=manifest_captured_at,
                        observation_time=visible_time,
                        system_id=system_id,
                        resource_id=primary_res,
                        extracted_facts={
                            "row_index": r_idx,
                            "row_text": row_text,
                            "emails": cleaned_emails,
                            "phones": row_phones,
                            "user_ids": row_users,
                            "resource_ids": row_resources,
                        },
                        extraction_method=self.parser_name,
                        uncertainty_or_warnings=[],
                        internal_id=make_observation_id(file_id, obs_idx),
                        file_path=file_path,
                        observation_type=ObservationType.STORED_RECORD.value,
                        scope_context={
                            "ocr_backend": "rapidocr_onnxruntime",
                            "bounding_box": [r_min_x, r_min_y, r_max_x, r_max_y],
                            "row_index": r_idx,
                            "multi_subject_isolated": True,
                        },
                        subject_references=row_subjects,
                        content_digest=content_digest,
                    )
                )

            # If there is also an active detail panel on the right, emit it as a distinct observation
            if detail_items:
                detail_text = "\n".join(b["text"] for b in detail_items)
                d_raw_emails = EMAIL_PATTERN.findall(detail_text)
                d_emails = sorted(set(clean_email(e) for e in d_raw_emails))
                d_phones = sorted(set(PHONE_PATTERN.findall(detail_text)))
                d_users = sorted(set(USER_ID_PATTERN.findall(detail_text)))
                d_resources = sorted(set(RESOURCE_ID_PATTERN.findall(detail_text)))
                d_subjects = sorted(set(d_users + d_emails + d_phones))
                d_res = select_primary_resource_id(d_resources, system_id)

                d_min_x = min(b["bbox"][0] for b in detail_items)
                d_min_y = min(b["bbox"][1] for b in detail_items)
                d_max_x = max(b["bbox"][2] for b in detail_items)
                d_max_y = max(b["bbox"][3] for b in detail_items)

                obs_idx += 1
                observations.append(
                    EvidenceObservation(
                        evidence_id=file_id,
                        source_locator="region:detail_panel",
                        capture_time=manifest_captured_at,
                        observation_time=visible_time,
                        system_id=system_id,
                        resource_id=d_res,
                        extracted_facts={
                            "panel": "detail_inspector",
                            "emails": d_emails,
                            "phones": d_phones,
                            "user_ids": d_users,
                            "resource_ids": d_resources,
                            "detail_text_excerpt": detail_text[:400].strip(),
                        },
                        extraction_method=self.parser_name,
                        uncertainty_or_warnings=[],
                        internal_id=make_observation_id(file_id, obs_idx),
                        file_path=file_path,
                        observation_type=ObservationType.STORED_RECORD.value,
                        scope_context={
                            "ocr_backend": "rapidocr_onnxruntime",
                            "bounding_box": [d_min_x, d_min_y, d_max_x, d_max_y],
                            "is_detail_panel": True,
                        },
                        subject_references=d_subjects,
                        content_digest=content_digest,
                    )
                )

        else:
            # Single-record or whole-console view (e.g. account_admin_console, analytics_profile_view, deleted_account_reference)
            raw_emails = EMAIL_PATTERN.findall(full_text)
            emails = sorted(set(clean_email(e) for e in raw_emails))
            phones = sorted(set(PHONE_PATTERN.findall(full_text)))
            user_ids = sorted(set(USER_ID_PATTERN.findall(full_text)))
            resource_ids = sorted(set(RESOURCE_ID_PATTERN.findall(full_text)))

            subject_refs = sorted(set(user_ids + emails + phones))

            # Detect tombstone / retained reference pattern (e.g. deleted_account_reference)
            is_tombstone = "retained reference" in full_text.lower() or "customerkey" in full_text.lower()

            # Detect statuses
            status_val = None
            for cand in ["LIVE", "ACTIVE", "HEALTHY", "Retained reference", "Normal priority", "DELETED", "DELETION_PENDING"]:
                if cand.lower() in full_text.lower():
                    status_val = cand
                    break

            primary_resource = select_primary_resource_id(resource_ids, system_id)

            extracted_facts = {
                "system": system_id,
                "detected_line_count": len(parsed_boxes),
                "user_ids": user_ids,
                "emails": emails,
                "phones": phones,
                "resource_ids": resource_ids,
                "is_tombstone": is_tombstone,
                "visible_status": status_val,
                "full_text_excerpt": full_text[:500].strip(),
                "bounding_boxes_summary": f"{len(parsed_boxes)} OCR regions detected",
            }

            obs_idx += 1
            observations.append(
                EvidenceObservation(
                    evidence_id=file_id,
                    source_locator=f"region:bbox:[{overall_bbox[0]},{overall_bbox[1]},{overall_bbox[2]},{overall_bbox[3]}]",
                    capture_time=manifest_captured_at,
                    observation_time=visible_time,
                    system_id=system_id,
                    resource_id=primary_resource,
                    extracted_facts=extracted_facts,
                    extraction_method=self.parser_name,
                    uncertainty_or_warnings=[],
                    internal_id=make_observation_id(file_id, obs_idx),
                    file_path=file_path,
                    observation_type=ObservationType.STORED_RECORD.value,
                    scope_context={
                        "ocr_backend": "rapidocr_onnxruntime",
                        "bounding_box": overall_bbox,
                        "coordinate_units": "pixels",
                        "orientation": "top_left",
                    },
                    subject_references=subject_refs,
                    content_digest=content_digest,
                )
            )

        return FileIngestionResult(
            file_id=file_id,
            file_path=file_path,
            origin=origin,
            format="png",
            status=IngestionStatus.PARSED,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            observation_count=len(observations),
            observations=observations,
            warnings=[],
            errors=[],
            unparsed_fragments=[],
            content_digest=content_digest,
        )

    def _derive_system_id_from_text(self, origin: str, text: str) -> str:
        """Infer system ID from console UI text if origin was missing."""
        lower_text = text.lower()
        if "pulse analytics" in lower_text or "audience operations" in lower_text:
            return "analytics_platform"
        if "vault recovery" in lower_text or "backup" in lower_text:
            return "backup_service"
        if "bridgeops" in lower_text or "connections" in lower_text:
            return "integration_service"
        if "customerdownloadcenter" in lower_text or "nimbus object" in lower_text:
            return "export_service"
        if "search console" in lower_text or "customer search" in lower_text:
            return "search_service"
        if "sentinel" in lower_text or "account events" in lower_text:
            return "security_service"
        if "helpline console" in lower_text or "inbox" in lower_text:
            return "support_platform"
        if "customer operations" in lower_text or "customer reference" in lower_text:
            return "account_service"
        return origin or "account_service"
