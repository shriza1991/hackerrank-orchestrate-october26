"""PDF document evidence parser extracting text, layout, and provenance from business documents."""

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


PARSER_NAME = "PdfEvidenceParser"
PARSER_VERSION = "1.0.0"

# Regex extractors for grounded identifiers
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
PHONE_PATTERN = re.compile(r'\+\d{1,3}(?:[\s-]?\(?\d{1,4}\)?)+[\s-]?\d{3,5}[\s-]?\d{3,5}')
USER_ID_PATTERN = re.compile(r'\buser_\d+\b')
RESOURCE_ID_PATTERN = re.compile(
    r'\b(?:account|analytics|support|marketing|backup|export|search|audit_record|data_flow)_\w+\b'
    r'|\bCS-\d+\b|\bORD-\d+\b|\bNST-[\w-]+\b|\bCJX-[\w-]+\b'
)

# Multi-record disputed orders table row pattern (e.g. in legal_retention_register_20260529.pdf)
# Example: ORD-20264118 | user_08 | Card dispute | 04 May 2026 | USD 184.20 | Retain until 04 May 2033 | AR
TABLE_ROW_PATTERN = re.compile(
    r'(ORD-\d+)\s*\|\s*(user_\d+)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*Retain until\s*([^|]+)\|\s*(\w+)',
    re.IGNORECASE,
)


def parse_human_readable_date(text: str) -> Optional[datetime]:
    """Parse common document timestamps into UTC datetime."""
    cleaned = re.sub(r'\s+', ' ', text.strip())
    # Normalise things like "18 Jun 2026 10 24 UTC" where colon was missing or space-separated
    cleaned = re.sub(r'(\d{2})\s+(\d{2})\s+UTC', r'\1:\2 UTC', cleaned)
    
    formats = [
        "%d %b %Y %H:%M:%S UTC",
        "%d %b %Y %H:%M UTC",
        "%d %b %Y %H:%M:%S",
        "%d %b %Y %H:%M",
        "%d %b %Y",
        "%d%b %Y %H:%M UTC",
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


class PdfEvidenceParser:
    """Parser for evidence provided as PDF documents (invoices, statements, registers, certificates)."""

    def __init__(self) -> None:
        self.parser_name = PARSER_NAME
        self.parser_version = PARSER_VERSION

    def parse(
        self,
        file_id: str,
        file_path: str,
        origin: str,
        manifest_captured_at: datetime,
        full_path: Path,
        allow_ocr: bool = True,
    ) -> FileIngestionResult:
        """Parse native text and layout from PDF document, emitting structured EvidenceObservation items."""
        if not full_path.exists():
            return FileIngestionResult(
                file_id=file_id,
                file_path=file_path,
                origin=origin,
                format="pdf",
                status=IngestionStatus.FAILED,
                parser_name=self.parser_name,
                parser_version=self.parser_version,
                observation_count=0,
                observations=[],
                warnings=[],
                errors=[f"PDF file does not exist at {full_path}"],
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
                format="pdf",
                status=IngestionStatus.FAILED,
                parser_name=self.parser_name,
                parser_version=self.parser_version,
                observation_count=0,
                observations=[],
                warnings=[],
                errors=[f"Failed to read PDF file bytes: {exc}"],
                unparsed_fragments=[],
                content_digest="",
            )

        # Attempt to open document using PyMuPDF (fitz), with fallback to pypdf
        doc = None
        use_fitz = False
        try:
            import fitz
            doc = fitz.open(stream=content_bytes, filetype="pdf")
            use_fitz = True
        except ImportError:
            try:
                import pypdf
                doc = pypdf.PdfReader(full_path)
                use_fitz = False
            except ImportError:
                return FileIngestionResult(
                    file_id=file_id,
                    file_path=file_path,
                    origin=origin,
                    format="pdf",
                    status=IngestionStatus.FAILED,
                    parser_name=self.parser_name,
                    parser_version=self.parser_version,
                    observation_count=0,
                    observations=[],
                    warnings=[],
                    errors=["Neither PyMuPDF (fitz) nor pypdf is installed."],
                    unparsed_fragments=[],
                    content_digest=content_digest,
                )
        except Exception as exc:
            return FileIngestionResult(
                file_id=file_id,
                file_path=file_path,
                origin=origin,
                format="pdf",
                status=IngestionStatus.FAILED,
                parser_name=self.parser_name,
                parser_version=self.parser_version,
                observation_count=0,
                observations=[],
                warnings=[],
                errors=[f"Failed to open PDF document: {exc}"],
                unparsed_fragments=[],
                content_digest=content_digest,
            )

        num_pages = len(doc.pages) if not use_fitz else len(doc)
        observations: list[EvidenceObservation] = []
        warnings: list[str] = []
        obs_idx = 0

        # Process each page with provenance
        for page_idx in range(1, num_pages + 1):
            page_text = ""
            if use_fitz:
                page = doc[page_idx - 1]
                page_text = page.get_text()
            else:
                page = doc.pages[page_idx - 1]
                page_text = page.extract_text() or ""

            # Check if page has unusable or absent text
            if len(page_text.strip()) < 15:
                # Page has no native text; attempt local OCR if RapidOCR is available and fitz is active
                ocr_text = self._attempt_ocr_page(page, use_fitz) if allow_ocr else None
                if ocr_text:
                    page_text = ocr_text
                    warnings.append(f"Page {page_idx} extracted via fallback OCR.")
                else:
                    reason = "OCR disabled for safe structured mode" if not allow_ocr else "OCR was unavailable or produced no text"
                    warnings.append(f"Page {page_idx} has unusable or absent native text; {reason}.")
                    continue

            # Check if this page contains a multi-record table (e.g. Disputed Orders / Retention Register)
            table_rows = list(TABLE_ROW_PATTERN.finditer(page_text))
            if table_rows:
                # Multiple distinct subjects and orders on one page: emit isolated observation per row
                for r_idx, match in enumerate(table_rows, start=1):
                    order_id, user_id, reason, order_date_raw, amount, retain_until_raw, owner = match.groups()
                    order_id = order_id.strip()
                    user_id = user_id.strip()
                    reason = reason.strip()
                    order_date_raw = order_date_raw.strip()
                    amount = amount.strip()
                    retain_until_raw = retain_until_raw.strip()
                    owner = owner.strip()

                    parsed_order_date = parse_human_readable_date(order_date_raw)
                    parsed_retention = parse_human_readable_date(retain_until_raw)

                    extracted_facts = {
                        "order_id": order_id,
                        "user_id": user_id,
                        "dispute_reason": reason,
                        "order_date": order_date_raw,
                        "order_date_iso": parsed_order_date.isoformat() if parsed_order_date else None,
                        "amount": amount,
                        "retention_until": retain_until_raw,
                        "retention_until_iso": parsed_retention.isoformat() if parsed_retention else None,
                        "hold_status": "ACTIVE",
                        "hold_end": parsed_retention.isoformat() if parsed_retention else retain_until_raw,
                        "finance_owner": owner,
                        "raw_entry": match.group(0),
                    }

                    obs_idx += 1
                    observations.append(
                        EvidenceObservation(
                            evidence_id=file_id,
                            source_locator=f"page:{page_idx}:row:{r_idx}",
                            capture_time=manifest_captured_at,
                            observation_time=parsed_order_date or manifest_captured_at,
                            system_id=self._derive_system_id(origin, page_text),
                            resource_id=order_id,
                            extracted_facts=extracted_facts,
                            extraction_method=self.parser_name,
                            uncertainty_or_warnings=[],
                            internal_id=make_observation_id(file_id, obs_idx),
                            file_path=file_path,
                            observation_type=ObservationType.STORED_RECORD.value,
                            scope_context={
                                "page": page_idx,
                                "total_pages": num_pages,
                                "row_index": r_idx,
                                "multi_subject_isolated": True,
                            },
                            subject_references=[user_id],  # ONLY this row's user!
                            content_digest=content_digest,
                        )
                    )
            else:
                # Single-record page or document summary page
                obs = self._parse_document_page(
                    file_id=file_id,
                    file_path=file_path,
                    origin=origin,
                    manifest_captured_at=manifest_captured_at,
                    page_idx=page_idx,
                    num_pages=num_pages,
                    page_text=page_text,
                    content_digest=content_digest,
                    obs_idx=obs_idx + 1,
                )
                if obs:
                    obs_idx += 1
                    observations.append(obs)

        status = IngestionStatus.PARSED
        if not observations:
            status = IngestionStatus.FAILED
        elif warnings:
            status = IngestionStatus.PARTIAL if any("absent" in w or "unusable" in w for w in warnings) else IngestionStatus.PARSED

        return FileIngestionResult(
            file_id=file_id,
            file_path=file_path,
            origin=origin,
            format="pdf",
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

    def _parse_document_page(
        self,
        file_id: str,
        file_path: str,
        origin: str,
        manifest_captured_at: datetime,
        page_idx: int,
        num_pages: int,
        page_text: str,
        content_digest: str,
        obs_idx: int,
    ) -> Optional[EvidenceObservation]:
        """Parse non-tabular document page into an EvidenceObservation."""
        # Extract identifiers
        emails = sorted(set(EMAIL_PATTERN.findall(page_text)))
        phones = sorted(set(PHONE_PATTERN.findall(page_text)))
        user_ids = sorted(set(USER_ID_PATTERN.findall(page_text)))
        resource_ids = sorted(set(RESOURCE_ID_PATTERN.findall(page_text)))

        subject_refs = sorted(set(user_ids + emails + phones))

        # Check for visible timestamps
        visible_time = manifest_captured_at
        # Date patterns like "submitted 18 Jun 2026 10 24 UTC", "received 18 Jun 2026", "issued 05 Sep 2026 06 30 UTC", "recorded 25 Aug 2026 04 03 UTC"
        time_match = re.search(
            r'(?:submitted|received|generated|issued|recorded|captured|order date)\s*([0-9]{1,2}\s+[A-Za-z]{3}\s+[0-9]{4}(?:\s+[0-9]{1,2}(?::|\s+)[0-9]{2}(?:\s+UTC)?)?)',
            page_text,
            re.IGNORECASE,
        )
        if time_match:
            parsed = parse_human_readable_date(time_match.group(1))
            if parsed:
                visible_time = parsed

        # Retention dates
        retention_info = None
        retention_match = re.search(r'retain\s+until\s*([0-9]{1,2}\s+[A-Za-z]{3}\s+[0-9]{4}(?:\s+[0-9]{1,2}(?::|\s+)[0-9]{2}(?:\s+UTC)?)?)', page_text, re.IGNORECASE)
        if retention_match:
            ret_parsed = parse_human_readable_date(retention_match.group(1))
            retention_info = {
                "retention_until_raw": retention_match.group(1).strip(),
                "retention_until_iso": ret_parsed.isoformat() if ret_parsed else None,
            }

        # Customer name
        name_match = re.search(r'Customer\s+([A-Za-z\s]+)\b', page_text) or re.search(r'Detail\s*\n\s*([A-Za-z\s]+)\s*\n\s*Detail\s*\n\s*user_', page_text)
        customer_name = name_match.group(1).strip() if name_match else None

        # Determine primary resource ID
        primary_resource = resource_ids[0] if resource_ids else None

        extracted_facts: dict[str, Any] = {
            "page": page_idx,
            "total_pages": num_pages,
            "emails": emails,
            "phones": phones,
            "user_ids": user_ids,
            "resource_ids": resource_ids,
            "linked_resources": resource_ids,
            "raw_text": page_text.strip(),
            "page_text_excerpt": page_text[:400].strip(),
        }
        if customer_name:
            extracted_facts["customer_name"] = customer_name
        if retention_info:
            extracted_facts["retention"] = retention_info
            extracted_facts["retention_until"] = (
                retention_info["retention_until_iso"] or retention_info["retention_until_raw"]
            )

        return EvidenceObservation(
            evidence_id=file_id,
            source_locator=f"page:{page_idx}",
            capture_time=manifest_captured_at,
            observation_time=visible_time,
            system_id=self._derive_system_id(origin, page_text),
            resource_id=primary_resource,
            extracted_facts=extracted_facts,
            extraction_method=self.parser_name,
            uncertainty_or_warnings=[],
            internal_id=make_observation_id(file_id, obs_idx),
            file_path=file_path,
            observation_type=ObservationType.STORED_RECORD.value,
            scope_context={"page": page_idx, "total_pages": num_pages},
            subject_references=subject_refs,
            content_digest=content_digest,
        )

    def _derive_system_id(self, origin: str, text: str) -> str:
        """Infer system ID from document context or fallback to origin."""
        lower_text = text.lower()
        if "compliance journal" in lower_text or "audit_record" in lower_text or "cjx-" in lower_text:
            return "security_service"
        if "helpline" in lower_text or "support" in lower_text or "cs-" in lower_text:
            return "support_platform"
        if "customer statement" in lower_text or "nst-" in lower_text:
            return "account_service"
        if "analytics" in lower_text:
            return "analytics_platform"
        if "bridgeops" in lower_text or "connector" in lower_text:
            return "integration_service"
        if "vault recovery" in lower_text or "backup" in lower_text:
            return "backup_service"
        if "download center" in lower_text or "export" in lower_text:
            return "export_service"
        if "search" in lower_text:
            return "search_service"
        return origin or "account_service"

    def _attempt_ocr_page(self, page: Any, use_fitz: bool) -> Optional[str]:
        """Attempt to render and OCR a page with absent native text using RapidOCR."""
        if not use_fitz:
            return None
        try:
            from rapidocr_onnxruntime import RapidOCR
            ocr = RapidOCR()
            # Render page to image bytes
            pix = page.get_pixmap()
            img_bytes = pix.tobytes("png")
            result, _ = ocr(img_bytes)
            if result:
                lines = [item[1] for item in result if float(item[2]) > 0.4]
                return "\n".join(lines)
        except Exception:
            pass
        return None
