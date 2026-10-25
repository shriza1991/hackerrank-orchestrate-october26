"""Unified evidence ingestion service for structured and multimodal participant evidence."""

import time
from pathlib import Path
from typing import Optional

from ghost_audit.config import Settings, get_settings
from ghost_audit.evidence.common import compute_content_digest
from ghost_audit.evidence.image_parser import ImageEvidenceParser
from ghost_audit.evidence.json_parser import JsonEvidenceParser
from ghost_audit.evidence.log_parser import LogEvidenceParser
from ghost_audit.evidence.models import (
    EvidenceIngestionSummary,
    FileIngestionResult,
    IngestionStatus,
)
from ghost_audit.evidence.pdf_parser import PdfEvidenceParser
from ghost_audit.evidence.sql_parser import SqlEvidenceParser
from ghost_audit.loader import DataLoader
from ghost_audit.manifest import validate_evidence_manifest
from ghost_audit.models.input_models import EvidenceManifestEntry
from ghost_audit.timestamps import parse_iso_timestamp


class EvidenceIngestionService:
    """Service to load, dispatch, parse, and collect observations from evidence files."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.config = self.settings
        self.json_parser = JsonEvidenceParser()
        self.sql_parser = SqlEvidenceParser()
        self.log_parser = LogEvidenceParser()
        self.pdf_parser = PdfEvidenceParser()
        self.image_parser = ImageEvidenceParser()

    def ingest_file(
        self,
        entry: EvidenceManifestEntry,
        dataset_dir: Optional[Path] = None,
        mode: str = "structured",
    ) -> FileIngestionResult:
        """Parse a single manifest evidence entry based on its format and ingestion mode."""
        base_dir = dataset_dir or self.config.dataset_dir
        resolved_path = (base_dir / entry.file_path).resolve()

        # Check path safety
        evidence_root = (base_dir / "evidence").resolve()
        try:
            resolved_path.relative_to(evidence_root)
        except ValueError:
            return FileIngestionResult(
                file_id=entry.file_id,
                file_path=entry.file_path,
                origin=entry.origin,
                format="unknown",
                status=IngestionStatus.FAILED,
                parser_name="PathValidator",
                parser_version="1.0.0",
                observation_count=0,
                observations=[],
                warnings=[],
                errors=[f"File path traversal outside evidence directory: {entry.file_path}"],
                unparsed_fragments=[],
                content_digest=None,
            )

        if not resolved_path.is_file():
            return FileIngestionResult(
                file_id=entry.file_id,
                file_path=entry.file_path,
                origin=entry.origin,
                format="unknown",
                status=IngestionStatus.FAILED,
                parser_name="PathValidator",
                parser_version="1.0.0",
                observation_count=0,
                observations=[],
                warnings=[],
                errors=[f"Evidence file missing on disk: {entry.file_path}"],
                unparsed_fragments=[],
                content_digest=None,
            )

        ext = resolved_path.suffix.lower()
        start_time = time.perf_counter()

        captured_at = entry.captured_at
        if isinstance(captured_at, str):
            captured_at = parse_iso_timestamp(captured_at)

        # Mode-based deferral handling
        is_multimodal = ext in {".pdf", ".png", ".jpg", ".jpeg"}
        if mode == "structured" and is_multimodal:
            try:
                raw_bytes = resolved_path.read_bytes()
                digest = compute_content_digest(raw_bytes)
            except Exception:
                digest = None

            elapsed = (time.perf_counter() - start_time) * 1000
            return FileIngestionResult(
                file_id=entry.file_id,
                file_path=entry.file_path,
                origin=entry.origin,
                format=ext.lstrip("."),
                status=IngestionStatus.DEFERRED,
                parser_name="DeferredMultimodalParser",
                parser_version="1.0.0",
                observation_count=0,
                observations=[],
                warnings=[f"Multimodal evidence ({ext}) deferred to Task 7 under mode='structured'."],
                errors=[],
                unparsed_fragments=[],
                content_digest=digest,
                execution_time_ms=elapsed,
            )
        elif mode == "multimodal" and not is_multimodal:
            try:
                raw_bytes = resolved_path.read_bytes()
                digest = compute_content_digest(raw_bytes)
            except Exception:
                digest = None

            elapsed = (time.perf_counter() - start_time) * 1000
            return FileIngestionResult(
                file_id=entry.file_id,
                file_path=entry.file_path,
                origin=entry.origin,
                format=ext.lstrip("."),
                status=IngestionStatus.DEFERRED,
                parser_name="DeferredStructuredParser",
                parser_version="1.0.0",
                observation_count=0,
                observations=[],
                warnings=[f"Structured evidence ({ext}) deferred under mode='multimodal'."],
                errors=[],
                unparsed_fragments=[],
                content_digest=digest,
                execution_time_ms=elapsed,
            )

        # Dispatch multimodal parsers
        if ext == ".pdf":
            result = self.pdf_parser.parse(
                file_id=entry.file_id,
                file_path=entry.file_path,
                origin=entry.origin,
                manifest_captured_at=captured_at,
                full_path=resolved_path,
            )
            elapsed = (time.perf_counter() - start_time) * 1000
            return FileIngestionResult(
                file_id=result.file_id,
                file_path=result.file_path,
                origin=result.origin,
                format=result.format,
                status=result.status,
                parser_name=result.parser_name,
                parser_version=result.parser_version,
                observation_count=result.observation_count,
                observations=result.observations,
                warnings=result.warnings,
                errors=result.errors,
                unparsed_fragments=result.unparsed_fragments,
                content_digest=result.content_digest,
                execution_time_ms=elapsed,
            )
        elif ext in {".png", ".jpg", ".jpeg"}:
            result = self.image_parser.parse(
                file_id=entry.file_id,
                file_path=entry.file_path,
                origin=entry.origin,
                manifest_captured_at=captured_at,
                full_path=resolved_path,
            )
            elapsed = (time.perf_counter() - start_time) * 1000
            return FileIngestionResult(
                file_id=result.file_id,
                file_path=result.file_path,
                origin=result.origin,
                format=result.format,
                status=result.status,
                parser_name=result.parser_name,
                parser_version=result.parser_version,
                observation_count=result.observation_count,
                observations=result.observations,
                warnings=result.warnings,
                errors=result.errors,
                unparsed_fragments=result.unparsed_fragments,
                content_digest=result.content_digest,
                execution_time_ms=elapsed,
            )

        # Read text content for structured files (.json, .sql, .log, .txt)
        try:
            content = resolved_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                content = resolved_path.read_text(encoding="utf-8-sig")
            except Exception as e:
                elapsed = (time.perf_counter() - start_time) * 1000
                return FileIngestionResult(
                    file_id=entry.file_id,
                    file_path=entry.file_path,
                    origin=entry.origin,
                    format=ext.lstrip("."),
                    status=IngestionStatus.FAILED,
                    parser_name="FileReader",
                    parser_version="1.0.0",
                    observation_count=0,
                    observations=[],
                    warnings=[],
                    errors=[f"Encoding error reading {entry.file_path}: {e}"],
                    unparsed_fragments=[],
                    content_digest=None,
                    execution_time_ms=elapsed,
                )

        if ext == ".json":
            result = self.json_parser.parse(
                file_id=entry.file_id,
                file_path=entry.file_path,
                origin=entry.origin,
                manifest_captured_at=captured_at,
                content=content,
            )
        elif ext == ".sql":
            result = self.sql_parser.parse(
                file_id=entry.file_id,
                file_path=entry.file_path,
                origin=entry.origin,
                manifest_captured_at=captured_at,
                content=content,
            )
        elif ext in {".log", ".txt"}:
            result = self.log_parser.parse(
                file_id=entry.file_id,
                file_path=entry.file_path,
                origin=entry.origin,
                manifest_captured_at=captured_at,
                content=content,
            )
        else:
            elapsed = (time.perf_counter() - start_time) * 1000
            return FileIngestionResult(
                file_id=entry.file_id,
                file_path=entry.file_path,
                origin=entry.origin,
                format=ext.lstrip("."),
                status=IngestionStatus.FAILED,
                parser_name="Dispatcher",
                parser_version="1.0.0",
                observation_count=0,
                observations=[],
                warnings=[],
                errors=[f"Unsupported evidence file extension: {ext}"],
                unparsed_fragments=[],
                content_digest=compute_content_digest(content),
                execution_time_ms=elapsed,
            )

        elapsed = (time.perf_counter() - start_time) * 1000
        return FileIngestionResult(
            file_id=result.file_id,
            file_path=result.file_path,
            origin=result.origin,
            format=result.format,
            status=result.status,
            parser_name=result.parser_name,
            parser_version=result.parser_version,
            observation_count=result.observation_count,
            observations=result.observations,
            warnings=result.warnings,
            errors=result.errors,
            unparsed_fragments=result.unparsed_fragments,
            content_digest=result.content_digest,
            execution_time_ms=elapsed,
        )

    def ingest_manifest(
        self,
        dataset_dir: Optional[Path] = None,
        file_id_filter: Optional[str] = None,
        mode: str = "structured",
        raise_on_manifest_error: bool = False,
    ) -> EvidenceIngestionSummary:
        """Ingest all or selected evidence files according to dataset manifest and mode."""
        base_settings = get_settings(dataset_dir) if dataset_dir else self.settings
        base_dir = base_settings.dataset_dir
        loader = DataLoader(base_settings)
        manifest_entries, issues = loader.load_evidence_manifest(base_settings.evidence_files_path)

        manifest_errors = [
            f"{i.file_name} (row {i.row_index or 'header'}, field {i.field_name or 'N/A'}): {i.message}"
            for i in issues
            if i.severity == "ERROR"
        ]
        if raise_on_manifest_error and manifest_errors:
            raise ValueError(f"Fatal manifest error(s): {'; '.join(manifest_errors)}")

        # Sort entries deterministically by file_id
        sorted_entries = sorted(manifest_entries, key=lambda e: e.file_id)

        if file_id_filter:
            sorted_entries = [e for e in sorted_entries if e.file_id == file_id_filter]
            if not sorted_entries:
                raise ValueError(f"File ID '{file_id_filter}' not found in evidence manifest.")

        file_results: list[FileIngestionResult] = []
        parsed_count = 0
        partial_count = 0
        failed_count = len(manifest_errors)
        deferred_count = 0
        total_obs = 0
        by_format: dict[str, dict[str, int]] = {}

        for entry in sorted_entries:
            res = self.ingest_file(entry, base_dir, mode=mode)
            file_results.append(res)

            fmt = res.format.lower()
            if fmt not in by_format:
                by_format[fmt] = {"parsed": 0, "partial": 0, "failed": 0, "deferred": 0, "observations": 0}

            st_val = res.status.value.lower()
            if st_val in by_format[fmt]:
                by_format[fmt][st_val] += 1
            by_format[fmt]["observations"] += res.observation_count

            if res.status == IngestionStatus.PARSED:
                parsed_count += 1
            elif res.status == IngestionStatus.PARTIAL:
                partial_count += 1
            elif res.status == IngestionStatus.FAILED:
                failed_count += 1
            elif res.status == IngestionStatus.DEFERRED:
                deferred_count += 1

            total_obs += res.observation_count

        return EvidenceIngestionSummary(
            manifest_file_count=len(sorted_entries),
            parsed_count=parsed_count,
            partial_count=partial_count,
            failed_count=failed_count,
            deferred_count=deferred_count,
            total_observations=total_obs,
            by_format=by_format,
            file_results=file_results,
            manifest_errors=manifest_errors,
        )
