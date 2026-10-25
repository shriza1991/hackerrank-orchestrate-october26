"""Shared end-to-end audit runner coordinating the full deletion-audit pipeline."""

from __future__ import annotations

import csv
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ghost_audit.config import Settings, get_settings, REPO_ROOT
from ghost_audit.evidence.service import EvidenceIngestionService
from ghost_audit.identity.service import IdentityResolutionService
from ghost_audit.intent.models import (
    CachedIntentEntry,
    IntentCacheFile,
    IntentModelOutput,
)
from ghost_audit.intent.prompt import PROMPT_VERSION
from ghost_audit.intent.service import IntentClassificationService, request_text_digest
from ghost_audit.llm.config import get_model_settings
from ghost_audit.llm.errors import ConfigurationError
from ghost_audit.llm.gateway import ModelGateway
from ghost_audit.llm.transport import OpenAIResponsesTransport
from ghost_audit.llm.usage import UsageTracker
from ghost_audit.loader import DataLoader
from ghost_audit.models.input_models import DeletionRequest
from ghost_audit.models.output_models import (
    DeletionStatus,
    OutputRow,
)
from ghost_audit.planner.service import AuditPlanGenerator
from ghost_audit.policy.service import PolicyDecisionEngine
from ghost_audit.retrieval.index import CorpusIndex
from ghost_audit.retrieval.service import EvidenceRetrievalService
from ghost_audit.state.reconstruction import ResourceStateEngine


@dataclass
class AuditRunSummary:
    """Summary metrics and diagnostic results for an end-to-end audit run."""

    total_cases: int = 0
    complete_cases: int = 0
    incomplete_cases: int = 0
    not_applicable_cases: int = 0
    unresolved_cases: int = 0
    diagnostic_bypass_count: int = 0
    unresolved_details: dict[str, list[str]] = field(default_factory=dict)
    execution_time_ms: float = 0.0
    output_path: Optional[str] = None
    is_valid_for_submission: bool = False
    usage_summary: Optional[dict[str, Any]] = None


class AuditPipelineRunner:
    """One shared end-to-end runner coordinating ingestion, retrieval, state reconstruction, policy, and planning."""

    def __init__(
        self,
        settings: Settings,
        mode: str = "structured",
        live: bool = False,
        intent_cache_path: Optional[Path] = None,
        diagnostic: bool = False,
    ) -> None:
        self.settings = settings
        self.mode = mode
        self.live = live
        self.diagnostic = diagnostic
        self.intent_cache_path = intent_cache_path
        self.usage_tracker = UsageTracker()

        # Initialize intent service or precomputed intent map
        self.precomputed_intents: dict[str, CachedIntentEntry] = {}
        if intent_cache_path and Path(intent_cache_path).exists():
            self._load_intent_cache(Path(intent_cache_path))

        self.intent_service: Optional[IntentClassificationService] = None
        if self.live:
            model_settings = get_model_settings()
            gateway = ModelGateway(
                settings=model_settings,
                transport=OpenAIResponsesTransport(),
                usage=self.usage_tracker,
            )
            self.intent_service = IntentClassificationService(gateway=gateway)

    def _load_intent_cache(self, path: Path) -> None:
        """Load a strict, versioned intent cache or reject the whole file."""
        try:
            cache = IntentCacheFile.model_validate_json(path.read_text(encoding="utf-8"), strict=True)
        except Exception as ex:
            raise ConfigurationError(f"Invalid intent cache {path}: strict validation failed.") from ex
        self.precomputed_intents = dict(cache.classifications)

    @staticmethod
    def _validated_cached_intent(entry: CachedIntentEntry, request: DeletionRequest) -> IntentModelOutput:
        if entry.prompt_version != PROMPT_VERSION:
            raise ConfigurationError(
                f"Intent cache prompt mismatch for {request.case_id}: expected {PROMPT_VERSION}."
            )
        if entry.request_text_sha256 != request_text_digest(request.request_text):
            raise ConfigurationError(f"Intent cache request-text mismatch for {request.case_id}.")
        if entry.intent.supporting_quote not in request.request_text:
            raise ConfigurationError(f"Intent cache quote mismatch for {request.case_id}.")
        return entry.intent

    def run(
        self,
        case_id: Optional[str] = None,
        sample: bool = False,
        output_file: Optional[Path] = None,
    ) -> tuple[list[OutputRow], AuditRunSummary]:
        """Execute end-to-end pipeline across target cases."""
        start_time = time.perf_counter()
        summary = AuditRunSummary()

        # 1. Load inputs once
        loader = DataLoader(self.settings)
        bundle = loader.load_bundle(sample=sample)

        target_requests: list[DeletionRequest] = []
        if case_id:
            target_requests = [r for r in bundle.requests if r.case_id == case_id]
            if not target_requests:
                raise ValueError(f"Target case '{case_id}' not found in loaded requests.")
        else:
            target_requests = list(bundle.requests)

        summary.total_cases = len(target_requests)

        # 2. Build identity service once
        identity_svc = IdentityResolutionService.from_data(
            identities=bundle.identities,
            audit_logs=bundle.audit_logs,
        )

        # 3. Ingest evidence corpus once
        ingestion_service = EvidenceIngestionService(self.settings)
        ingestion_summary = ingestion_service.ingest_manifest(
            dataset_dir=self.settings.dataset_dir,
            mode=self.mode,
        )
        all_observations = []
        for fr in ingestion_summary.file_results:
            all_observations.extend(fr.observations)

        # 4. Build global corpus index once
        corpus_index = CorpusIndex(
            observations=all_observations,
            activity_events=bundle.activity_events,
        )

        # 5. Initialize shared services
        failed_files = [fr.file_id for fr in ingestion_summary.file_results if getattr(fr.status, "value", str(fr.status)) == "FAILED"]
        deferred_files = [fr.file_id for fr in ingestion_summary.file_results if getattr(fr.status, "value", str(fr.status)) == "DEFERRED"]
        manifest_errors = [str(err) for err in ingestion_summary.manifest_errors]

        retrieval_service = EvidenceRetrievalService(
            index=corpus_index,
            identity_service=identity_svc,
            intent_service=self.intent_service,
            failed_files=failed_files,
            deferred_files=deferred_files,
            manifest_errors=manifest_errors,
        )
        policy_engine = PolicyDecisionEngine.from_rules_file(self.settings.deletion_rules_path)
        planner = AuditPlanGenerator()

        # 6. Process each case
        output_rows: list[OutputRow] = []

        for req in target_requests:
            # Check precomputed intent
            cached_entry = self.precomputed_intents.get(req.case_id)
            precomputed = self._validated_cached_intent(cached_entry, req) if cached_entry else None

            # Retrieve evidence packet
            packet = retrieval_service.retrieve_for_case(
                case=req,
                diagnostic_mode=self.diagnostic,
                precomputed_intent=precomputed,
            )

            # Reconstruct resource state
            state_engine = ResourceStateEngine(audit_at=req.audit_at)
            recon = state_engine.reconstruct_case_state(packet)

            # Evaluate policy
            policy_assessment = policy_engine.assess_case(
                recon=recon,
                packet=packet,
                request=req,
                diagnostic=self.diagnostic,
            )

            # Generate audit plan
            plan = planner.generate_plan(
                assessment=policy_assessment,
                recon=recon,
                packet=packet,
            )

            if plan.is_unresolved:
                summary.unresolved_cases += 1
                summary.unresolved_details[req.case_id] = plan.unresolved_reasons
            else:
                if plan.status == DeletionStatus.COMPLETE:
                    summary.complete_cases += 1
                elif plan.status == DeletionStatus.INCOMPLETE:
                    summary.incomplete_cases += 1
                elif plan.status == DeletionStatus.NOT_APPLICABLE:
                    summary.not_applicable_cases += 1
                output_rows.append(plan.to_output_row())

            if policy_assessment.diagnostic_bypass:
                summary.diagnostic_bypass_count += 1

        # Sort lexicographically by case_id
        output_rows.sort(key=lambda r: r.case_id)

        # Validate whole run
        selected_ids = [request.case_id for request in target_requests]
        row_ids = [row.case_id for row in output_rows]
        selected_run_complete = (
            summary.unresolved_cases == 0
            and summary.diagnostic_bypass_count == 0
            and not bundle.errors
            and len(row_ids) == len(set(row_ids))
            and set(row_ids) == set(selected_ids)
            and row_ids == sorted(row_ids)
        )
        is_full_evaluation = not sample and case_id is None
        is_submittable = selected_run_complete and is_full_evaluation and not self.diagnostic
        summary.is_valid_for_submission = is_submittable
        summary.execution_time_ms = (time.perf_counter() - start_time) * 1000

        # Record usage summary if gateway was called
        if self.live and self.usage_tracker.records:
            summary.usage_summary = self.usage_tracker.summary()

        # 7. Write output safely if requested
        if output_file:
            self._write_output_csv_atomically(
                output_rows=output_rows,
                output_path=Path(output_file),
                is_submittable=is_submittable,
                selected_run_complete=selected_run_complete,
                expected_case_ids=set(selected_ids),
                diagnostic=self.diagnostic,
            )
            summary.output_path = str(output_file)

        return output_rows, summary

    def _write_output_csv_atomically(
        self,
        output_rows: list[OutputRow],
        output_path: Path,
        is_submittable: bool,
        selected_run_complete: bool,
        expected_case_ids: set[str],
        diagnostic: bool,
    ) -> None:
        """Validate coverage and atomically replace only an eligible output artifact."""
        output_path = output_path.resolve()
        is_root_submission = (output_path == (REPO_ROOT / "output.csv").resolve())

        if is_root_submission and not is_submittable:
            raise RuntimeError(
                f"Cannot overwrite submission file {output_path}: only a complete, non-diagnostic "
                "518-case evaluation run is eligible."
            )

        if diagnostic:
            artifacts_root = (REPO_ROOT / "artifacts").resolve()
            try:
                output_path.relative_to(artifacts_root)
            except ValueError as exc:
                raise RuntimeError("Diagnostic CSVs must be written under the repository artifacts directory.") from exc
            if "diagnostic" not in output_path.stem.lower():
                raise RuntimeError("Diagnostic CSV filenames must contain the label 'diagnostic'.")
        elif not selected_run_complete:
            raise RuntimeError("Cannot export an unresolved, failed, or incomplete-coverage run.")

        row_ids = [row.case_id for row in output_rows]
        if len(row_ids) != len(set(row_ids)):
            raise ValueError("Output contains duplicate case IDs.")
        if not diagnostic and set(row_ids) != expected_case_ids:
            missing = sorted(expected_case_ids - set(row_ids))
            extra = sorted(set(row_ids) - expected_case_ids)
            raise ValueError(f"Output case coverage mismatch; missing={missing}, extra={extra}.")
        if row_ids != sorted(row_ids):
            raise ValueError("Output rows must be sorted lexicographically by case_id.")

        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Validate every row before writing
        for row in output_rows:
            validation_errors = row.validate_row()
            if validation_errors:
                raise ValueError(f"Output row {row.case_id} failed validation: {'; '.join(validation_errors)}")

        # Write to temporary file in same directory for atomic replace
        temp_file = tempfile.NamedTemporaryFile(
            mode="w",
            newline="",
            encoding="utf-8",
            dir=str(output_path.parent),
            delete=False,
        )
        temp_path = Path(temp_file.name)
        try:
            writer = csv.writer(temp_file)
            writer.writerow(["case_id", "deletion_status", "steps_json"])
            for row in output_rows:
                writer.writerow(row.to_csv_record())
            temp_file.flush()
            temp_file.close()

            # Atomically replace destination
            os.replace(temp_path, output_path)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise
