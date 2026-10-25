"""CLI handler and formatting utilities for resource-state reconstruction."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional

from ghost_audit.config import get_settings
from ghost_audit.evidence.service import EvidenceIngestionService
from ghost_audit.identity.service import IdentityResolutionService
from ghost_audit.loader import DataLoader
from ghost_audit.models.intermediate_models import EvidenceObservation
from ghost_audit.retrieval.index import CorpusIndex
from ghost_audit.retrieval.service import EvidenceRetrievalService
from ghost_audit.state.models import CaseStateReconstruction
from ghost_audit.state.service import ResourceStateReconstructionService
from ghost_audit.timestamps import format_iso_timestamp


def _json_serial(obj: Any) -> Any:
    """JSON serializer helper for datetime and Pydantic models."""
    if hasattr(obj, "isoformat"):
        return format_iso_timestamp(obj)
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    raise TypeError(f"Type {type(obj)} not serializable")


def format_reconstruction_text(recon: CaseStateReconstruction) -> str:
    """Format a CaseStateReconstruction into a human-readable diagnostic report."""
    lines = [
        "=" * 72,
        "RESOURCE-STATE RECONSTRUCTION REPORT",
        "=" * 72,
        f"Case ID                 : {recon.case_id}",
        f"Audit Cutoff (audit_at) : {format_iso_timestamp(recon.audit_at)}",
        f"Subject Reference       : {recon.subject_id or 'None'}",
        f"Diagnostic Mode         : {recon.is_diagnostic_mode}",
        f"Is Blocked              : {recon.is_blocked}",
    ]
    if recon.blocking_reason:
        lines.append(f"Blocking Reason         : {recon.blocking_reason}")

    lines.append("-" * 72)
    lines.append(f"RECONSTRUCTED RESOURCES ({len(recon.resources)}):")
    if recon.resources:
        for canon_key, agg in sorted(recon.resources.items()):
            lines.append(f"  * [{agg.canonical_key}] category={agg.data_category} aggregate_existence={agg.aggregate_existence.value}")
            lines.append(f"    - PII Exposed: {agg.observed_pii_exposed} | Recreation Risk: {agg.has_recreation_risk}")
            lines.append(f"    - Surviving Copies ({len(agg.surviving_copies)}): {', '.join(agg.surviving_copies) or 'none'}")
            lines.append(f"    - Absent Copies ({len(agg.absent_copies)}): {', '.join(agg.absent_copies) or 'none'}")
            for c_str, copy_ast in sorted(agg.copies.items()):
                lines.append(f"      + Copy: {c_str} -> existence={copy_ast.existence.value} attr={copy_ast.attribution.value}")
                if copy_ast.is_recreated:
                    lines.append(f"        ! RECREATION DETECTED: {copy_ast.recreation_details}")
                if copy_ast.fields:
                    field_strs = [f"{k}={f.raw_value or f.status.value}" for k, f in copy_ast.fields.items()]
                    lines.append(f"        fields: {', '.join(field_strs)}")
                if copy_ast.unverified_claims:
                    lines.append(f"        unverified_claims: {'; '.join(copy_ast.unverified_claims)}")
                if copy_ast.conflicts:
                    for cf in copy_ast.conflicts:
                        lines.append(f"        CONFLICT: {cf}")
    else:
        lines.append("  (none established)")

    lines.append("-" * 72)
    lines.append(f"ACTIVE PROCESSES / RESTORE RISKS:")
    lines.append(f"  - Active Processes : {', '.join(recon.active_processes) or 'none observed'}")
    lines.append(f"  - Restore Risks    : {', '.join(recon.restore_risks) or 'none observed'}")

    lines.append("-" * 72)
    lines.append(f"SCOPED ABSENCE CHECKS ({len(recon.scoped_absence_checks)}):")
    if recon.scoped_absence_checks:
        for sc in recon.scoped_absence_checks:
            lines.append(f"  [{sc.source_id}] {sc.system_id} @ {sc.table_scope} -> {sc.membership_result} ({sc.completeness_basis})")
    else:
        lines.append("  (none)")

    lines.append("-" * 72)
    lines.append("DIAGNOSTICS:")
    lines.append(f"  Coverage Scope             : {recon.diagnostics.coverage_scope}")
    lines.append(f"  Resources Evaluated        : {recon.diagnostics.total_resources_evaluated}")
    lines.append(f"  Copies Evaluated           : {recon.diagnostics.total_copies_evaluated}")
    lines.append(f"  Conflicts Detected         : {len(recon.diagnostics.conflicts_detected)}")
    lines.append(f"  Recreations Detected       : {len(recon.diagnostics.recreations_detected)}")
    lines.append(f"  Unverified Claims Count    : {recon.diagnostics.unverified_claims_count}")
    lines.append(f"  Execution Time             : {recon.diagnostics.execution_time_ms:.1f}ms")
    lines.append("=" * 72)

    return "\n".join(lines)


def run_reconstruct_state(
    case_id: Optional[str] = None,
    sample: bool = False,
    batch: bool = False,
    diagnostic: bool = False,
    dataset_dir: Optional[Path] = None,
    mode: str = "structured",
    json_output: bool = False,
    artifacts_dir: Optional[Path] = None,
) -> int:
    """Run resource-state reconstruction CLI pipeline."""
    settings = get_settings(dataset_dir)
    loader = DataLoader(settings)
    bundle = loader.load_bundle(sample=sample)

    if not bundle.requests:
        print("ERROR: No deletion requests loaded from dataset.", file=sys.stderr)
        return 1

    # Ingest evidence
    ingestion_svc = EvidenceIngestionService(settings)
    summary = ingestion_svc.ingest_manifest(dataset_dir=settings.dataset_dir, mode=mode)
    all_observations: list[EvidenceObservation] = []
    for fr in summary.file_results:
        all_observations.extend(fr.observations)

    failed_files = [fr.file_id for fr in summary.file_results if getattr(fr.status, "value", str(fr.status)) == "FAILED"]
    deferred_files = [fr.file_id for fr in summary.file_results if getattr(fr.status, "value", str(fr.status)) == "DEFERRED"]
    manifest_errors = [str(err) for err in summary.manifest_errors]

    # Build corpus index and services
    corpus_index = CorpusIndex(
        observations=all_observations,
        activity_events=bundle.activity_events,
    )
    identity_svc = IdentityResolutionService.from_data(
        identities=bundle.identities,
        audit_logs=bundle.audit_logs,
    )

    retrieval_svc = EvidenceRetrievalService(
        index=corpus_index,
        identity_service=identity_svc,
        intent_service=None,
        failed_files=failed_files,
        deferred_files=deferred_files,
        manifest_errors=manifest_errors,
    )

    reconstruction_svc = ResourceStateReconstructionService()

    # Select target requests
    targets = bundle.requests
    if case_id:
        targets = [r for r in bundle.requests if r.case_id == case_id.strip()]
        if not targets:
            print(f"ERROR: Case '{case_id}' not found in loaded requests.", file=sys.stderr)
            return 1
    elif not batch:
        targets = [bundle.requests[0]]

    # Execute retrieval and state reconstruction
    packets = retrieval_svc.retrieve_batch(targets, diagnostic_mode=diagnostic)
    reconstructions = reconstruction_svc.reconstruct_batch(packets)

    if json_output:
        if len(reconstructions) == 1:
            print(json.dumps(reconstructions[0].model_dump(mode="json"), indent=2, default=_json_serial))
        else:
            print(json.dumps([r.model_dump(mode="json") for r in reconstructions], indent=2, default=_json_serial))
    else:
        for recon in reconstructions:
            print(format_reconstruction_text(recon))
            print()

    return 0
