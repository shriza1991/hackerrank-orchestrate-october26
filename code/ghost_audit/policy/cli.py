"""CLI handler and formatting utilities for evidence-grounded policy assessment."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

from ghost_audit.config import get_settings
from ghost_audit.evidence.service import EvidenceIngestionService
from ghost_audit.identity.service import IdentityResolutionService
from ghost_audit.loader import DataLoader
from ghost_audit.models.intermediate_models import EvidenceObservation
from ghost_audit.policy.models import CasePolicyAssessment
from ghost_audit.policy.service import PolicyDecisionEngine
from ghost_audit.retrieval.index import CorpusIndex
from ghost_audit.retrieval.service import EvidenceRetrievalService
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


def format_policy_assessment_text(assessment: CasePolicyAssessment) -> str:
    """Format a CasePolicyAssessment into a human-readable diagnostic report."""
    lines = [
        "=" * 76,
        "EVIDENCE-GROUNDED POLICY DECISION ENGINE REPORT",
        "=" * 76,
        f"Case ID                 : {assessment.case_id}",
        f"Audit Cutoff (audit_at) : {format_iso_timestamp(assessment.audit_at)}",
        f"Intent Status           : {assessment.intent_status}",
        f"Diagnostic Bypass       : {assessment.diagnostic_bypass}",
        f"Is Blocked              : {assessment.is_blocked}",
    ]
    if assessment.blocking_reason:
        lines.append(f"Blocking Reason         : {assessment.blocking_reason}")

    lines.append(f"Overall Compliance      : {assessment.overall_compliance.value}")
    lines.append("-" * 76)

    lines.append(f"EVALUATED RESOURCES ({len(assessment.resources)}):")
    if assessment.resources:
        for canon_key, r_ast in sorted(assessment.resources.items()):
            cat_str = r_ast.data_category.value if r_ast.data_category else "UNRESOLVED"
            lines.append(
                f"  * [{r_ast.canonical_key}] category={cat_str} rule={r_ast.rule_id or 'none'} "
                f"action={r_ast.required_action.value if r_ast.required_action else 'none'} "
                f"outcome={r_ast.outcome.value}"
            )
            lines.append(f"    - Category Basis    : {r_ast.category_basis}")
            lines.append(f"    - Condition Premise : {r_ast.condition_evaluation.value} ({r_ast.condition_details})")
            if r_ast.recreation_risk:
                lines.append(f"    ! RECREATION RISK   : {r_ast.recreation_risk}")
            if r_ast.restore_risk:
                lines.append(f"    ! RESTORE RISK      : {r_ast.restore_risk}")
            if r_ast.conflicts:
                lines.append(f"    ! CONFLICTS         : {'; '.join(r_ast.conflicts)}")
            if r_ast.missing_facts:
                lines.append(f"    ? Missing Facts     : {'; '.join(r_ast.missing_facts)}")

            for c_str, c_ast in sorted(r_ast.copies.items()):
                lines.append(
                    f"      + Copy: {c_str} -> existence={c_ast.observed_existence.value} "
                    f"pii_exposed={c_ast.observed_pii_exposed} outcome={c_ast.outcome.value}"
                )
                if c_ast.pii_details:
                    lines.append(f"        pii_details: {', '.join(c_ast.pii_details)}")
                if c_ast.retention_obligation:
                    lines.append(f"        retention: {c_ast.retention_obligation}")
                if c_ast.target_properties:
                    t_str = ", ".join(f"{k}={v}" for k, v in c_ast.target_properties.items())
                    lines.append(f"        target_properties: {t_str}")
    else:
        lines.append("  (no resources evaluated)")

    lines.append("-" * 76)
    lines.append(f"PROCESS RISKS ({len(assessment.process_risks)}):")
    if assessment.process_risks:
        for pr in assessment.process_risks:
            lines.append(f"  * [{pr.process_id}] {pr.risk_type} active={pr.is_active}: {pr.details}")
    else:
        lines.append("  (none)")

    lines.append("-" * 76)
    lines.append(f"RESTORE RISKS ({len(assessment.restore_risks)}):")
    if assessment.restore_risks:
        for rr in assessment.restore_risks:
            lines.append(f"  * [{rr.backup_id}] {rr.risk_type} blocked={rr.is_blocked}: {rr.details}")
    else:
        lines.append("  (none)")

    lines.append("-" * 76)
    lines.append("SUMMARY:")
    lines.append(f"  Violations ({len(assessment.violations_summary)}):")
    for v in assessment.violations_summary:
        lines.append(f"    - {v}")
    if not assessment.violations_summary:
        lines.append("    (none)")

    lines.append(f"  Undetermined Items ({len(assessment.unresolved_summary)}):")
    for u in assessment.unresolved_summary:
        lines.append(f"    - {u}")
    if not assessment.unresolved_summary:
        lines.append("    (none)")

    if assessment.coverage_limitations:
        lines.append(f"  Coverage Limitations: {', '.join(assessment.coverage_limitations)}")

    lines.append(f"  Evaluation Time: {assessment.evaluation_time_ms:.1f}ms")
    lines.append("=" * 76)
    return "\n".join(lines)


def run_assess_policy(
    case_id: Optional[str] = None,
    sample: bool = False,
    batch: bool = False,
    diagnostic: bool = False,
    dataset_dir: Optional[Path] = None,
    mode: str = "structured",
    json_output: bool = False,
    artifacts_dir: Optional[Path] = None,
) -> int:
    """Run evidence-grounded policy decision CLI pipeline."""
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
    policy_engine = PolicyDecisionEngine.from_rules_file(settings.deletion_rules_path)

    # Select target requests
    targets = bundle.requests
    if case_id:
        targets = [r for r in bundle.requests if r.case_id == case_id.strip()]
        if not targets:
            print(f"ERROR: Case '{case_id}' not found in loaded requests.", file=sys.stderr)
            return 1
    elif not batch:
        targets = [bundle.requests[0]]

    # Execute pipeline
    packets = retrieval_svc.retrieve_batch(targets, diagnostic_mode=diagnostic)
    reconstructions = reconstruction_svc.reconstruct_batch(packets)
    assessments = policy_engine.assess_batch(reconstructions=reconstructions, packets=packets, diagnostic=diagnostic)

    # Optional artifact writing
    if artifacts_dir:
        artifacts_path = Path(artifacts_dir)
        artifacts_path.mkdir(parents=True, exist_ok=True)
        dump_path = artifacts_path / f"policy_assessment_{'sample' if sample else 'eval'}.json"
        with open(dump_path, "w", encoding="utf-8") as f:
            dump_data = [a.model_dump(mode="json") for a in assessments]
            json.dump(dump_data, f, indent=2, default=_json_serial)

    if json_output:
        if len(assessments) == 1:
            print(json.dumps(assessments[0].model_dump(mode="json"), indent=2, default=_json_serial))
        else:
            print(json.dumps([a.model_dump(mode="json") for a in assessments], indent=2, default=_json_serial))
    else:
        for ast in assessments:
            print(format_policy_assessment_text(ast))
            print()

    return 0
