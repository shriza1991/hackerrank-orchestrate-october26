"""CLI handler and formatting utilities for evidence linking and retrieval."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional

from ghost_audit.config import Settings, get_settings
from ghost_audit.evidence.service import EvidenceIngestionService
from ghost_audit.identity.service import IdentityResolutionService
from ghost_audit.intent.service import IntentClassificationService
from ghost_audit.loader import DataLoader
from ghost_audit.models.intermediate_models import EvidenceObservation
from ghost_audit.retrieval.index import CorpusIndex
from ghost_audit.retrieval.models import CaseEvidencePacket
from ghost_audit.retrieval.service import EvidenceRetrievalService
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


def format_packet_text(packet: CaseEvidencePacket) -> str:
    """Format a CaseEvidencePacket into a human-readable diagnostic report."""
    lines = [
        "=" * 72,
        "CASE EVIDENCE RETRIEVAL PACKET",
        "=" * 72,
        f"Case ID                 : {packet.case_id}",
        f"Email                   : {packet.email}",
        f"Requested At            : {format_iso_timestamp(packet.requested_at)}",
        f"Reported Status / At    : {packet.reported_status} @ {format_iso_timestamp(packet.reported_at)}",
        f"Audit Cutoff (audit_at) : {format_iso_timestamp(packet.audit_at)}",
        f"Intent Decision         : {packet.intent_decision or 'None'}",
        f"Identity Resolution     : {packet.identity_status.value} (Subject: {packet.stable_subject_reference or 'None'})",
        f"Is Blocked              : {packet.is_blocked}",
    ]
    if packet.blocking_reason:
        lines.append(f"Blocking Reason         : {packet.blocking_reason}")

    lines.append("-" * 72)
    lines.append(f"SUBJECT IDENTIFIERS ({len(packet.subject_identifiers)}):")
    if packet.subject_identifiers:
        for ident in packet.subject_identifiers:
            lines.append(f"  - {ident}")
    else:
        lines.append("  (none established)")

    lines.append("-" * 72)
    lines.append(f"GROUNDED RESOURCES ({len(packet.grounded_resources)}):")
    if packet.grounded_resources:
        for res in packet.grounded_resources:
            lines.append(f"  - {res}")
    else:
        lines.append("  (none grounded)")

    lines.append("-" * 72)
    lines.append(f"SELECTED OBSERVATIONS ({len(packet.selected_observations)}):")
    if packet.selected_observations:
        for so in packet.selected_observations:
            obs = so.observation
            loc_str = f" @ {obs.source_locator}" if obs.source_locator else ""
            res_str = f" (resource: {obs.resource_id})" if obs.resource_id else ""
            lines.append(f"  [{obs.evidence_id}{loc_str}] sys={obs.system_id}{res_str} rel={so.primary_relationship.value}")
    else:
        lines.append("  (none selected)")

    lines.append("-" * 72)
    lines.append(f"SELECTED SYSTEM ACTIVITY ({len(packet.selected_activities)}):")
    if packet.selected_activities:
        for sa in packet.selected_activities:
            lines.append(f"  [{sa.activity_id}] {format_iso_timestamp(sa.event_time)} {sa.event_type} target={sa.target_system} res={sa.resource_id} claim={sa.reported_result}")
    else:
        lines.append("  (none selected)")

    lines.append("-" * 72)
    lines.append(f"SCOPED INVENTORIES ({len(packet.scoped_inventories)}):")
    if packet.scoped_inventories:
        for si in packet.scoped_inventories:
            loc_str = f" @ {si.source_locator}" if si.source_locator else ""
            lines.append(f"  [{si.source_id}{loc_str}] system={si.system_id} time={format_iso_timestamp(si.timestamp)}")
    else:
        lines.append("  (none)")

    lines.append("-" * 72)
    lines.append(f"EVIDENCE LINKS ({len(packet.linking_graph)}):")
    if packet.linking_graph:
        for link in packet.linking_graph:
            lines.append(f"  {link.link_id}: {link.from_endpoint} -> {link.to_endpoint} ({link.provenance.relationship.value}) [{link.provenance.source_id}]")
    else:
        lines.append("  (none)")

    if packet.ambiguous_or_rejected_links:
        lines.append("-" * 72)
        lines.append(f"REJECTED / AMBIGUOUS LINKS ({len(packet.ambiguous_or_rejected_links)}):")
        for rej in packet.ambiguous_or_rejected_links:
            lines.append(f"  - {rej.candidate_endpoint} [{rej.source_id}]: {rej.reason}")

    lines.append("-" * 72)
    lines.append("DIAGNOSTICS:")
    lines.append(f"  Eligible Observations Scanned : {packet.diagnostics.total_eligible_observations_scanned}")
    lines.append(f"  Future Observations Excluded  : {packet.diagnostics.total_future_observations_excluded}")
    lines.append(f"  Eligible Activities Scanned   : {packet.diagnostics.total_eligible_activities_scanned}")
    lines.append(f"  Future Activities Excluded    : {packet.diagnostics.total_future_activities_excluded}")
    lines.append(f"  Max Expansion Depth Reached   : {packet.diagnostics.max_expansion_depth_reached}")
    if packet.diagnostics.cycles_detected:
        lines.append(f"  Cycles Detected               : {', '.join(packet.diagnostics.cycles_detected)}")
    if packet.diagnostics.coverage_warnings:
        for w in packet.diagnostics.coverage_warnings:
            lines.append(f"  Warning                       : {w}")
    lines.append(f"  Execution Time                : {packet.diagnostics.execution_time_ms:.1f}ms")
    lines.append("=" * 72)

    return "\n".join(lines)


def run_evidence_retrieval(
    case_id: Optional[str] = None,
    sample: bool = False,
    batch: bool = False,
    diagnostic: bool = False,
    dataset_dir: Optional[Path] = None,
    mode: str = "all",
    json_output: bool = False,
    artifacts_dir: Optional[Path] = None,
    write_report: bool = False,
) -> int:
    """Run evidence retrieval CLI pipeline."""
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

    # Build corpus index and services
    corpus_index = CorpusIndex(
        observations=all_observations,
        activity_events=bundle.activity_events,
    )
    identity_svc = IdentityResolutionService.from_data(
        identities=bundle.identities,
        audit_logs=bundle.audit_logs,
    )

    intent_svc: Optional[IntentClassificationService] = None
    if not diagnostic:
        intent_svc = IntentClassificationService()

    retrieval_svc = EvidenceRetrievalService(
        index=corpus_index,
        identity_service=identity_svc,
        intent_service=intent_svc,
    )

    # Select target requests
    targets = bundle.requests
    if case_id:
        targets = [r for r in bundle.requests if r.case_id == case_id.strip()]
        if not targets:
            print(f"ERROR: Case '{case_id}' not found in loaded requests.", file=sys.stderr)
            return 1

    packets = retrieval_svc.retrieve_batch(targets, diagnostic_mode=diagnostic)

    # Optional artifacts export
    if artifacts_dir:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        for pkt in packets:
            art_file = artifacts_dir / f"{pkt.case_id}_evidence_packet.json"
            art_file.write_text(pkt.model_dump_json(indent=2), encoding="utf-8")

    # Output
    if json_output:
        if len(packets) == 1:
            print(packets[0].model_dump_json(indent=2))
        else:
            payload = [p.model_dump(mode="json") for p in packets]
            print(json.dumps(payload, indent=2, default=_json_serial))
    else:
        for pkt in packets:
            print(format_packet_text(pkt))
            print()

    return 0
