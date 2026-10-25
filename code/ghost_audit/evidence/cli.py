"""CLI command handler for evidence ingestion."""

import json
import sys
from pathlib import Path
from typing import Any, Optional

from ghost_audit.config import get_settings
from ghost_audit.evidence.models import EvidenceIngestionSummary
from ghost_audit.evidence.service import EvidenceIngestionService


def run_evidence_ingestion(
    dataset_dir: Optional[Path] = None,
    file_id: Optional[str] = None,
    as_json: bool = False,
    artifacts_dir: Optional[Path] = None,
    detailed_report: bool = False,
) -> int:
    """Execute evidence ingestion across manifest or single file and display results."""
    settings = get_settings(dataset_dir)
    target_dataset_dir = settings.dataset_dir

    service = EvidenceIngestionService(settings)

    try:
        summary = service.ingest_manifest(
            dataset_dir=target_dataset_dir,
            file_id_filter=file_id,
        )
    except Exception as e:
        if as_json:
            print(json.dumps({"error": str(e), "status": "FAILED"}, indent=2))
        else:
            print(f"Error during evidence ingestion: {e}", file=sys.stderr)
        return 1

    # Optionally write artifacts to artifacts-dir
    if artifacts_dir:
        artifacts_dir = Path(artifacts_dir)
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        # 1. Summary JSON
        summary_path = artifacts_dir / "evidence_ingestion_summary.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary.model_dump(mode="json"), f, indent=2)

        # 2. Observations JSONL
        obs_path = artifacts_dir / "evidence_observations.jsonl"
        with open(obs_path, "w", encoding="utf-8") as f:
            for file_res in summary.file_results:
                for obs in file_res.observations:
                    f.write(json.dumps(obs.model_dump(mode="json")) + "\n")

    if as_json:
        # Machine-readable output
        payload = summary.model_dump(mode="json")
        print(json.dumps(payload, indent=2))
        return 0 if summary.failed_count == 0 else 1

    # Human-readable summary output
    print("=" * 60)
    print("GHOST AUDIT - STRUCTURED EVIDENCE INGESTION SUMMARY")
    print("=" * 60)
    print(f"Dataset directory : {target_dataset_dir}")
    print(f"Total manifest files : {summary.manifest_file_count}")
    print(f"Fully parsed files   : {summary.parsed_count}")
    print(f"Partial files        : {summary.partial_count}")
    print(f"Deferred files (T7)  : {summary.deferred_count} (PDF/image multimodal)")
    print(f"Failed files         : {summary.failed_count}")
    print(f"Total observations   : {summary.total_observations}")
    print("-" * 60)
    print("FORMAT BREAKDOWN:")
    for fmt, counts in sorted(summary.by_format.items()):
        obs_c = counts.get("observations", 0)
        p_c = counts.get("parsed", 0)
        part_c = counts.get("partial", 0)
        def_c = counts.get("deferred", 0)
        f_c = counts.get("failed", 0)
        status_detail = f"{p_c} parsed, {part_c} partial, {def_c} deferred, {f_c} failed"
        print(f"  .{fmt:<6} : {obs_c:>5} observations ({status_detail})")

    if detailed_report or summary.failed_count > 0 or summary.partial_count > 0:
        print("-" * 60)
        print("FILE STATUS DETAILS:")
        for r in summary.file_results:
            if r.status.value == "FAILED" or r.warnings or detailed_report:
                warn_str = f" [Warnings: {len(r.warnings)}]" if r.warnings else ""
                err_str = f" [Errors: {len(r.errors)}]" if r.errors else ""
                print(f"  {r.file_id:<12} {r.format:<5} {r.status.value:<8} obs={r.observation_count:<5} {r.file_path}{warn_str}{err_str}")

    print("=" * 60)
    return 0 if summary.failed_count == 0 else 1
