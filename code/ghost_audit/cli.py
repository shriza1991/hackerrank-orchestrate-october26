"""Inspection CLI for dataset validation and verification."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional

from ghost_audit.config import EXPECTED_COUNTS, Settings, get_settings
from ghost_audit.loader import DataLoader
from ghost_audit.llm.smoke import run_smoke
from ghost_audit.intent.cli import run_intent_classification


def inspect_dataset(
    settings: Settings,
    sample: bool = False,
) -> dict[str, Any]:
    """Execute validation and generate inspection summary dictionary."""
    loader = DataLoader(settings)
    bundle = loader.load_bundle(sample=sample)

    ext_counts = bundle.manifest_result.extension_counts if bundle.manifest_result else {}

    errors = [str(e) for e in bundle.errors]
    warnings = [str(w) for w in bundle.warnings]

    req_expected = EXPECTED_COUNTS["sample_requests"] if sample else EXPECTED_COUNTS["evaluation_requests"]

    summary = {
        "status": "VALID" if bundle.is_valid else "INVALID",
        "dataset_dir": str(settings.dataset_dir),
        "is_sample": sample,
        "counts": {
            "selected_requests": len(bundle.requests),
            "identities": len(bundle.identities),
            "historical_changes": len(bundle.audit_logs),
            "activity_events": len(bundle.activity_events),
            "policy_rules": len(bundle.deletion_rules),
            "evidence_files": len(bundle.manifest_entries),
        },
        "expected_counts": {
            "selected_requests": req_expected,
            "identities": EXPECTED_COUNTS["identities"],
            "historical_changes": EXPECTED_COUNTS["historical_changes"],
            "activity_events": EXPECTED_COUNTS["activity_events"],
            "policy_rules": EXPECTED_COUNTS["policy_rules"],
            "evidence_files": EXPECTED_COUNTS["evidence_files"],
        },
        "counts_match_expected": {
            "selected_requests": len(bundle.requests) == req_expected,
            "identities": len(bundle.identities) == EXPECTED_COUNTS["identities"],
            "historical_changes": len(bundle.audit_logs) == EXPECTED_COUNTS["historical_changes"],
            "activity_events": len(bundle.activity_events) == EXPECTED_COUNTS["activity_events"],
            "policy_rules": len(bundle.deletion_rules) == EXPECTED_COUNTS["policy_rules"],
            "evidence_files": len(bundle.manifest_entries) == EXPECTED_COUNTS["evidence_files"],
        },
        "evidence_format_breakdown": ext_counts,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "errors": errors,
        "warnings": warnings,
    }
    return summary


def format_text_summary(summary: dict[str, Any]) -> str:
    """Format inspection summary for human-readable terminal display."""
    lines = [
        "=" * 68,
        "HACKERRANK ORCHESTRATE -- GHOST DATA STILL EXISTS: DATASET INSPECTION",
        "=" * 68,
        f"Dataset Directory : {summary['dataset_dir']}",
        f"Mode              : {'SAMPLE' if summary['is_sample'] else 'EVALUATION'}",
        f"Overall Status    : {summary['status']}",
        "-" * 68,
        "RECORD COUNTS (Observed / Expected):",
        f"  - Requests           : {summary['counts']['selected_requests']:>5} / {summary['expected_counts']['selected_requests']:>5} "
        f"[{'MATCH' if summary['counts_match_expected']['selected_requests'] else 'MISMATCH'}]",
        f"  - User Identities    : {summary['counts']['identities']:>5} / {summary['expected_counts']['identities']:>5} "
        f"[{'MATCH' if summary['counts_match_expected']['identities'] else 'MISMATCH'}]",
        f"  - Historical Changes : {summary['counts']['historical_changes']:>5} / {summary['expected_counts']['historical_changes']:>5} "
        f"[{'MATCH' if summary['counts_match_expected']['historical_changes'] else 'MISMATCH'}]",
        f"  - Activity Events    : {summary['counts']['activity_events']:>5} / {summary['expected_counts']['activity_events']:>5} "
        f"[{'MATCH' if summary['counts_match_expected']['activity_events'] else 'MISMATCH'}]",
        f"  - Deletion Rules     : {summary['counts']['policy_rules']:>5} / {summary['expected_counts']['policy_rules']:>5} "
        f"[{'MATCH' if summary['counts_match_expected']['policy_rules'] else 'MISMATCH'}]",
        f"  - Evidence Files     : {summary['counts']['evidence_files']:>5} / {summary['expected_counts']['evidence_files']:>5} "
        f"[{'MATCH' if summary['counts_match_expected']['evidence_files'] else 'MISMATCH'}]",
        "-" * 68,
        "EVIDENCE FORMAT BREAKDOWN:",
    ]
    for ext, count in summary["evidence_format_breakdown"].items():
        lines.append(f"  {ext:<10} : {count:>4} files")

    lines.append("-" * 68)
    lines.append(f"Validation Errors   : {summary['error_count']}")
    lines.append(f"Validation Warnings : {summary['warning_count']}")

    if summary["errors"]:
        lines.append("\nERRORS:")
        for err in summary["errors"][:20]:
            lines.append(f"  [!] {err}")
        if len(summary["errors"]) > 20:
            lines.append(f"  ... and {len(summary['errors']) - 20} more errors")

    if summary["warnings"]:
        lines.append("\nWARNINGS:")
        for warn in summary["warnings"][:10]:
            lines.append(f"  [*] {warn}")
        if len(summary["warnings"]) > 10:
            lines.append(f"  ... and {len(summary['warnings']) - 10} more warnings")

    lines.append("=" * 68)
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point for dataset inspection."""
    parser = argparse.ArgumentParser(
        prog="ghost-audit",
        description="Dataset inspection and validation CLI for Ghost Data Still Exists.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="Inspect and validate dataset CSVs and evidence files.")
    inspect_parser.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help="Path to dataset directory (defaults to repository dataset/).",
    )
    inspect_parser.add_argument(
        "--sample",
        action="store_true",
        help="Inspect sample requests instead of evaluation requests.",
    )
    inspect_parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON format.",
    )
    smoke_parser = subparsers.add_parser(
        "model-smoke", help="Check model configuration or run an explicitly authorized synthetic call."
    )
    smoke_parser.add_argument(
        "--live", action="store_true",
        help="Explicitly authorize one potentially paid synthetic model request.",
    )
    smoke_parser.add_argument(
        "--report", action="store_true",
        help="Write development accounting to ignored artifacts/model-smoke-usage.md.",
    )
    intent_parser = subparsers.add_parser(
        "classify-intent", help="Classify one request's deletion authorization intent."
    )
    intent_input = intent_parser.add_mutually_exclusive_group(required=True)
    intent_input.add_argument("--text", help="Request text to classify without loading a dataset.")
    intent_input.add_argument("--case", dest="case_id", help="Case ID to load and classify.")
    intent_parser.add_argument("--sample", action="store_true", help="Resolve --case from sample requests.")
    intent_parser.add_argument("--dataset", type=Path, default=None, help="Dataset directory override.")
    intent_parser.add_argument("--live", action="store_true", help="Authorize one potentially paid model call.")
    intent_parser.add_argument(
        "--report", action="store_true",
        help="Write development accounting to ignored artifacts/intent-classification-usage.md.",
    )

    identity_parser = subparsers.add_parser(
        "resolve-identity", help="Resolve request email to stable user identity and recover identifiers."
    )
    identity_input = identity_parser.add_mutually_exclusive_group(required=True)
    identity_input.add_argument("--case", dest="case_id", help="Case ID to load and resolve.")
    identity_input.add_argument("--email", help="Request email to resolve directly.")
    identity_input.add_argument("--batch", action="store_true", help="Batch resolve all requests in dataset.")

    identity_parser.add_argument("--audit-at", help="Audit cutoff timestamp (ISO-8601). Required with --email.")
    identity_parser.add_argument("--requested-at", help="Request submission timestamp (ISO-8601).")
    identity_parser.add_argument("--sample", action="store_true", help="Resolve from sample requests.")
    identity_parser.add_argument("--dataset", type=Path, default=None, help="Dataset directory override.")
    identity_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON format.")
    identity_parser.add_argument(
        "--report", action="store_true", help="Write batch diagnostic summary to artifacts/."
    )

    # Subcommand: ingest-evidence
    evidence_parser = subparsers.add_parser(
        "ingest-evidence",
        help="Ingest structured evidence files from dataset and extract observations.",
    )
    evidence_parser.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help="Path to dataset directory (defaults to configured dataset_dir).",
    )
    evidence_parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Specific evidence file_id to ingest (e.g. evidence_01).",
    )
    evidence_parser.add_argument(
        "--batch",
        action="store_true",
        default=True,
        help="Batch process all manifest evidence files (default).",
    )
    evidence_parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON summary.",
    )
    evidence_parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=None,
        help="Optional directory to write observation artifacts (e.g. artifacts/).",
    )
    evidence_parser.add_argument(
        "--report",
        action="store_true",
        help="Print detailed per-file status breakdown.",
    )
    evidence_parser.add_argument(
        "--mode",
        choices=["all", "structured", "multimodal"],
        default="all",
        help="Ingestion mode: 'all' (default, all 94 files), 'structured' (79 files), or 'multimodal' (15 files).",
    )
    evidence_parser.add_argument(
        "--live",
        action="store_true",
        help="Authorize optional live vision model calls (default False).",
    )

    # Subcommand: retrieve-evidence
    retrieve_parser = subparsers.add_parser(
        "retrieve-evidence",
        help="Retrieve grounded evidence and system activity for deletion audit cases.",
    )
    retrieve_parser.add_argument(
        "--case",
        "--case-id",
        dest="case_id",
        type=str,
        default=None,
        help="Specific case_id to retrieve (e.g. case_01).",
    )
    retrieve_parser.add_argument(
        "--sample",
        action="store_true",
        help="Target sample deletion requests instead of evaluation set.",
    )
    retrieve_parser.add_argument(
        "--batch",
        action="store_true",
        default=False,
        help="Batch process all requests in target dataset.",
    )
    retrieve_parser.add_argument(
        "--diagnostic",
        action="store_true",
        help="Diagnostic mode: bypass intent classification for debugging.",
    )
    retrieve_parser.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help="Path to dataset directory override.",
    )
    retrieve_parser.add_argument(
        "--mode",
        choices=["all", "structured", "multimodal"],
        default="all",
        help="Ingestion mode (default: 'all').",
    )
    retrieve_parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON packet format.",
    )
    retrieve_parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=None,
        help="Optional directory to write case evidence packet JSON files.",
    )
    retrieve_parser.add_argument(
        "--report",
        action="store_true",
        help="Generate detailed diagnostic evaluation report.",
    )
    # Subcommand: reconstruct-state
    reconstruct_parser = subparsers.add_parser(
        "reconstruct-state",
        help="Reconstruct grounded resource states, visible PII, and process configurations at audit cutoff.",
    )
    reconstruct_parser.add_argument(
        "--case",
        "--case-id",
        dest="case_id",
        type=str,
        default=None,
        help="Specific case_id to reconstruct (e.g. case_01).",
    )
    reconstruct_parser.add_argument(
        "--sample",
        action="store_true",
        help="Target sample deletion requests instead of evaluation set.",
    )
    reconstruct_parser.add_argument(
        "--batch",
        action="store_true",
        default=False,
        help="Batch process all requests in target dataset.",
    )
    reconstruct_parser.add_argument(
        "--diagnostic",
        action="store_true",
        help="Diagnostic mode: bypass intent classification for debugging.",
    )
    reconstruct_parser.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help="Path to dataset directory override.",
    )
    reconstruct_parser.add_argument(
        "--mode",
        choices=["all", "structured", "multimodal"],
        default="structured",
        help="Ingestion mode (default: 'structured').",
    )
    reconstruct_parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON format.",
    )
    reconstruct_parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=None,
        help="Optional directory for ignored artifacts.",
    )

    # assess-policy subcommand
    assess_parser = subparsers.add_parser(
        "assess-policy",
        help="Evaluate reconstructed states against deletion policy rules.",
    )
    assess_parser.add_argument(
        "--case",
        "--case-id",
        dest="case_id",
        type=str,
        default=None,
        help="Target case ID to evaluate (e.g. case_01).",
    )
    assess_parser.add_argument(
        "--sample",
        action="store_true",
        default=False,
        help="Use sample dataset instead of full evaluation dataset.",
    )
    assess_parser.add_argument(
        "--batch",
        action="store_true",
        default=False,
        help="Batch process all requests in target dataset.",
    )
    assess_parser.add_argument(
        "--diagnostic",
        action="store_true",
        help="Diagnostic mode: bypass intent classification for debugging.",
    )
    assess_parser.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help="Path to dataset directory override.",
    )
    assess_parser.add_argument(
        "--mode",
        choices=["all", "structured", "multimodal"],
        default="structured",
        help="Ingestion mode (default: 'structured').",
    )
    assess_parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON format.",
    )
    assess_parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=None,
        help="Optional directory for ignored artifacts.",
    )

    args = parser.parse_args(argv)

    if args.command == "inspect":
        settings = get_settings(args.dataset)
        summary = inspect_dataset(settings, sample=args.sample)

        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(format_text_summary(summary))

        return 0 if summary["status"] == "VALID" else 1

    if args.command == "model-smoke":
        return run_smoke(live=args.live, write_report=args.report)

    if args.command == "classify-intent":
        return run_intent_classification(
            text=args.text, case_id=args.case_id, sample=args.sample, dataset=args.dataset,
            live=args.live, write_report=args.report,
        )

    if args.command == "resolve-identity":
        from ghost_audit.identity.cli import run_identity_resolution

        return run_identity_resolution(
            case_id=args.case_id,
            email=args.email,
            audit_at=args.audit_at,
            requested_at=args.requested_at,
            sample=args.sample,
            batch=args.batch,
            dataset=args.dataset,
            json_output=args.json,
            write_report=args.report,
        )

    if args.command == "ingest-evidence":
        from ghost_audit.evidence.cli import run_evidence_ingestion

        return run_evidence_ingestion(
            dataset_dir=args.dataset,
            file_id=args.file,
            mode=args.mode,
            live=args.live,
            as_json=args.json,
            artifacts_dir=args.artifacts_dir,
            detailed_report=args.report,
        )

    if args.command == "retrieve-evidence":
        from ghost_audit.retrieval.cli import run_evidence_retrieval

        return run_evidence_retrieval(
            case_id=args.case_id,
            sample=args.sample,
            batch=args.batch,
            diagnostic=args.diagnostic,
            dataset_dir=args.dataset,
            mode=args.mode,
            json_output=args.json,
            artifacts_dir=args.artifacts_dir,
            write_report=getattr(args, "report", False),
        )

    if args.command == "reconstruct-state":
        from ghost_audit.state.cli import run_reconstruct_state

        return run_reconstruct_state(
            case_id=args.case_id,
            sample=args.sample,
            batch=args.batch,
            diagnostic=args.diagnostic,
            dataset_dir=args.dataset,
            mode=args.mode,
            json_output=args.json,
            artifacts_dir=args.artifacts_dir,
        )

    if args.command == "assess-policy":
        from ghost_audit.policy.cli import run_assess_policy

        return run_assess_policy(
            case_id=args.case_id,
            sample=args.sample,
            batch=args.batch,
            diagnostic=args.diagnostic,
            dataset_dir=args.dataset,
            mode=args.mode,
            json_output=args.json,
            artifacts_dir=args.artifacts_dir,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
