"""Inspection CLI for dataset validation and verification."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional

from ghost_audit.config import EXPECTED_COUNTS, Settings, get_settings
from ghost_audit.loader import DataLoader


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

    args = parser.parse_args(argv)

    if args.command == "inspect":
        settings = get_settings(args.dataset)
        summary = inspect_dataset(settings, sample=args.sample)

        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(format_text_summary(summary))

        return 0 if summary["status"] == "VALID" else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
