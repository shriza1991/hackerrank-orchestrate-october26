"""Command-line evaluator for Ghost Data Still Exists predictions.

Exit 0 means evaluation completed and predictions passed contract/coverage
checks, even when accuracy is below 100%. Exit 1 means prediction contract or
coverage failed. Exit 2 means an input (especially the reference) is unusable.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = CODE_ROOT.parent
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from evaluation.evaluator import EvaluationInputError, evaluate_files
from evaluation.report import write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare deletion-audit predictions with reference answers.")
    parser.add_argument("--predictions", type=Path, required=True, help="Prediction output CSV (required).")
    parser.add_argument("--reference", type=Path, default=REPO_ROOT / "dataset" / "sample_output.csv")
    parser.add_argument("--requests", type=Path, default=REPO_ROOT / "dataset" / "sample_deletion_requests.csv")
    parser.add_argument("--report", type=Path, help="Write detailed Markdown diagnostics to this path.")
    parser.add_argument("--json", action="store_true", dest="machine_readable", help="Print machine-readable JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = evaluate_files(args.predictions, args.reference, args.requests)
    except EvaluationInputError as exc:
        print(f"Evaluation error: {exc}", file=sys.stderr)
        return 2
    if args.report:
        write_report(result, args.report)
    if args.machine_readable:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        metrics, coverage = result.metrics, result.coverage
        print(f"Cases: {coverage.supplied} supplied / {coverage.expected} expected")
        print(f"Status accuracy: {metrics.status_accuracy:.2%}")
        print(f"Exact-row accuracy: {metrics.exact_row_accuracy:.2%}")
        print(f"Step P/R/F1: {metrics.step_precision:.2%} / {metrics.step_recall:.2%} / {metrics.step_f1:.2%}")
        print(f"Step-field accuracy: {metrics.step_field_accuracy:.2%}")
        print(f"Sequence accuracy: {metrics.sequence_accuracy:.2%}")
        print(f"Contract and coverage valid: {result.prediction_contract_valid}")
        if args.report:
            print(f"Detailed report: {args.report.resolve()}")
    return 0 if result.prediction_contract_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
