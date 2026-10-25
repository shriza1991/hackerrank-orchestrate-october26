"""Markdown rendering for evaluation results."""

from pathlib import Path

from evaluation.evaluator import EvaluationResult
from evaluation.fixtures import TEAM_CASES


def render_report(result: EvaluationResult) -> str:
    m, c = result.metrics, result.coverage
    lines = [
        "# Deletion-Audit Evaluation Report", "", "## Scope", "",
        f"- Predictions: `{Path(result.prediction_path).name}`",
        f"- Reference: `{Path(result.reference_path).name}`",
        f"- Requests: `{Path(result.requests_path).name}`", "",
        "This report measures the supplied prediction file. It does not estimate hidden full-dataset accuracy.", "",
        "## Metric definitions", "",
        "- **Case-status accuracy:** strict status matches divided by all expected cases; missing, unreadable, or duplicate predictions get no credit.",
        "- **Exact-row accuracy:** status and the full ordered raw steps array match, and the predicted row satisfies the output contract.",
        "- **Step precision/recall/F1:** micro-aggregated one-to-one multiset matching of the six non-`step_no` fields. Both global sides empty is perfect; no predictions against expected steps scores zero precision and recall; no expected steps gives recall 1.",
        "- **Step-field accuracy:** positional, order-sensitive comparison of all seven fields. Missing or extra steps add seven incorrect comparisons. Equality is type-aware.",
        "- **Sequence accuracy:** fraction of expected cases whose complete raw steps arrays match in order, including numbering and values.",
        "- **Contract/coverage:** evaluated over all expected cases; missing or invalid cases are never dropped by intersection-only scoring.", "",
        "## Measured values", "", "| Metric | Value |", "| --- | ---: |",
        f"| Case-status accuracy | {m.status_correct}/{m.expected_cases} ({m.status_accuracy:.2%}) |",
        f"| Exact-row accuracy | {m.exact_rows_correct}/{m.expected_cases} ({m.exact_row_accuracy:.2%}) |",
        f"| Step precision | {m.step_precision:.2%} |", f"| Step recall | {m.step_recall:.2%} |",
        f"| Step F1 | {m.step_f1:.2%} |",
        f"| Step-field accuracy | {m.correct_step_fields}/{m.compared_step_fields} ({m.step_field_accuracy:.2%}) |",
        f"| Sequence accuracy | {m.sequences_correct}/{m.expected_cases} ({m.sequence_accuracy:.2%}) |", "",
        "## Coverage and contract", "", f"- Expected IDs: {c.expected}; supplied unique IDs: {c.supplied}",
        f"- Missing: {c.missing_case_ids or 'none'}", f"- Extra: {c.extra_case_ids or 'none'}",
        f"- Duplicates: {c.duplicate_case_ids or 'none'}",
        f"- Contract-valid expected cases: {c.contract_valid_cases}/{c.expected} ({c.contract_valid_rate:.2%})",
        f"- Sorted output: {c.sorted_output_valid}",
        f"- Malformed JSON rows: {c.json_error_count}; other schema-invalid rows: {c.schema_error_count}", "",
        "## Failed-case diagnostics", "",
    ]
    if result.diagnostics:
        for diagnostic in result.diagnostics:
            lines.extend([f"### `{diagnostic.case_id}`", ""])
            lines.extend(f"- {message}" for message in diagnostic.messages)
            lines.append("")
    else:
        lines.extend(["No failed cases.", ""])
    lines.extend(["## Additional team-created cases", ""])
    for case in TEAM_CASES:
        lines.extend([f"### {case.case_id}: {case.title}", "", case.explanation, ""])
    lines.extend([
        "## Evaluator correctness, failures, and improvements", "",
        "Controlled tests mutate the team fixtures to cover wrong status, missing/extra/reordered/duplicated steps, wrong evidence, wrong numbering and types, missing/extra/duplicate cases, malformed JSON, and invalid NOT_APPLICABLE rows. The evaluator preserves raw input so validation cannot silently sort, renumber, coerce, fill, or deduplicate a prediction.", "",
        "## Limitations", "",
        "Evidence IDs are compared exactly; semantic citation verification is intentionally deferred. Public-sample prediction performance is only measured when a real prediction file is supplied. Hidden full-dataset accuracy is unavailable to this framework.", "",
    ])
    return "\n".join(lines)


def write_report(result: EvaluationResult, path: Path | str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_report(result), encoding="utf-8", newline="\n")
