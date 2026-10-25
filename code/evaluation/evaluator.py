"""Metric computation and case diagnostics for deletion-audit predictions."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from evaluation.loader import STEP_FIELDS, LoadedOutput, RawOutputRow, load_output, load_request_ids


class EvaluationInputError(ValueError):
    """The reference or request input is unusable; this is not a prediction miss."""


def _typed(value: Any) -> Any:
    """Hashable, recursively type-tagged value (so True, 1, and '1' differ)."""
    if isinstance(value, dict):
        return ("dict", tuple(sorted((str(key), _typed(item)) for key, item in value.items())))
    if isinstance(value, list):
        return ("list", tuple(_typed(item) for item in value))
    return (type(value).__name__, value)


def strict_equal(left: Any, right: Any) -> bool:
    return _typed(left) == _typed(right)


def _step_identity(step: Any) -> Any:
    if not isinstance(step, dict):
        return ("invalid-step", _typed(step))
    return tuple((name, _typed(step[name]) if name in step else ("missing",)) for name in STEP_FIELDS[1:])


def _steps(row: RawOutputRow | None) -> list[Any]:
    return row.steps if row is not None and isinstance(row.steps, list) else []


@dataclass
class Metrics:
    expected_cases: int
    status_correct: int
    status_accuracy: float
    exact_rows_correct: int
    exact_row_accuracy: float
    matched_steps: int
    predicted_steps: int
    expected_steps: int
    step_precision: float
    step_recall: float
    step_f1: float
    correct_step_fields: int
    compared_step_fields: int
    step_field_accuracy: float
    sequences_correct: int
    sequence_accuracy: float


@dataclass
class Coverage:
    expected: int
    supplied: int
    missing_case_ids: list[str]
    extra_case_ids: list[str]
    duplicate_case_ids: list[str]
    contract_valid_cases: int
    contract_valid_rate: float
    sorted_output_valid: bool
    json_error_count: int
    schema_error_count: int
    file_errors: list[str]

    @property
    def valid(self) -> bool:
        return not (
            self.missing_case_ids or self.extra_case_ids or self.duplicate_case_ids
            or self.contract_valid_cases != self.expected or not self.sorted_output_valid or self.file_errors
        )


@dataclass
class CaseDiagnostic:
    case_id: str
    messages: list[str] = field(default_factory=list)


@dataclass
class EvaluationResult:
    prediction_path: str
    reference_path: str
    requests_path: str
    metrics: Metrics
    coverage: Coverage
    diagnostics: list[CaseDiagnostic]

    @property
    def prediction_contract_valid(self) -> bool:
        return self.coverage.valid

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["prediction_contract_valid"] = self.prediction_contract_valid
        return value


def _multiset_diff(expected: list[Any], predicted: list[Any]) -> tuple[int, list[Any], list[Any]]:
    expected_counts = Counter(_step_identity(step) for step in expected)
    predicted_counts = Counter(_step_identity(step) for step in predicted)
    matched = sum((expected_counts & predicted_counts).values())
    return matched, list((expected_counts - predicted_counts).elements()), list((predicted_counts - expected_counts).elements())


def _field_score(expected: list[Any], predicted: list[Any]) -> tuple[int, int, list[str]]:
    correct = 0
    total = max(len(expected), len(predicted)) * len(STEP_FIELDS)
    mismatches: list[str] = []
    for index in range(max(len(expected), len(predicted))):
        if index >= len(expected):
            mismatches.append(f"unexpected step at position {index + 1}")
            continue
        if index >= len(predicted):
            mismatches.append(f"missing step at position {index + 1}")
            continue
        exp, pred = expected[index], predicted[index]
        for name in STEP_FIELDS:
            exp_value = exp.get(name, ("missing",)) if isinstance(exp, dict) else ("invalid",)
            pred_value = pred.get(name, ("missing",)) if isinstance(pred, dict) else ("invalid",)
            if strict_equal(exp_value, pred_value):
                correct += 1
            else:
                mismatches.append(f"position {index + 1} field {name}: expected {exp_value!r}, got {pred_value!r}")
    return correct, total, mismatches


def _validate_reference(reference: LoadedOutput, request_ids: list[str]) -> None:
    problems = list(reference.fatal_errors) + list(reference.file_errors)
    problems.extend(f"Reference row {row.line_no}: {error}" for row in reference.rows for error in row.errors)
    if [row.case_id for row in reference.rows] != request_ids:
        problems.append("Reference case IDs do not exactly match requests in sorted row order.")
    if problems:
        raise EvaluationInputError("Invalid reference input: " + " | ".join(problems))


def evaluate_loaded(predictions: LoadedOutput, reference: LoadedOutput, request_ids: list[str]) -> EvaluationResult:
    _validate_reference(reference, request_ids)
    if predictions.fatal_errors:
        raise EvaluationInputError("Unusable prediction input: " + " | ".join(predictions.fatal_errors))
    expected_rows, predicted_unique = reference.unique_rows, predictions.unique_rows
    expected_set, supplied_set = set(request_ids), set(predictions.rows_by_id)
    missing, extra = sorted(expected_set - supplied_set), sorted(supplied_set - expected_set)
    duplicate = predictions.duplicate_ids
    status_correct = exact_correct = sequence_correct = 0
    matched_steps = predicted_steps = expected_steps = fields_correct = fields_total = 0
    diagnostics: list[CaseDiagnostic] = []

    for case_id in request_ids:
        expected = expected_rows[case_id]
        predicted = None if case_id in duplicate else predicted_unique.get(case_id)
        expected_list, predicted_list = _steps(expected), _steps(predicted)
        expected_steps += len(expected_list)
        predicted_steps += len(predicted_list)
        if case_id in duplicate:
            # Ambiguous duplicate rows cannot match the expected case, but
            # their emitted steps still count as unmatched predictions.
            for duplicate_row in predictions.rows_by_id[case_id]:
                predicted_steps += len(_steps(duplicate_row))
                fields_total += len(_steps(duplicate_row)) * len(STEP_FIELDS)
        matched, missing_steps, unexpected_steps = _multiset_diff(expected_list, predicted_list)
        matched_steps += matched
        correct, total, field_mismatches = _field_score(expected_list, predicted_list)
        fields_correct += correct
        fields_total += total
        readable = predicted is not None and isinstance(predicted.steps, list)
        status_match = readable and strict_equal(expected.deletion_status, predicted.deletion_status)
        sequence_match = readable and strict_equal(expected_list, predicted_list)
        status_correct += int(status_match)
        sequence_correct += int(sequence_match)
        exact = bool(status_match and sequence_match and predicted and predicted.contract_valid)
        exact_correct += int(exact)
        if not exact:
            messages: list[str] = []
            if case_id in duplicate:
                messages.append("ambiguous duplicate prediction rows")
            elif predicted is None:
                messages.append("prediction row is missing")
            else:
                if not status_match:
                    messages.append(f"status expected {expected.deletion_status!r}, got {predicted.deletion_status!r}")
                messages.extend(f"contract: {error}" for error in predicted.errors)
            if missing_steps:
                messages.append(f"missing unordered steps: {len(missing_steps)}")
            if unexpected_steps:
                messages.append(f"unexpected unordered steps: {len(unexpected_steps)}")
            messages.extend(field_mismatches)
            if predicted is not None and not sequence_match and matched == len(expected_list) == len(predicted_list):
                messages.append("steps discovered but array order and/or numbering differs")
            diagnostics.append(CaseDiagnostic(case_id, messages))

    for case_id in extra:
        for row in predictions.rows_by_id[case_id]:
            predicted_steps += len(_steps(row))
            fields_total += len(_steps(row)) * len(STEP_FIELDS)
        diagnostics.append(CaseDiagnostic(case_id, ["unexpected extra case ID"]))

    precision = matched_steps / predicted_steps if predicted_steps else (1.0 if expected_steps == 0 else 0.0)
    recall = matched_steps / expected_steps if expected_steps else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    field_accuracy = fields_correct / fields_total if fields_total else 1.0
    count = len(request_ids)
    contract_valid_cases = sum(1 for case_id in request_ids if case_id not in duplicate and case_id in predicted_unique and predicted_unique[case_id].contract_valid)
    json_errors = sum(1 for row in predictions.rows if any(error.startswith("Malformed steps_json") for error in row.errors))
    schema_errors = sum(1 for row in predictions.rows if row.errors and not all(error.startswith("Malformed steps_json") for error in row.errors))
    metrics = Metrics(count, status_correct, status_correct / count if count else 1.0,
                      exact_correct, exact_correct / count if count else 1.0,
                      matched_steps, predicted_steps, expected_steps, precision, recall, f1,
                      fields_correct, fields_total, field_accuracy,
                      sequence_correct, sequence_correct / count if count else 1.0)
    coverage = Coverage(count, len(supplied_set), missing, extra, duplicate, contract_valid_cases,
                        contract_valid_cases / count if count else 1.0, predictions.sorted_valid,
                        json_errors, schema_errors, list(predictions.file_errors))
    return EvaluationResult(str(predictions.path), str(reference.path), "", metrics, coverage, diagnostics)


def evaluate_files(predictions: Path | str, reference: Path | str, requests: Path | str) -> EvaluationResult:
    try:
        request_ids = load_request_ids(requests)
    except ValueError as exc:
        raise EvaluationInputError(f"Invalid requests input: {exc}") from exc
    result = evaluate_loaded(load_output(predictions), load_output(reference), request_ids)
    result.requests_path = str(Path(requests).resolve())
    return result
