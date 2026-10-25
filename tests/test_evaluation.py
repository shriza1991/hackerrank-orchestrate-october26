"""Task 2 evaluator metrics, diagnostics, isolation, and CLI tests."""

from __future__ import annotations

import csv
import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from evaluation.evaluator import EvaluationInputError, evaluate_files, strict_equal
from evaluation.fixtures import TEAM_CASES


def write_requests(path: Path, case_ids: list[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["case_id"])
        writer.writerows([[case_id] for case_id in case_ids])


def write_output(path: Path, rows, headers=("case_id", "deletion_status", "steps_json")) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        for row in rows:
            steps = row[2] if isinstance(row[2], str) else json.dumps(row[2])
            writer.writerow([row[0], row[1], steps])


def fixture_rows():
    return [(case.case_id, case.status, copy.deepcopy(case.steps)) for case in TEAM_CASES]


def evaluate(tmp_path: Path, predicted_rows, reference_rows=None):
    reference_rows = reference_rows or fixture_rows()
    ids = [row[0] for row in reference_rows]
    requests, reference, predictions = tmp_path / "requests.csv", tmp_path / "reference.csv", tmp_path / "predictions.csv"
    write_requests(requests, ids)
    write_output(reference, reference_rows)
    write_output(predictions, predicted_rows)
    return evaluate_files(predictions, reference, requests)


def test_perfect_match_metrics_and_empty_case_convention(tmp_path):
    result = evaluate(tmp_path, fixture_rows())
    assert result.prediction_contract_valid
    assert result.metrics.status_accuracy == result.metrics.exact_row_accuracy == 1
    assert result.metrics.step_precision == result.metrics.step_recall == result.metrics.step_f1 == 1
    assert result.metrics.step_field_accuracy == result.metrics.sequence_accuracy == 1


def test_wrong_status_detected_even_with_matching_sequence(tmp_path):
    rows = fixture_rows()
    rows[1] = (rows[1][0], "INCOMPLETE", rows[1][2])
    result = evaluate(tmp_path, rows)
    assert result.metrics.status_correct == 4
    assert result.metrics.sequences_correct == 5
    assert result.metrics.exact_rows_correct == 4
    assert not result.prediction_contract_valid


@pytest.mark.parametrize("mutation", ["missing", "extra", "evidence", "reorder", "number", "duplicate"])
def test_controlled_step_errors_are_detected(tmp_path, mutation):
    rows = fixture_rows()
    steps = rows[3][2]
    if mutation == "missing":
        steps.pop()
    elif mutation == "extra":
        duplicate = copy.deepcopy(steps[-1]); duplicate["step_no"] = 4; steps.append(duplicate)
    elif mutation == "evidence":
        steps[0]["evidence_id"] = "wrong_evidence"
    elif mutation == "reorder":
        steps[0], steps[1] = steps[1], steps[0]
    elif mutation == "number":
        steps[0]["step_no"] = 9
    elif mutation == "duplicate":
        duplicate = copy.deepcopy(steps[0]); duplicate["step_no"] = 4; steps.append(duplicate)
    result = evaluate(tmp_path, rows)
    assert result.metrics.exact_rows_correct < 5
    assert result.diagnostics
    assert result.prediction_contract_valid is (mutation == "evidence")


def test_strict_field_types_do_not_coerce_bool_int_or_string(tmp_path):
    rows = fixture_rows()
    rows[1][2][0]["step_no"] = True
    result = evaluate(tmp_path, rows)
    assert not strict_equal(True, 1)
    assert result.metrics.step_field_accuracy < 1
    assert any("positive integer" in error for error in result.diagnostics[0].messages)


def test_duplicate_aware_multiset_matching(tmp_path):
    rows = fixture_rows()
    duplicate = copy.deepcopy(rows[3][2][0]); duplicate["step_no"] = 4; rows[3][2].append(duplicate)
    result = evaluate(tmp_path, rows)
    assert result.metrics.matched_steps == result.metrics.expected_steps
    assert result.metrics.predicted_steps == result.metrics.expected_steps + 1
    assert result.metrics.step_precision < 1
    assert result.metrics.step_recall == 1


def test_missing_and_extra_cases_affect_full_denominators(tmp_path):
    rows = fixture_rows()[1:]
    rows.append(("team_999", "NOT_APPLICABLE", []))
    result = evaluate(tmp_path, rows)
    assert result.coverage.missing_case_ids == ["team_001"]
    assert result.coverage.extra_case_ids == ["team_999"]
    assert result.metrics.expected_cases == 5
    assert result.metrics.status_accuracy == pytest.approx(4 / 5)


def test_duplicate_case_is_ambiguous_and_gets_no_credit(tmp_path):
    rows = fixture_rows()
    rows.insert(1, copy.deepcopy(rows[0]))
    result = evaluate(tmp_path, rows)
    assert result.coverage.duplicate_case_ids == ["team_001"]
    assert result.metrics.status_accuracy == pytest.approx(4 / 5)


def test_malformed_json_and_invalid_not_applicable_are_diagnostic(tmp_path):
    rows = fixture_rows()
    rows[0] = ("team_001", "NOT_APPLICABLE", TEAM_CASES[1].steps)
    rows[1] = ("team_002", "COMPLETE", "{broken")
    result = evaluate(tmp_path, rows)
    assert result.coverage.json_error_count == 1
    assert result.coverage.schema_error_count >= 1
    assert result.metrics.exact_rows_correct == 3


def test_header_non_array_and_invalid_status_contract_errors(tmp_path):
    requests, reference, predictions = tmp_path / "requests.csv", tmp_path / "reference.csv", tmp_path / "predictions.csv"
    rows = fixture_rows()
    write_requests(requests, [row[0] for row in rows])
    write_output(reference, rows)
    bad = fixture_rows(); bad[1] = ("team_002", "ERASED", "{}")
    with predictions.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle); writer.writerow(("case_id", "deletion_status", "steps_json", "extra"))
        for case_id, status, steps in bad:
            writer.writerow((case_id, status, steps if isinstance(steps, str) else json.dumps(steps), "x"))
    result = evaluate_files(predictions, reference, requests)
    assert any("exactly" in error for error in result.coverage.file_errors)
    assert result.coverage.schema_error_count >= 1
    assert not result.prediction_contract_valid


def test_duplicate_and_blank_output_headers_are_unusable(tmp_path):
    requests, reference, predictions = tmp_path / "requests.csv", tmp_path / "reference.csv", tmp_path / "predictions.csv"
    rows = fixture_rows(); write_requests(requests, [row[0] for row in rows]); write_output(reference, rows)
    predictions.write_text("case_id,case_id,steps_json\nteam_001,team_001,[]\n", encoding="utf-8")
    with pytest.raises(EvaluationInputError, match="Duplicate CSV headers"):
        evaluate_files(predictions, reference, requests)
    predictions.write_text("case_id,,steps_json\nteam_001,NOT_APPLICABLE,[]\n", encoding="utf-8")
    with pytest.raises(EvaluationInputError, match="Blank CSV headers"):
        evaluate_files(predictions, reference, requests)


def test_json_object_key_and_whitespace_invariance_but_array_order_sensitivity(tmp_path):
    rows = fixture_rows()
    reordered_keys = [{key: step[key] for key in reversed(list(step))} for step in rows[3][2]]
    rows[3] = (rows[3][0], rows[3][1], json.dumps(reordered_keys, indent=4))
    assert evaluate(tmp_path, rows).metrics.exact_rows_correct == 5
    rows = fixture_rows(); rows[3][2][0], rows[3][2][1] = rows[3][2][1], rows[3][2][0]
    assert evaluate(tmp_path, rows).metrics.sequence_accuracy < 1


def test_unexpected_fields_prevent_exact_credit_without_being_dropped(tmp_path):
    rows = fixture_rows(); rows[1][2][0]["surprise"] = "kept raw"
    result = evaluate(tmp_path, rows)
    assert result.metrics.exact_rows_correct == 4
    assert any("unexpected fields" in message for message in result.diagnostics[0].messages)


def test_invalid_reference_is_evaluator_error(tmp_path):
    reference = fixture_rows(); reference[1][2][0]["step_no"] = "1"
    with pytest.raises(EvaluationInputError, match="Invalid reference"):
        evaluate(tmp_path, fixture_rows(), reference)


def test_public_reference_is_structurally_accepted(real_dataset_dir):
    result = evaluate_files(real_dataset_dir / "sample_output.csv", real_dataset_dir / "sample_output.csv",
                            real_dataset_dir / "sample_deletion_requests.csv")
    assert result.prediction_contract_valid
    assert result.metrics.exact_row_accuracy == 1  # evaluator sanity only, not model performance


def test_cli_from_another_working_directory_and_report(tmp_path, real_dataset_dir):
    root = Path(__file__).resolve().parents[1]
    report = tmp_path / "report.md"
    command = [sys.executable, str(root / "code" / "evaluation" / "main.py"), "--predictions",
               str(real_dataset_dir / "sample_output.csv"), "--report", str(report), "--json"]
    completed = subprocess.run(command, cwd=tmp_path, text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["prediction_contract_valid"] is True
    assert "Additional team-created cases" in report.read_text(encoding="utf-8")


def test_cli_exit_zero_for_valid_inaccurate_and_one_for_contract_failure(tmp_path):
    root = Path(__file__).resolve().parents[1]
    requests, reference = tmp_path / "requests.csv", tmp_path / "reference.csv"
    write_requests(requests, [row[0] for row in fixture_rows()])
    write_output(reference, fixture_rows())
    inaccurate = fixture_rows(); inaccurate[1][2][0]["evidence_id"] = "wrong_but_well_formed"
    valid_predictions = tmp_path / "valid_inaccurate.csv"; write_output(valid_predictions, inaccurate)
    base = [sys.executable, str(root / "code" / "evaluation" / "main.py"),
            "--reference", str(reference), "--requests", str(requests)]
    assert subprocess.run(base + ["--predictions", str(valid_predictions)], capture_output=True).returncode == 0
    invalid_predictions = tmp_path / "invalid.csv"; write_output(invalid_predictions, fixture_rows()[1:])
    assert subprocess.run(base + ["--predictions", str(invalid_predictions)], capture_output=True).returncode == 1


def test_prediction_reference_separation():
    code_root = Path(__file__).resolve().parents[1] / "code" / "ghost_audit"
    for source in code_root.rglob("*.py"):
        text = source.read_text(encoding="utf-8")
        assert "from evaluation" not in text and "import evaluation" not in text, source
