"""Lossless CSV/JSON loading and structural validation for evaluator inputs."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ghost_audit.models.output_models import DeletionStatus, Step, validate_steps_sequence

OUTPUT_COLUMNS = ["case_id", "deletion_status", "steps_json"]
STEP_FIELDS = [
    "step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"
]


@dataclass
class RawOutputRow:
    """One row exactly as supplied, plus diagnostics; values are never repaired."""

    line_no: int
    case_id: Any
    deletion_status: Any
    raw_steps_json: Any
    steps: Any = None
    errors: list[str] = field(default_factory=list)

    @property
    def contract_valid(self) -> bool:
        return not self.errors


@dataclass
class LoadedOutput:
    path: Path
    headers: list[str] = field(default_factory=list)
    rows: list[RawOutputRow] = field(default_factory=list)
    file_errors: list[str] = field(default_factory=list)
    fatal_errors: list[str] = field(default_factory=list)
    sorted_valid: bool = False

    @property
    def rows_by_id(self) -> dict[str, list[RawOutputRow]]:
        grouped: dict[str, list[RawOutputRow]] = defaultdict(list)
        for row in self.rows:
            if isinstance(row.case_id, str) and row.case_id.strip():
                grouped[row.case_id].append(row)
        return dict(grouped)

    @property
    def duplicate_ids(self) -> list[str]:
        return sorted(case_id for case_id, rows in self.rows_by_id.items() if len(rows) > 1)

    @property
    def unique_rows(self) -> dict[str, RawOutputRow]:
        return {case_id: rows[0] for case_id, rows in self.rows_by_id.items() if len(rows) == 1}


def _strict_csv(path: Path) -> tuple[list[str], list[tuple[int, list[str]]], list[str]]:
    """Read a CSV with BOM support, strict quotes, and physical line diagnostics."""
    if not path.is_file():
        return [], [], [f"File does not exist: {path}"]
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle, strict=True)
            try:
                headers = next(reader)
            except StopIteration:
                return [], [], ["CSV is empty; no header row found."]
            rows: list[tuple[int, list[str]]] = []
            while True:
                line_no = reader.line_num + 1
                try:
                    values = next(reader)
                except StopIteration:
                    break
                if not values:
                    continue
                rows.append((line_no, values))
            return headers, rows, []
    except (csv.Error, UnicodeError, OSError) as exc:
        return [], [], [f"Unable to read CSV: {exc}"]


def _validate_step(step: Any, position: int) -> list[str]:
    prefix = f"step {position}"
    if not isinstance(step, dict):
        return [f"{prefix} must be an object; got {type(step).__name__}."]
    errors: list[str] = []
    missing = [key for key in STEP_FIELDS if key not in step]
    extra = [key for key in step if key not in STEP_FIELDS]
    if missing:
        errors.append(f"{prefix} missing fields: {missing}.")
    if extra:
        errors.append(f"{prefix} has unexpected fields: {extra}.")
    if "step_no" in step and (type(step["step_no"]) is not int or step["step_no"] < 1):
        errors.append(f"{prefix}.step_no must be a positive integer (booleans are invalid).")
    for key in STEP_FIELDS[1:]:
        if key in step and type(step[key]) is not str:
            errors.append(f"{prefix}.{key} must be a string; got {type(step[key]).__name__}.")
    for key in ("system_id", "resource_id"):
        if key in step and isinstance(step[key], str) and not step[key].strip():
            errors.append(f"{prefix}.{key} must be nonblank.")
    if "evidence_id" in step and isinstance(step["evidence_id"], str):
        if step["evidence_id"] and not step["evidence_id"].strip():
            errors.append(f"{prefix}.evidence_id must be empty or nonblank.")
    if not missing and not extra and not errors:
        try:
            # Enum fields arrive from JSON as strings. Primitive types were
            # checked strictly above; normal Pydantic parsing maps enum values
            # so Task 1's canonical operation contract can be reused.
            Step.model_validate(step)
        except Exception as exc:
            errors.append(f"{prefix} schema violation: {exc}")
    return errors


def _validate_row(row: RawOutputRow) -> None:
    if not isinstance(row.case_id, str) or not row.case_id.strip():
        row.errors.append("case_id must be a nonblank string.")
    if type(row.deletion_status) is not str or row.deletion_status not in {item.value for item in DeletionStatus}:
        row.errors.append(f"Invalid deletion_status: {row.deletion_status!r}.")
    try:
        row.steps = json.loads(row.raw_steps_json)
    except (TypeError, json.JSONDecodeError) as exc:
        row.errors.append(f"Malformed steps_json: {exc}.")
        return
    if not isinstance(row.steps, list):
        row.errors.append(f"steps_json must decode to an array; got {type(row.steps).__name__}.")
        return
    for position, step in enumerate(row.steps, start=1):
        row.errors.extend(_validate_step(step, position))
    if not row.errors:
        status = DeletionStatus(row.deletion_status)
        steps = [Step.model_validate(step) for step in row.steps]
        row.errors.extend(validate_steps_sequence(status, steps))


def load_output(path: Path | str) -> LoadedOutput:
    path = Path(path).resolve()
    result = LoadedOutput(path=path)
    headers, raw_rows, fatal = _strict_csv(path)
    result.headers = headers
    result.fatal_errors.extend(fatal)
    if fatal:
        return result
    duplicates = sorted(name for name, count in Counter(headers).items() if count > 1)
    blanks = [index + 1 for index, name in enumerate(headers) if not name.strip()]
    if duplicates:
        result.fatal_errors.append(f"Duplicate CSV headers: {duplicates}.")
    if blanks:
        result.fatal_errors.append(f"Blank CSV headers at columns: {blanks}.")
    if result.fatal_errors:
        return result
    if headers != OUTPUT_COLUMNS:
        result.file_errors.append(f"Output columns must be exactly {OUTPUT_COLUMNS}; found {headers}.")
    for line_no, values in raw_rows:
        if len(values) != len(headers):
            result.file_errors.append(f"Row {line_no} has {len(values)} cells; header has {len(headers)}.")
            continue
        record = dict(zip(headers, values))
        row = RawOutputRow(line_no, record.get("case_id"), record.get("deletion_status"), record.get("steps_json"))
        _validate_row(row)
        result.rows.append(row)
    case_ids = [row.case_id for row in result.rows]
    result.sorted_valid = all(isinstance(value, str) and value.strip() for value in case_ids) and case_ids == sorted(case_ids)
    if not result.sorted_valid:
        result.file_errors.append("Rows are not sorted by case_id.")
    if result.duplicate_ids:
        result.file_errors.append(f"Duplicate case IDs: {result.duplicate_ids}.")
    return result


def load_request_ids(path: Path | str) -> list[str]:
    path = Path(path).resolve()
    headers, rows, fatal = _strict_csv(path)
    if fatal:
        raise ValueError("; ".join(fatal))
    duplicates = sorted(name for name, count in Counter(headers).items() if count > 1)
    if duplicates or any(not name.strip() for name in headers) or "case_id" not in headers:
        raise ValueError("Requests CSV must have unique nonblank headers including case_id.")
    index = headers.index("case_id")
    ids: list[str] = []
    for line_no, values in rows:
        if len(values) != len(headers):
            raise ValueError(f"Requests row {line_no} has the wrong number of cells.")
        case_id = values[index]
        if not case_id.strip():
            raise ValueError(f"Requests row {line_no} has a blank case_id.")
        ids.append(case_id)
    repeated = sorted(name for name, count in Counter(ids).items() if count > 1)
    if repeated:
        raise ValueError(f"Requests contain duplicate case IDs: {repeated}.")
    return ids
