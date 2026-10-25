"""CSV data loaders and validation engine for ghost_audit."""

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, TypeVar

from pydantic import ValidationError

from ghost_audit.config import Settings
from ghost_audit.manifest import ManifestValidationResult, validate_evidence_manifest
from ghost_audit.models.input_models import (
    DeletionRequest,
    DeletionRule,
    EvidenceManifestEntry,
    SystemActivityEvent,
    UserAuditLogEntry,
    UserIdentity,
)

T = TypeVar("T")


@dataclass(frozen=True)
class ValidationIssue:
    """Detailed validation issue with row and field context."""

    severity: str  # "ERROR" or "WARNING"
    file_name: str
    row_index: Optional[int]
    field_name: Optional[str]
    message: str

    def __str__(self) -> str:
        ctx = f"[{self.file_name}"
        if self.row_index is not None:
            ctx += f":row {self.row_index}"
        if self.field_name:
            ctx += f":field '{self.field_name}'"
        ctx += "]"
        return f"{self.severity} {ctx}: {self.message}"


@dataclass
class DatasetBundle:
    """Container for validated participant-facing dataset tables."""

    is_sample: bool
    requests: list[DeletionRequest] = field(default_factory=list)
    identities: list[UserIdentity] = field(default_factory=list)
    audit_logs: list[UserAuditLogEntry] = field(default_factory=list)
    activity_events: list[SystemActivityEvent] = field(default_factory=list)
    deletion_rules: list[DeletionRule] = field(default_factory=list)
    manifest_entries: list[EvidenceManifestEntry] = field(default_factory=list)
    manifest_result: Optional[ManifestValidationResult] = None
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "ERROR"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "WARNING"]

    @property
    def is_valid(self) -> bool:
        manifest_ok = self.manifest_result.is_valid if self.manifest_result else True
        return len(self.errors) == 0 and manifest_ok


class DataLoader:
    """Loads and validates participant-facing CSV files with robust error reporting."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or Settings()

    def _read_csv_raw(
        self,
        file_path: Path,
        expected_headers: Sequence[str],
    ) -> tuple[list[dict[str, str]], list[ValidationIssue]]:
        """Read CSV file using UTF-8 with BOM support and validate structural row integrity."""
        issues: list[ValidationIssue] = []
        file_name = file_path.name

        if not file_path.exists():
            issues.append(
                ValidationIssue(
                    severity="ERROR",
                    file_name=file_name,
                    row_index=None,
                    field_name=None,
                    message=f"File does not exist: '{file_path}'",
                )
            )
            return [], issues

        rows: list[dict[str, str]] = []
        try:
            with open(file_path, mode="r", encoding="utf-8-sig", newline="") as f:
                reader = csv.reader(f)
                try:
                    headers = next(reader)
                except StopIteration:
                    issues.append(
                        ValidationIssue(
                            severity="ERROR",
                            file_name=file_name,
                            row_index=0,
                            field_name=None,
                            message="Empty CSV file; no header row found.",
                        )
                    )
                    return [], issues

                # Validate headers
                missing_headers = [h for h in expected_headers if h not in headers]
                if missing_headers:
                    issues.append(
                        ValidationIssue(
                            severity="ERROR",
                            file_name=file_name,
                            row_index=1,
                            field_name=None,
                            message=f"Missing required headers: {missing_headers}; found {headers}.",
                        )
                    )
                    return [], issues

                # Informative warning for unexpected headers
                unexpected_headers = [h for h in headers if h not in expected_headers]
                if unexpected_headers:
                    issues.append(
                        ValidationIssue(
                            severity="WARNING",
                            file_name=file_name,
                            row_index=1,
                            field_name=None,
                            message=f"Unexpected headers present: {unexpected_headers}.",
                        )
                    )

                expected_len = len(headers)
                for line_no, raw_row in enumerate(reader, start=2):
                    # Skip empty trailing rows
                    if not raw_row:
                        continue
                    if len(raw_row) != expected_len:
                        issues.append(
                            ValidationIssue(
                                severity="ERROR",
                                file_name=file_name,
                                row_index=line_no,
                                field_name=None,
                                message=f"Malformed row with {len(raw_row)} cells; expected {expected_len}.",
                            )
                        )
                        continue

                    row_dict = dict(zip(headers, raw_row))
                    rows.append(row_dict)

        except Exception as exc:
            issues.append(
                ValidationIssue(
                    severity="ERROR",
                    file_name=file_name,
                    row_index=None,
                    field_name=None,
                    message=f"Failed to read CSV: {exc}",
                )
            )

        return rows, issues

    def _parse_records(
        self,
        raw_rows: list[dict[str, str]],
        file_name: str,
        id_field: str,
        parser: Callable[[dict[str, str]], T],
    ) -> tuple[list[T], list[ValidationIssue]]:
        """Parse raw CSV rows into typed models, enforcing unique primary IDs and recording validation issues."""
        records: list[T] = []
        issues: list[ValidationIssue] = []
        seen_ids: set[str] = set()

        for idx, row in enumerate(raw_rows, start=2):
            primary_id = row.get(id_field, "").strip()
            if not primary_id:
                issues.append(
                    ValidationIssue(
                        severity="ERROR",
                        file_name=file_name,
                        row_index=idx,
                        field_name=id_field,
                        message=f"Missing primary identifier '{id_field}'.",
                    )
                )
            elif primary_id in seen_ids:
                issues.append(
                    ValidationIssue(
                        severity="ERROR",
                        file_name=file_name,
                        row_index=idx,
                        field_name=id_field,
                        message=f"Duplicate primary identifier '{id_field}'='{primary_id}'.",
                    )
                )
            else:
                seen_ids.add(primary_id)

            try:
                model = parser(row)
                records.append(model)
            except ValidationError as ve:
                for err in ve.errors():
                    field_name = ".".join(str(loc) for loc in err["loc"])
                    issues.append(
                        ValidationIssue(
                            severity="ERROR",
                            file_name=file_name,
                            row_index=idx,
                            field_name=field_name,
                            message=err["msg"],
                        )
                    )
            except Exception as exc:
                issues.append(
                    ValidationIssue(
                        severity="ERROR",
                        file_name=file_name,
                        row_index=idx,
                        field_name=None,
                        message=f"Parsing error: {exc}",
                    )
                )

        return records, issues

    def load_deletion_requests(self, path: Path) -> tuple[list[DeletionRequest], list[ValidationIssue]]:
        expected_headers = [
            "case_id",
            "email",
            "requested_at",
            "reported_status",
            "reported_at",
            "audit_at",
            "request_text",
        ]
        raw_rows, issues = self._read_csv_raw(path, expected_headers)
        if not raw_rows and any(i.severity == "ERROR" for i in issues):
            return [], issues

        records, parse_issues = self._parse_records(
            raw_rows, path.name, "case_id", lambda r: DeletionRequest.model_validate(r)
        )
        return records, issues + parse_issues

    def load_user_identities(self, path: Path) -> tuple[list[UserIdentity], list[ValidationIssue]]:
        expected_headers = ["user_id", "name", "email", "phone", "email_hash", "updated_at"]
        raw_rows, issues = self._read_csv_raw(path, expected_headers)
        if not raw_rows and any(i.severity == "ERROR" for i in issues):
            return [], issues

        records, parse_issues = self._parse_records(
            raw_rows, path.name, "user_id", lambda r: UserIdentity.model_validate(r)
        )
        return records, issues + parse_issues

    def load_user_audit_log(self, path: Path) -> tuple[list[UserAuditLogEntry], list[ValidationIssue]]:
        expected_headers = ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"]
        raw_rows, issues = self._read_csv_raw(path, expected_headers)
        if not raw_rows and any(i.severity == "ERROR" for i in issues):
            return [], issues

        records, parse_issues = self._parse_records(
            raw_rows, path.name, "audit_id", lambda r: UserAuditLogEntry.model_validate(r)
        )
        return records, issues + parse_issues

    def load_system_activity(self, path: Path) -> tuple[list[SystemActivityEvent], list[ValidationIssue]]:
        expected_headers = [
            "activity_id",
            "event_time",
            "event_type",
            "source_system",
            "target_system",
            "resource_id",
            "reported_result",
            "details",
        ]
        raw_rows, issues = self._read_csv_raw(path, expected_headers)
        if not raw_rows and any(i.severity == "ERROR" for i in issues):
            return [], issues

        records, parse_issues = self._parse_records(
            raw_rows, path.name, "activity_id", lambda r: SystemActivityEvent.model_validate(r)
        )
        return records, issues + parse_issues

    def load_deletion_rules(self, path: Path) -> tuple[list[DeletionRule], list[ValidationIssue]]:
        expected_headers = ["rule_id", "data_category", "condition", "required_action"]
        raw_rows, issues = self._read_csv_raw(path, expected_headers)
        if not raw_rows and any(i.severity == "ERROR" for i in issues):
            return [], issues

        records, parse_issues = self._parse_records(
            raw_rows, path.name, "rule_id", lambda r: DeletionRule.model_validate(r)
        )
        return records, issues + parse_issues

    def load_evidence_manifest(self, path: Path) -> tuple[list[EvidenceManifestEntry], list[ValidationIssue]]:
        expected_headers = ["file_id", "file_path", "origin", "captured_at"]
        raw_rows, issues = self._read_csv_raw(path, expected_headers)
        if not raw_rows and any(i.severity == "ERROR" for i in issues):
            return [], issues

        records, parse_issues = self._parse_records(
            raw_rows, path.name, "file_id", lambda r: EvidenceManifestEntry.model_validate(r)
        )
        return records, issues + parse_issues

    def load_bundle(self, sample: bool = False) -> DatasetBundle:
        """Load and validate the full participant-facing dataset bundle.

        IMPORTANT: Never loads sample_output.csv into the prediction-facing bundle.
        """
        all_issues: list[ValidationIssue] = []

        req_path = (
            self.settings.sample_deletion_requests_path
            if sample
            else self.settings.deletion_requests_path
        )
        requests, req_issues = self.load_deletion_requests(req_path)
        all_issues.extend(req_issues)

        identities, id_issues = self.load_user_identities(self.settings.user_identities_path)
        all_issues.extend(id_issues)

        audit_logs, audit_issues = self.load_user_audit_log(self.settings.user_audit_log_path)
        all_issues.extend(audit_issues)

        activity_events, act_issues = self.load_system_activity(self.settings.system_activity_path)
        all_issues.extend(act_issues)

        deletion_rules, rule_issues = self.load_deletion_rules(self.settings.deletion_rules_path)
        all_issues.extend(rule_issues)

        manifest_entries, man_issues = self.load_evidence_manifest(self.settings.evidence_files_path)
        all_issues.extend(man_issues)

        # Validate evidence files on disk
        manifest_res = validate_evidence_manifest(manifest_entries, self.settings.dataset_dir)
        for err in manifest_res.errors:
            all_issues.append(
                ValidationIssue(
                    severity="ERROR",
                    file_name="evidence_files.csv",
                    row_index=None,
                    field_name=None,
                    message=err,
                )
            )

        # Basic referential integrity checks (informative warnings)
        known_user_ids = {u.user_id for u in identities}
        for log in audit_logs:
            if log.user_id not in known_user_ids:
                all_issues.append(
                    ValidationIssue(
                        severity="WARNING",
                        file_name="user_audit_log.csv",
                        row_index=None,
                        field_name="user_id",
                        message=f"Audit log entry '{log.audit_id}' references user_id '{log.user_id}' not in user_identities.csv snapshot.",
                    )
                )

        return DatasetBundle(
            is_sample=sample,
            requests=requests,
            identities=identities,
            audit_logs=audit_logs,
            activity_events=activity_events,
            deletion_rules=deletion_rules,
            manifest_entries=manifest_entries,
            manifest_result=manifest_res,
            issues=all_issues,
        )
