"""Five independently authored evaluator cases (not prediction rules)."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TeamCase:
    case_id: str
    title: str
    explanation: str
    status: str
    steps: list[dict[str, Any]]


def _step(no, phase, system, resource, operation, state, evidence=""):
    return {"step_no": no, "phase": phase, "system_id": system, "resource_id": resource,
            "operation": operation, "state": state, "evidence_id": evidence}


TEAM_CASES = [
    TeamCase("team_001", "Non-deletion access request",
             "An access request authorizes no deletion work, so the only valid output is NOT_APPLICABLE with an empty array.",
             "NOT_APPLICABLE", []),
    TeamCase("team_002", "Evidence-backed complete deletion",
             "A captured account lookup proves the profile is absent at audit time.", "COMPLETE", [
        _step(1, "VERIFICATION", "account_service", "acct_team_2", "VERIFY_RECORD_ABSENT", "ABSENT", "evidence_team_2")]),
    TeamCase("team_003", "Tombstone redaction and retained security ledger",
             "Direct identifiers remain on a tombstone and must be redacted, while a required security record remains present.",
             "INCOMPLETE", [
        _step(1, "FINDING", "account_service", "tomb_team_3", "REPORT_EXPOSED_PII", "PRESENT", "evidence_team_3a"),
        _step(2, "REMEDIATION", "account_service", "tomb_team_3", "REDACT_RECORD", "REDACTED"),
        _step(3, "VERIFICATION", "security_ledger", "sec_team_3", "VERIFY_RECORD_PRESENT", "PRESENT"),
        _step(4, "VERIFICATION", "account_service", "tomb_team_3", "VERIFY_RECORD_REDACTED", "REDACTED")]),
    TeamCase("team_004", "Active connector",
             "An enabled connector can recreate data; report it, disable it, then verify it is disabled.",
             "INCOMPLETE", [
        _step(1, "FINDING", "connector_service", "conn_team_4", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "evidence_team_4"),
        _step(2, "REMEDIATION", "connector_service", "conn_team_4", "DISABLE_DATA_FLOW", "DISABLED"),
        _step(3, "VERIFICATION", "connector_service", "conn_team_4", "VERIFY_DATA_FLOW_DISABLED", "DISABLED")]),
    TeamCase("team_005", "Backup restore risk",
             "A restorable backup can reintroduce prohibited data; block it before verifying the restore path.",
             "INCOMPLETE", [
        _step(1, "FINDING", "backup_service", "backup_team_5", "REPORT_RESTORE_RISK", "ACTIVE", "evidence_team_5"),
        _step(2, "REMEDIATION", "backup_service", "backup_team_5", "BLOCK_RESTORE", "BLOCKED"),
        _step(3, "VERIFICATION", "backup_service", "backup_team_5", "VERIFY_RESTORE_BLOCKED", "BLOCKED")]),
]
