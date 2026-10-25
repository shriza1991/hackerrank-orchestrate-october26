"""Multi-valued in-memory indexes for identities and historical audit logs."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Sequence

from ghost_audit.identity.normalization import normalize_email, normalize_user_id
from ghost_audit.models.input_models import UserAuditLogEntry, UserIdentity
from ghost_audit.timestamps import is_within_audit_cutoff


@dataclass(frozen=True)
class EmailOwnershipRecord:
    """Record associating an email with a user via snapshot or historical change."""

    user_id: str
    raw_email: str
    normalized_email: str
    source_type: str  # "SNAPSHOT", "AUDIT_OLD", "AUDIT_NEW"
    source_id: Optional[str]  # audit_id or None
    event_time: datetime
    validity_start: Optional[datetime] = None
    validity_end: Optional[datetime] = None


class IdentityIndex:
    """Thread-safe multi-valued index built once from identities and audit logs.

    Prevents cross-person leakage by maintaining multi-valued mappings
    and preserving individual user provenance without overwriting duplicate aliases.
    """

    def __init__(
        self,
        identities: Sequence[UserIdentity] = (),
        audit_logs: Sequence[UserAuditLogEntry] = (),
    ) -> None:
        self._identities_by_user_id: dict[str, UserIdentity] = {}
        self._audit_logs_by_user_id: dict[str, list[UserAuditLogEntry]] = defaultdict(list)
        self._email_ownership: dict[str, list[EmailOwnershipRecord]] = defaultdict(list)

        for ident in identities:
            norm_uid = normalize_user_id(ident.user_id)
            self._identities_by_user_id[norm_uid] = ident
            norm_e = normalize_email(ident.email)
            if norm_e:
                self._email_ownership[norm_e].append(
                    EmailOwnershipRecord(
                        user_id=norm_uid,
                        raw_email=ident.email.strip(),
                        normalized_email=norm_e,
                        source_type="SNAPSHOT",
                        source_id=None,
                        event_time=ident.updated_at,
                        validity_start=None,
                        validity_end=None,
                    )
                )

        for log in audit_logs:
            norm_uid = normalize_user_id(log.user_id)
            self._audit_logs_by_user_id[norm_uid].append(log)
            if log.field_name == "email":
                if log.old_value.strip():
                    raw_old = log.old_value.strip()
                    norm_old = normalize_email(raw_old)
                    if norm_old:
                        self._email_ownership[norm_old].append(
                            EmailOwnershipRecord(
                                user_id=norm_uid,
                                raw_email=raw_old,
                                normalized_email=norm_old,
                                source_type="AUDIT_OLD",
                                source_id=log.audit_id,
                                event_time=log.event_time,
                                validity_start=None,
                                validity_end=log.event_time,
                            )
                        )
                if log.new_value.strip():
                    raw_new = log.new_value.strip()
                    norm_new = normalize_email(raw_new)
                    if norm_new:
                        self._email_ownership[norm_new].append(
                            EmailOwnershipRecord(
                                user_id=norm_uid,
                                raw_email=raw_new,
                                normalized_email=norm_new,
                                source_type="AUDIT_NEW",
                                source_id=log.audit_id,
                                event_time=log.event_time,
                                validity_start=log.event_time,
                                validity_end=None,
                            )
                        )

    def get_snapshot(self, user_id: str) -> Optional[UserIdentity]:
        """Look up user identity snapshot by user_id."""
        return self._identities_by_user_id.get(normalize_user_id(user_id))

    def get_audit_logs(self, user_id: str) -> list[UserAuditLogEntry]:
        """Look up all historical audit log entries for a user_id."""
        return list(self._audit_logs_by_user_id.get(normalize_user_id(user_id), []))

    def find_eligible_email_records(
        self,
        normalized_email: str,
        audit_at: datetime,
    ) -> list[EmailOwnershipRecord]:
        """Find all email ownership records that are eligible at or before audit_at cutoff."""
        records = self._email_ownership.get(normalized_email, [])
        eligible: list[EmailOwnershipRecord] = []
        for r in records:
            if is_within_audit_cutoff(r.event_time, audit_at):
                eligible.append(r)
        return eligible

    def find_candidate_user_ids(
        self,
        normalized_email: str,
        audit_at: datetime,
    ) -> list[str]:
        """Return deterministically sorted list of unique candidate user IDs eligible at cutoff."""
        eligible = self.find_eligible_email_records(normalized_email, audit_at)
        return sorted({r.user_id for r in eligible})
