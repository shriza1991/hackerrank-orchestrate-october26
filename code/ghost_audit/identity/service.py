"""Reusable identity resolution service over indexed user identities and audit logs."""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Sequence

from ghost_audit.identity.index import IdentityIndex
from ghost_audit.identity.normalization import normalize_email
from ghost_audit.identity.timeline import reconstruct_user_timeline
from ghost_audit.models.input_models import DeletionRequest, UserAuditLogEntry, UserIdentity
from ghost_audit.models.intermediate_models import (
    IdentityResolutionResult,
    IdentityResolutionStatus,
)
from ghost_audit.timestamps import parse_iso_timestamp


class IdentityResolutionService:
    """Service for resolving request emails to stable user identities.

    Deterministic, fully offline, model-free, and adheres to all temporal
    and cross-person leakage constraints.
    """

    def __init__(self, index: IdentityIndex) -> None:
        self.index = index

    @classmethod
    def from_data(
        cls,
        identities: Sequence[UserIdentity] = (),
        audit_logs: Sequence[UserAuditLogEntry] = (),
    ) -> IdentityResolutionService:
        """Create a service by building the index once from dataset records."""
        index = IdentityIndex(identities=identities, audit_logs=audit_logs)
        return cls(index)

    def resolve_request(self, request: DeletionRequest) -> IdentityResolutionResult:
        """Resolve a DeletionRequest's email and timestamps to its stable identity."""
        return self.resolve_email(
            email=request.email,
            audit_at=request.audit_at,
            requested_at=request.requested_at,
            case_id=request.case_id,
        )

    def resolve_email(
        self,
        email: str,
        audit_at: datetime | str,
        requested_at: Optional[datetime | str] = None,
        case_id: Optional[str] = None,
    ) -> IdentityResolutionResult:
        """Resolve an email address to a stable user identity at an inclusive audit cutoff."""
        audit_dt = parse_iso_timestamp(audit_at)
        req_dt = parse_iso_timestamp(requested_at) if requested_at is not None else None

        norm_email = normalize_email(email)
        if not norm_email:
            return IdentityResolutionResult(
                resolution_status=IdentityResolutionStatus.UNRESOLVED,
                stable_subject_reference=None,
                request_email=email,
                normalized_request_email="",
                notes="Email is empty, None, or whitespace-only.",
                applicable_timestamps={"audit_cutoff": audit_dt},
            )

        candidates = self.index.find_candidate_user_ids(norm_email, audit_dt)

        if not candidates:
            return IdentityResolutionResult(
                resolution_status=IdentityResolutionStatus.UNRESOLVED,
                stable_subject_reference=None,
                request_email=email,
                normalized_request_email=norm_email,
                notes=f"No eligible pre-cutoff identity record found for '{email}' at cutoff {audit_dt.isoformat()}.",
                applicable_timestamps={"audit_cutoff": audit_dt},
            )

        if len(candidates) > 1:
            notes = (
                f"Ambiguous match: multiple plausible candidate users {candidates} "
                f"are associated with email '{email}' at or before cutoff."
            )
            return IdentityResolutionResult(
                resolution_status=IdentityResolutionStatus.AMBIGUOUS,
                stable_subject_reference=None,
                request_email=email,
                normalized_request_email=norm_email,
                candidates=candidates,
                notes=notes,
                applicable_timestamps={"audit_cutoff": audit_dt},
            )

        # Exactly 1 candidate resolved
        user_id = candidates[0]
        snapshot = self.index.get_snapshot(user_id)
        user_logs = self.index.get_audit_logs(user_id)
        timeline = reconstruct_user_timeline(
            user_id=user_id,
            snapshot=snapshot,
            audit_logs=user_logs,
            audit_at=audit_dt,
        )

        # Determine match method
        matching_records = [
            r
            for r in self.index.find_eligible_email_records(norm_email, audit_dt)
            if r.user_id == user_id
        ]
        types = {r.source_type for r in matching_records}
        is_current_snap = (
            "SNAPSHOT" in types
            and snapshot is not None
            and normalize_email(snapshot.email) == norm_email
            and snapshot.updated_at <= audit_dt
        )

        if is_current_snap and ("AUDIT_OLD" in types or "AUDIT_NEW" in types):
            match_method = "SNAPSHOT_AND_HISTORICAL_EMAIL"
        elif is_current_snap:
            match_method = "CURRENT_SNAPSHOT_EMAIL"
        elif "AUDIT_OLD" in types:
            match_method = "HISTORICAL_AUDIT_LOG_OLD_EMAIL"
        elif "AUDIT_NEW" in types:
            match_method = "HISTORICAL_AUDIT_LOG_NEW_EMAIL"
        else:
            match_method = "HISTORICAL_AUDIT_LOG"

        applicable_ts = dict(timeline.applicable_timestamps)
        if req_dt is not None:
            applicable_ts["requested_at"] = req_dt

        return IdentityResolutionResult(
            resolution_status=IdentityResolutionStatus.RESOLVED,
            stable_subject_reference=user_id,
            current_identifiers=timeline.current_identifiers,
            historical_identifiers=timeline.historical_identifiers,
            supporting_references=timeline.supporting_audit_ids,
            applicable_timestamps=applicable_ts,
            notes=f"Successfully resolved to user {user_id} via {match_method}.",
            request_email=email,
            normalized_request_email=norm_email,
            match_method=match_method,
            candidates=[user_id],
            searchable_identifiers=timeline.searchable_identifiers,
            warnings=timeline.warnings,
            conflicts=timeline.conflicts,
            provenance=timeline.provenance,
        )
