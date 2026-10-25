"""Temporal identity reconstruction helpers up to an inclusive audit cutoff."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, Callable, Optional, Sequence

from ghost_audit.identity.models import (
    IdentifierInterval,
    IdentifierProvenance,
    SourceType,
    UserHistoryTimeline,
)
from ghost_audit.identity.normalization import (
    normalize_email,
    normalize_email_hash,
    normalize_phone,
    normalize_user_id,
)
from ghost_audit.models.input_models import UserAuditLogEntry, UserIdentity
from ghost_audit.timestamps import is_within_audit_cutoff


FIELD_NORMALIZERS: dict[str, Callable[[str | None], str]] = {
    "email": normalize_email,
    "phone": normalize_phone,
    "email_hash": normalize_email_hash,
}


def _order_equal_time_events(
    events: list[UserAuditLogEntry],
    field_name: str,
    warnings: list[str],
    conflicts: list[str],
) -> tuple[list[UserAuditLogEntry], bool]:
    """Order equal-timestamp events if they form an unambiguous linear chain.

    Returns (ordered_events, is_conflicted).
    If transitions do not determine an unambiguous chain, surfaces the conflict
    and returns (sorted_events, True) without claiming false authority.
    """
    if len(events) <= 1:
        return events, False

    # Build old_value -> event map
    old_to_event: dict[str, list[UserAuditLogEntry]] = defaultdict(list)
    new_values: set[str] = set()
    for e in events:
        old_to_event[e.old_value].append(e)
        new_values.add(e.new_value)

    # Find candidate start event (old_value not produced as new_value by another event in the group)
    starts = [e for e in events if e.old_value not in new_values]
    if len(starts) == 1:
        chain: list[UserAuditLogEntry] = []
        curr = starts[0]
        visited = set()
        while curr and curr.audit_id not in visited:
            visited.add(curr.audit_id)
            chain.append(curr)
            next_events = old_to_event.get(curr.new_value, [])
            if len(next_events) == 1:
                curr = next_events[0]
            else:
                curr = None
        if len(chain) == len(events):
            return chain, False

    # Ambiguous or branching transitions at the same timestamp
    ts_str = events[0].event_time.isoformat()
    msg = (
        f"Conflicting audit events for field '{field_name}' at {ts_str}: "
        f"cannot determine unambiguous transition sequence among {sorted(e.audit_id for e in events)}."
    )
    conflicts.append(msg)
    warnings.append(msg)
    # Return sorted by audit_id as deterministic fallback with is_conflicted=True
    return sorted(events, key=lambda x: x.audit_id), True


def reconstruct_user_timeline(
    user_id: str,
    snapshot: Optional[UserIdentity],
    audit_logs: Sequence[UserAuditLogEntry],
    audit_at: datetime,
) -> UserHistoryTimeline:
    """Reconstruct an individual user's identifier history up to an inclusive audit cutoff.

    Temporal rules:
    - Excludes any audit log with event_time > audit_at.
    - Excludes snapshot if updated_at > audit_at; does not use future snapshot to invent pre-cutoff state.
    - Detects broken audit chains and equal-timestamp conflicts.
    - Preserves all sources/provenance across deduplication.
    - Distinguishes current-at-cutoff identifiers from historical aliases.
    - Empty old/new values represent absence/clearing and are not treated as searchable identifiers.
    """
    norm_uid = normalize_user_id(user_id)
    warnings: list[str] = []
    conflicts: list[str] = []
    applicable_timestamps: dict[str, datetime] = {"audit_cutoff": audit_at}

    # 1. Filter audit logs by audit_at cutoff
    eligible_logs: list[UserAuditLogEntry] = []
    for log in audit_logs:
        if is_within_audit_cutoff(log.event_time, audit_at):
            eligible_logs.append(log)

    # 2. Check snapshot pre-cutoff validity
    valid_snapshot: Optional[UserIdentity] = None
    if snapshot is not None:
        if is_within_audit_cutoff(snapshot.updated_at, audit_at):
            valid_snapshot = snapshot
            applicable_timestamps["snapshot_updated_at"] = snapshot.updated_at
        else:
            warnings.append(
                f"Snapshot for user {norm_uid} updated at {snapshot.updated_at} is after "
                f"audit cutoff {audit_at}; excluded from pre-cutoff state reconstruction."
            )

    # 3. Group eligible audit logs by field name
    logs_by_field: dict[str, list[UserAuditLogEntry]] = defaultdict(list)
    for log in eligible_logs:
        logs_by_field[log.field_name].append(log)

    current_identifiers: dict[str, str] = {}
    normalized_current_identifiers: dict[str, str] = {}
    historical_intervals: list[IdentifierInterval] = []
    all_provenance: list[IdentifierProvenance] = []
    supporting_audit_ids: set[str] = set()

    # If valid snapshot has a name, record it as contextual metadata
    if valid_snapshot is not None and valid_snapshot.name.strip():
        current_identifiers["name"] = valid_snapshot.name.strip()
        all_provenance.append(
            IdentifierProvenance(
                source_type=SourceType.SNAPSHOT,
                source_file="user_identities.csv",
                source_id=None,
                source_locator=f"user_id:{norm_uid}",
                field_name="name",
                raw_value=valid_snapshot.name.strip(),
                normalized_value=valid_snapshot.name.strip(),
                timestamp=valid_snapshot.updated_at,
                change_type="CURRENT_SNAPSHOT",
                validity_start=None,
                validity_end=None,
            )
        )

    # 4. Reconstruct each identity field
    for field_name in ("email", "phone", "email_hash"):
        normalizer = FIELD_NORMALIZERS[field_name]
        raw_field_logs = logs_by_field.get(field_name, [])

        # Group by timestamp to sequence equal-time events
        time_groups: dict[datetime, list[UserAuditLogEntry]] = defaultdict(list)
        for l in raw_field_logs:
            time_groups[l.event_time].append(l)

        ordered_field_logs: list[UserAuditLogEntry] = []
        conflicted_timestamps: set[datetime] = set()
        for t in sorted(time_groups.keys()):
            grp = time_groups[t]
            ordered_grp, is_conflicted = _order_equal_time_events(grp, field_name, warnings, conflicts)
            if is_conflicted:
                conflicted_timestamps.add(t)
            ordered_field_logs.extend(ordered_grp)

        for l in ordered_field_logs:
            supporting_audit_ids.add(l.audit_id)
            applicable_timestamps[f"{l.audit_id}_event_time"] = l.event_time

        # Check chain continuity
        for i in range(len(ordered_field_logs) - 1):
            curr_log = ordered_field_logs[i]
            next_log = ordered_field_logs[i + 1]
            if normalizer(curr_log.new_value) != normalizer(next_log.old_value):
                warnings.append(
                    f"Discontinuous audit chain for {norm_uid} field '{field_name}': "
                    f"{curr_log.audit_id} produced '{curr_log.new_value}', but subsequent "
                    f"{next_log.audit_id} started with '{next_log.old_value}' at {next_log.event_time}."
                )

        # Build chronological values & intervals
        # Record old_values that establish historical ownership
        for i, l in enumerate(ordered_field_logs):
            raw_old = l.old_value.strip()
            if not raw_old:
                continue
            norm_old = normalizer(raw_old)
            prev_new = ordered_field_logs[i - 1].new_value.strip() if i > 0 else ""
            if i == 0 or norm_old != normalizer(prev_new):
                v_start = ordered_field_logs[i - 1].event_time if i > 0 else None
                prov = IdentifierProvenance(
                    source_type=SourceType.AUDIT_LOG,
                    source_file="user_audit_log.csv",
                    source_id=l.audit_id,
                    source_locator=f"audit_id:{l.audit_id}",
                    field_name=field_name,
                    raw_value=raw_old,
                    normalized_value=norm_old,
                    timestamp=l.event_time,
                    change_type="OLD_VALUE",
                    validity_start=v_start,
                    validity_end=l.event_time,
                )
                all_provenance.append(prov)
                historical_intervals.append(
                    IdentifierInterval(
                        field_name=field_name,
                        raw_value=raw_old,
                        normalized_value=norm_old,
                        is_current_at_cutoff=False,
                        validity_start=v_start,
                        validity_end=l.event_time,
                        sources=[prov],
                    )
                )

        # Determine current-at-cutoff value first to properly categorize transition new_values
        last_log = ordered_field_logs[-1] if ordered_field_logs else None
        latest_audit_time = last_log.event_time if last_log else None
        has_latest_conflict = (latest_audit_time is not None and latest_audit_time in conflicted_timestamps)
        snapshot_val = getattr(valid_snapshot, field_name, "").strip() if valid_snapshot else ""
        has_later_snapshot = (
            valid_snapshot is not None
            and (valid_snapshot.updated_at > latest_audit_time if latest_audit_time else True)
        )

        curr_raw = ""
        curr_norm = ""

        if has_latest_conflict and not has_later_snapshot:
            # Equal-time conflict without independent later snapshot:
            # Audit-ID sorting must not determine whether B or C is current.
            warnings.append(
                f"Current value for {norm_uid} field '{field_name}' is unknown due to unresolved "
                f"equal-timestamp conflict at {latest_audit_time.isoformat()}."
            )
        elif valid_snapshot is not None and (
            has_later_snapshot or (not has_latest_conflict and valid_snapshot.updated_at >= latest_audit_time)
        ):
            # Snapshot is later than (or equal to unconflicted) audit changes
            curr_raw = snapshot_val
            curr_norm = normalizer(curr_raw)
            snap_prov = IdentifierProvenance(
                source_type=SourceType.SNAPSHOT,
                source_file="user_identities.csv",
                source_id=None,
                source_locator=f"user_id:{norm_uid}",
                field_name=field_name,
                raw_value=curr_raw,
                normalized_value=curr_norm,
                timestamp=valid_snapshot.updated_at,
                change_type="CURRENT_SNAPSHOT",
                validity_start=latest_audit_time,
                validity_end=None,
            )
            all_provenance.append(snap_prov)
            if curr_raw:
                current_identifiers[field_name] = curr_raw
                normalized_current_identifiers[field_name] = curr_norm
            if last_log is not None and normalizer(snapshot_val) != normalizer(last_log.new_value):
                warnings.append(
                    f"Discrepancy for {norm_uid} field '{field_name}': snapshot value '{snapshot_val}' "
                    f"at {valid_snapshot.updated_at} differs from latest audit log '{last_log.new_value}' "
                    f"at {last_log.event_time}."
                )
        elif last_log is not None and not has_latest_conflict:
            # Audit log is newer than snapshot (or no snapshot) and unconflicted
            curr_raw = last_log.new_value.strip()
            curr_norm = normalizer(curr_raw)
            if curr_raw:
                current_identifiers[field_name] = curr_raw
                normalized_current_identifiers[field_name] = curr_norm
            if snapshot_val:
                snap_prov = IdentifierProvenance(
                    source_type=SourceType.SNAPSHOT,
                    source_file="user_identities.csv",
                    source_id=None,
                    source_locator=f"user_id:{norm_uid}",
                    field_name=field_name,
                    raw_value=snapshot_val,
                    normalized_value=normalizer(snapshot_val),
                    timestamp=valid_snapshot.updated_at,
                    change_type="HISTORICAL_SNAPSHOT",
                    validity_start=None,
                    validity_end=last_log.event_time,
                )
                all_provenance.append(snap_prov)
                historical_intervals.append(
                    IdentifierInterval(
                        field_name=field_name,
                        raw_value=snapshot_val,
                        normalized_value=normalizer(snapshot_val),
                        is_current_at_cutoff=False,
                        validity_start=None,
                        validity_end=last_log.event_time,
                        sources=[snap_prov],
                    )
                )

        # For each transition's new_value
        for i, l in enumerate(ordered_field_logs):
            raw_new = l.new_value.strip()
            if not raw_new:
                continue
            norm_new = normalizer(raw_new)
            v_start = l.event_time
            if i + 1 < len(ordered_field_logs):
                v_end = ordered_field_logs[i + 1].event_time
            elif valid_snapshot is not None and valid_snapshot.updated_at > l.event_time:
                v_end = valid_snapshot.updated_at
            else:
                v_end = None

            prov = IdentifierProvenance(
                source_type=SourceType.AUDIT_LOG,
                source_file="user_audit_log.csv",
                source_id=l.audit_id,
                source_locator=f"audit_id:{l.audit_id}",
                field_name=field_name,
                raw_value=raw_new,
                normalized_value=norm_new,
                timestamp=l.event_time,
                change_type="NEW_VALUE",
                validity_start=v_start,
                validity_end=v_end,
            )
            all_provenance.append(prov)

            is_the_current_value = (
                curr_raw != ""
                and norm_new == curr_norm
                and (i == len(ordered_field_logs) - 1)
                and not has_latest_conflict
                and not (valid_snapshot and valid_snapshot.updated_at > l.event_time and normalizer(snapshot_val) != norm_new)
            )

            if not is_the_current_value:
                historical_intervals.append(
                    IdentifierInterval(
                        field_name=field_name,
                        raw_value=raw_new,
                        normalized_value=norm_new,
                        is_current_at_cutoff=False,
                        validity_start=v_start,
                        validity_end=v_end,
                        sources=[prov],
                    )
                )

    # 5. Deduplicate historical identifiers while preserving provenance
    curr_norm_set = set(normalized_current_identifiers.values())
    hist_by_key: dict[tuple[str, str], dict[str, Any]] = {}

    for interval in historical_intervals:
        if not interval.normalized_value:
            continue
        if interval.normalized_value in curr_norm_set and interval.validity_end is None:
            continue

        key = (interval.field_name, interval.normalized_value)
        if key not in hist_by_key:
            hist_by_key[key] = {
                "field_name": interval.field_name,
                "raw_value": interval.raw_value,
                "normalized_value": interval.normalized_value,
                "validity_start": interval.validity_start,
                "validity_end": interval.validity_end,
                "sources": [s.model_dump() for s in interval.sources],
            }
        else:
            existing = hist_by_key[key]
            existing_src_ids = {
                (s.get("source_file"), s.get("source_locator"), s.get("change_type"))
                for s in existing["sources"]
            }
            for s in interval.sources:
                s_dict = s.model_dump()
                s_key = (s_dict.get("source_file"), s_dict.get("source_locator"), s_dict.get("change_type"))
                if s_key not in existing_src_ids:
                    existing["sources"].append(s_dict)
                    existing_src_ids.add(s_key)

    sorted_historical = sorted(
        hist_by_key.values(),
        key=lambda x: (x["field_name"], x["normalized_value"], str(x["validity_end"] or "")),
    )

    # 6. Aggregate deterministic searchable identifiers
    searchable_set: set[str] = {norm_uid}
    for k, v in current_identifiers.items():
        if k != "name" and v:
            searchable_set.add(v)
    for k, v in normalized_current_identifiers.items():
        if k != "name" and v:
            searchable_set.add(v)
    for h in sorted_historical:
        if h["raw_value"]:
            searchable_set.add(h["raw_value"])
        if h["normalized_value"]:
            searchable_set.add(h["normalized_value"])

    # Ensure every supported identifier from eligible logs and snapshot is preserved
    for log in eligible_logs:
        if log.old_value.strip():
            raw_v = log.old_value.strip()
            searchable_set.add(raw_v)
            if log.field_name in FIELD_NORMALIZERS:
                norm_v = FIELD_NORMALIZERS[log.field_name](raw_v)
                if norm_v:
                    searchable_set.add(norm_v)
        if log.new_value.strip():
            raw_v = log.new_value.strip()
            searchable_set.add(raw_v)
            if log.field_name in FIELD_NORMALIZERS:
                norm_v = FIELD_NORMALIZERS[log.field_name](raw_v)
                if norm_v:
                    searchable_set.add(norm_v)

    if valid_snapshot is not None:
        for fn in ("email", "phone", "email_hash"):
            val = getattr(valid_snapshot, fn, "").strip()
            if val:
                searchable_set.add(val)
                norm_v = FIELD_NORMALIZERS[fn](val)
                if norm_v:
                    searchable_set.add(norm_v)

    sorted_searchable = sorted(searchable_set)
    sorted_audit_ids = sorted(supporting_audit_ids)
    sorted_provenance = sorted(
        [p.model_dump() for p in all_provenance],
        key=lambda x: (x["field_name"], x["timestamp"].isoformat(), x["source_locator"]),
    )

    return UserHistoryTimeline(
        user_id=norm_uid,
        current_identifiers=current_identifiers,
        normalized_current_identifiers=normalized_current_identifiers,
        historical_identifiers=sorted_historical,
        searchable_identifiers=sorted_searchable,
        supporting_audit_ids=sorted_audit_ids,
        provenance=sorted_provenance,
        applicable_timestamps=applicable_timestamps,
        warnings=sorted(warnings),
        conflicts=sorted(conflicts),
    )
