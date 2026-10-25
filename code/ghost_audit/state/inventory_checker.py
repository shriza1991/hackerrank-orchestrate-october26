"""Scoped inventory checking interface for grounded proof of absence."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, Sequence

from ghost_audit.retrieval.models import ScopedInventory, SelectedObservation
from ghost_audit.state.models import ScopedAbsenceCheck


class ScopedInventoryChecker:
    """Verifies absence using complete scoped table inventories or negative lookups.

    Absence is NEVER assumed from missing retrieval results. It requires explicit,
    grounded proof from a scoped inventory or negative readback lookup at or before audit_at.
    """

    @staticmethod
    def check_table_absence(
        scoped_inventories: Sequence[ScopedInventory],
        system_id: str,
        target_resource_id: Optional[str],
        subject_identifiers: Sequence[str],
        audit_at: datetime,
        store_locator: Optional[str] = None,
    ) -> Optional[ScopedAbsenceCheck]:
        """Perform a grounded absence check across scoped inventories for a store copy."""
        relevant_invs = [
            inv for inv in scoped_inventories
            if inv.system_id == system_id and inv.timestamp <= audit_at
        ]
        if store_locator:
            s_loc = store_locator.lower()
            relevant_invs = [
                inv for inv in relevant_invs
                if (inv.source_locator and (inv.source_locator.lower() in s_loc or s_loc in inv.source_locator.lower()))
                or (inv.extracted_facts.get("table_name") and (str(inv.extracted_facts["table_name"]).lower() in s_loc or s_loc in str(inv.extracted_facts["table_name"]).lower()))
            ]

        # Sort chronologically, taking the latest pre-cutoff inventory
        sorted_invs = sorted(relevant_invs, key=lambda i: i.timestamp, reverse=True)

        for inv in sorted_invs:
            facts = inv.extracted_facts or {}
            table_name = facts.get("table_name") or inv.source_locator or "unknown_table"

            # Check 1: Explicit zero-count collection (e.g., count: 0 in snapshot)
            if facts.get("count") == 0:
                return ScopedAbsenceCheck(
                    system_id=system_id,
                    resource_id=target_resource_id,
                    source_id=inv.source_id,
                    source_locator=inv.source_locator,
                    timestamp=inv.timestamp,
                    table_scope=table_name,
                    checked_identifiers=list(subject_identifiers),
                    membership_result="ABSENT",
                    completeness_basis=f"Empty scoped collection (count=0) in {inv.source_id} proves absence at {inv.timestamp.isoformat()}.",
                )

            # Check 2: Table inventory with full row dumps
            table_rows = facts.get("table_rows")
            if isinstance(table_rows, list):
                # Search all rows for target_resource_id or subject_identifiers
                found_match = False
                for row in table_rows:
                    if isinstance(row, dict):
                        row_vals = {str(v).strip().lower() for v in row.values() if v is not None}
                        if target_resource_id and target_resource_id.lower() in row_vals:
                            found_match = True
                            break
                        for ident in subject_identifiers:
                            if ident.lower() in row_vals:
                                found_match = True
                                break
                    elif isinstance(row, str):
                        if target_resource_id and target_resource_id.lower() in row.lower():
                            found_match = True
                            break
                        for ident in subject_identifiers:
                            if ident.lower() in row.lower():
                                found_match = True
                                break

                if not found_match:
                    return ScopedAbsenceCheck(
                        system_id=system_id,
                        resource_id=target_resource_id,
                        source_id=inv.source_id,
                        source_locator=inv.source_locator,
                        timestamp=inv.timestamp,
                        table_scope=table_name,
                        checked_identifiers=list(subject_identifiers),
                        membership_result="ABSENT",
                        completeness_basis=(
                            f"Complete table dump ({len(table_rows)} rows) in {inv.source_id} "
                            f"confirmed subject record/identifier is not present."
                        ),
                    )
                else:
                    return ScopedAbsenceCheck(
                        system_id=system_id,
                        resource_id=target_resource_id,
                        source_id=inv.source_id,
                        source_locator=inv.source_locator,
                        timestamp=inv.timestamp,
                        table_scope=table_name,
                        checked_identifiers=list(subject_identifiers),
                        membership_result="PRESENT",
                        completeness_basis=f"Table dump in {inv.source_id} contains matching record for subject.",
                    )

        return None

    @staticmethod
    def check_negative_lookup(
        selected_observations: Sequence[SelectedObservation],
        system_id: str,
        target_resource_id: Optional[str],
        audit_at: datetime,
        store_locator: Optional[str] = None,
        subject_identifiers: Sequence[str] = (),
    ) -> Optional[ScopedAbsenceCheck]:
        """Check for explicit negative lookups (404, not_found, 0 rows returned) in observations."""
        from ghost_audit.state.timestamp_interpreter import SourceAwareTimestampInterpreter

        candidates: list[tuple[datetime, ScopedAbsenceCheck]] = []

        for so in selected_observations:
            obs = so.observation
            if obs.system_id != system_id:
                continue

            # Validate observation timing against cutoff
            ts_info = SourceAwareTimestampInterpreter.interpret_observation(obs, audit_at)
            if not ts_info.is_eligible or ts_info.state_observation_time > audit_at:
                continue

            facts = obs.extracted_facts or {}

            # Grounded applicability to exact target_resource_id or subject query
            obs_r_id = obs.resource_id or facts.get("resource_id") or facts.get("query_resource_id")
            if target_resource_id:
                if obs_r_id:
                    if obs_r_id.strip().lower() != target_resource_id.strip().lower():
                        continue
                else:
                    loc = (obs.source_locator or "").lower()
                    if target_resource_id.lower() not in loc:
                        if not any(ident.lower() in loc for ident in subject_identifiers):
                            continue

            # Grounded store/copy scope check
            if store_locator:
                s_loc = store_locator.lower()
                obs_loc = (obs.source_locator or "").lower()
                # Primary lookup cannot establish replica absence
                if "primary" in s_loc and any(r in obs_loc for r in ["replica", "failover", "reporting"]):
                    continue
                if any(r in s_loc for r in ["replica", "failover", "reporting"]):
                    if "primary" in obs_loc and not any(r in obs_loc for r in ["replica", "failover", "reporting"]):
                        continue

            # Negative readback markers
            is_404 = facts.get("status_code") == 404 or facts.get("http_status") == 404
            is_not_found = (
                facts.get("result") in {"NOT_FOUND", "ZERO_ROWS", "EMPTY"}
                or facts.get("rows_returned") == 0
                or "404 Not Found" in str(facts)
                or "not found" in str(facts.get("message", "")).lower()
            )
            if is_404 or is_not_found:
                query_args = facts.get("query_args") or facts.get("params") or {
                    k: v for k, v in facts.items() if k in {"resource_id", "email", "user_id", "id", "status_code", "result"}
                }
                check = ScopedAbsenceCheck(
                    system_id=system_id,
                    resource_id=target_resource_id or obs_r_id,
                    source_id=obs.evidence_id,
                    source_locator=obs.source_locator,
                    timestamp=ts_info.state_observation_time,
                    table_scope=obs.source_locator or "query_readback",
                    checked_identifiers=list(subject_identifiers),
                    membership_result="ABSENT",
                    completeness_basis=(
                        f"Explicit negative readback lookup for {target_resource_id or obs_r_id} in {obs.evidence_id} "
                        f"returned not-found / zero rows at {ts_info.state_observation_time.isoformat()} "
                        f"(capture time: {obs.capture_time.isoformat()}, query: {query_args})."
                    ),
                )
                candidates.append((ts_info.state_observation_time, check))

        if not candidates:
            return None

        # Sort by latest observation time descending
        candidates.sort(key=lambda c: c[0], reverse=True)
        return candidates[0][1]

