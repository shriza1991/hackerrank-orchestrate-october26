"""Resource-state reconstruction engine establishing grounded state at audit cutoff."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime
from typing import Any, Optional, Sequence

from ghost_audit.retrieval.models import CaseEvidencePacket, SelectedActivity, SelectedObservation
from ghost_audit.state.inventory_checker import ScopedInventoryChecker
from ghost_audit.state.models import (
    CaseStateReconstruction,
    CopyKey,
    CopyStateAssessment,
    CopyType,
    ExistenceState,
    FieldObservation,
    FieldStatus,
    ProcessObservation,
    ProcessState,
    ResourceStateAggregate,
    RestoreObservation,
    RestoreState,
    ScopedAbsenceCheck,
    StateDiagnostics,
    StateTimelineEvent,
    SubjectAttribution,
)
from ghost_audit.state.timestamp_interpreter import SourceAwareTimestampInterpreter


def derive_copy_type(
    system_id: str,
    source_locator: Optional[str] = None,
    facts: Optional[dict[str, Any]] = None,
    scope_context: Optional[dict[str, Any]] = None,
) -> tuple[CopyType, Optional[str]]:
    """Determine copy classification and physical store identity.

    Returns:
        (CopyType, physical_store_name)
    """
    sys_lower = (system_id or "").lower()
    loc_lower = (source_locator or "").lower()
    facts_dict = facts or {}
    scope_ctx = scope_context or {}

    # Extract explicit topology
    topo = str(scope_ctx.get("topology") or scope_ctx.get("table_topology") or facts_dict.get("topology") or "").lower()
    combined = f"{sys_lower} {loc_lower} {topo}"

    if "read_replica" in combined:
        copy_type = CopyType.READ_REPLICA
    elif "failover_replica" in combined or "failover" in combined:
        copy_type = CopyType.FAILOVER_REPLICA
    elif "reporting_replica" in combined or "reporting" in combined:
        copy_type = CopyType.REPORTING_REPLICA
    elif "replica_" in combined or "regional" in combined:
        copy_type = CopyType.REGIONAL_REPLICA
    elif "primary" in combined:
        copy_type = CopyType.PRIMARY
    elif "search" in sys_lower or "search" in loc_lower:
        copy_type = CopyType.SEARCH_INDEX
    elif "export" in sys_lower or "export" in loc_lower:
        copy_type = CopyType.EXPORT_ARCHIVE
    elif "attachment" in sys_lower or "attachment" in loc_lower:
        copy_type = CopyType.SUPPORT_ATTACHMENT
    elif "backup" in sys_lower or "backup" in loc_lower:
        copy_type = CopyType.DATABASE_BACKUP
    elif "connector" in loc_lower or "sync" in loc_lower:
        copy_type = CopyType.SYSTEM_PROCESS
    else:
        copy_type = CopyType.PRIMARY

    # Physical store name: remove row/page qualifiers (e.g. table:customer_data_primary:row:1 -> customer_data_primary)
    store_name = facts_dict.get("table_name")
    if not store_name and source_locator:
        s = source_locator
        s = re.sub(r':row:\d+.*$', '', s)
        s = re.sub(r':page:\d+.*$', '', s)
        s = re.sub(r'\[\d+\].*$', '', s)
        if s.startswith("table:"):
            store_name = s[len("table:"):]
        elif s.startswith("config:"):
            store_name = s[len("config:"):]
        else:
            store_name = s
    elif not store_name:
        store_name = f"{sys_lower}_store"

    return copy_type, store_name


def extract_field_observations(facts: dict[str, Any]) -> dict[str, FieldObservation]:
    """Extract and categorize field-level identifier and PII observations."""
    fields: dict[str, FieldObservation] = {}
    merged_facts = dict(facts)

    # 1. Embedded record_json (string or dict)
    record_json_val = facts.get("record_json")
    if isinstance(record_json_val, str) and record_json_val.strip():
        stripped = record_json_val.strip()
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                merged_facts.update(parsed)
            elif isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        merged_facts.update(item)
        except json.JSONDecodeError:
            pass
    elif isinstance(record_json_val, dict):
        merged_facts.update(record_json_val)

    # 2. Extract nested objects if any (e.g. user, customer, profile, data)
    for parent_key in ["customer", "user", "profile", "data", "metadata"]:
        parent_val = merged_facts.get(parent_key)
        if isinstance(parent_val, dict):
            for k, v in parent_val.items():
                if k not in merged_facts:
                    merged_facts[k] = v

    # 3. Check free-text fields for embedded emails/phones (e.g. message, body, text, details, payload)
    free_texts = []
    for txt_key in ["message", "body", "details", "query", "text", "payload", "content"]:
        if txt_key in merged_facts and isinstance(merged_facts[txt_key], str):
            free_texts.append(merged_facts[txt_key])
    combined_text = " ".join(free_texts)
    if combined_text:
        email_match = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', combined_text)
        if email_match and "email" not in merged_facts:
            merged_facts["email"] = email_match.group(0)
        phone_match = re.search(r'\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}', combined_text)
        if phone_match and "phone" not in merged_facts:
            merged_facts["phone"] = phone_match.group(0)

    facts = merged_facts
    is_claimed_redacted = (
        facts.get("redacted") is True
        or facts.get("is_redacted") is True
        or "redacted" in str(facts.get("account_status", "")).lower()
    )

    # 1. Full name
    name_val = None
    for k in ["full_name", "name", "customer_name"]:
        if k in facts:
            name_val = facts[k]
            break
    if name_val is not None:
        name_str = str(name_val).strip()
        if not name_str:
            status = FieldStatus.EMPTY
        elif "***" in name_str or name_str.lower().startswith("anon_"):
            status = FieldStatus.MASKED
        elif "unreadable" in name_str.lower():
            status = FieldStatus.UNREADABLE
        else:
            status = FieldStatus.EXPOSED
        claim_label = "CLAIMED_REDACTED_BUT_NAME_EXPOSED" if is_claimed_redacted and status == FieldStatus.EXPOSED else None
        fields["name"] = FieldObservation(
            field_name="name",
            status=status,
            raw_value=name_str,
            is_direct_pii=(status == FieldStatus.EXPOSED),
            is_stable_ref=False,
            claim_label=claim_label,
        )
    elif "full_name" in facts or "name" in facts or "customer_name" in facts:
        fields["name"] = FieldObservation(
            field_name="name",
            status=FieldStatus.NULL,
            raw_value=None,
            is_direct_pii=False,
            is_stable_ref=False,
        )

    # 2. Email
    email_val = None
    for k in ["email", "customer_email", "requester_email"]:
        if k in facts:
            email_val = facts[k]
            break
    if email_val is not None:
        email_str = str(email_val).strip()
        if not email_str:
            status = FieldStatus.EMPTY
        elif "***" in email_str or email_str.lower().startswith("anon_"):
            status = FieldStatus.MASKED
        elif "unreadable" in email_str.lower():
            status = FieldStatus.UNREADABLE
        else:
            status = FieldStatus.EXPOSED
        claim_label = "CLAIMED_REDACTED_BUT_EMAIL_EXPOSED" if is_claimed_redacted and status == FieldStatus.EXPOSED else None
        fields["email"] = FieldObservation(
            field_name="email",
            status=status,
            raw_value=email_str,
            is_direct_pii=(status == FieldStatus.EXPOSED),
            is_stable_ref=False,
            claim_label=claim_label,
        )
    elif "email" in facts or "customer_email" in facts or "requester_email" in facts:
        fields["email"] = FieldObservation(
            field_name="email",
            status=FieldStatus.NULL,
            raw_value=None,
            is_direct_pii=False,
            is_stable_ref=False,
        )

    # 3. Phone
    phone_val = None
    for k in ["phone", "phone_number", "customer_phone"]:
        if k in facts:
            phone_val = facts[k]
            break
    if phone_val is not None:
        phone_str = str(phone_val).strip()
        if not phone_str:
            status = FieldStatus.EMPTY
        elif "***" in phone_str:
            status = FieldStatus.MASKED
        elif "unreadable" in phone_str.lower():
            status = FieldStatus.UNREADABLE
        else:
            status = FieldStatus.EXPOSED
        fields["phone"] = FieldObservation(
            field_name="phone",
            status=status,
            raw_value=phone_str,
            is_direct_pii=(status == FieldStatus.EXPOSED),
            is_stable_ref=False,
        )
    elif "phone" in facts or "phone_number" in facts or "customer_phone" in facts:
        fields["phone"] = FieldObservation(
            field_name="phone",
            status=FieldStatus.NULL,
            raw_value=None,
            is_direct_pii=False,
            is_stable_ref=False,
        )

    # 4. Email hash
    hash_val = None
    if "email_hash" in facts:
        hash_val = facts["email_hash"]
    if hash_val is not None:
        hash_str = str(hash_val).strip()
        if not hash_str:
            status = FieldStatus.EMPTY
        else:
            status = FieldStatus.EXPOSED
        fields["email_hash"] = FieldObservation(
            field_name="email_hash",
            status=status,
            raw_value=hash_str,
            is_direct_pii=True,
            is_stable_ref=False,
        )
    elif "email_hash" in facts:
        fields["email_hash"] = FieldObservation(
            field_name="email_hash",
            status=FieldStatus.NULL,
            raw_value=None,
            is_direct_pii=False,
            is_stable_ref=False,
        )

    # 5. Stable user ID / Subject reference
    user_val = None
    for k in ["user_id", "subject_reference", "subject_id"]:
        if k in facts:
            user_val = facts[k]
            break
    if user_val is not None:
        user_str = str(user_val).strip()
        if user_str.startswith("user_"):
            status = FieldStatus.RETAINED_STABLE_REF
            is_stable = True
            is_direct = False
        elif not user_str:
            status = FieldStatus.EMPTY
            is_stable = False
            is_direct = False
        else:
            status = FieldStatus.EXPOSED
            is_stable = False
            is_direct = True
        fields["user_id"] = FieldObservation(
            field_name="user_id",
            status=status,
            raw_value=user_str,
            is_direct_pii=is_direct,
            is_stable_ref=is_stable,
        )
    elif "user_id" in facts or "subject_reference" in facts or "subject_id" in facts:
        fields["user_id"] = FieldObservation(
            field_name="user_id",
            status=FieldStatus.NULL,
            raw_value=None,
            is_direct_pii=False,
            is_stable_ref=False,
        )

    return fields


def extract_process_and_restore_state(facts: dict[str, Any]) -> tuple[ProcessState, RestoreState]:
    """Extract operational process configuration and backup restore states."""
    proc_state = ProcessState.NOT_APPLICABLE
    rest_state = RestoreState.NOT_APPLICABLE

    # Process settings
    for key in ["connector_status", "sync_status", "process_state", "data_flow_state", "state"]:
        if key in facts and facts[key] is not None:
            v_str = str(facts[key]).strip()
            if re.search(r"\b(disabled|paused|stopped|inactive|blocked)\b", v_str, re.IGNORECASE):
                proc_state = ProcessState.DISABLED
                break
            elif re.search(r"\b(enabled|active|running|streaming)\b", v_str, re.IGNORECASE):
                proc_state = ProcessState.ENABLED
                break

    # Restore permissions
    for key in ["restore_allowed", "restore_status", "restore_permission", "restore_policy"]:
        if key in facts and facts[key] is not None:
            v_val = facts[key]
            if v_val is False or (isinstance(v_val, str) and re.search(r"\b(blocked|disabled|prohibited|denied)\b", v_val, re.IGNORECASE)):
                rest_state = RestoreState.BLOCKED
                break
            elif v_val is True or (isinstance(v_val, str) and re.search(r"\b(allowed|enabled|permitted)\b", v_val, re.IGNORECASE)):
                rest_state = RestoreState.ALLOWED
                break

    return proc_state, rest_state


class ResourceStateEngine:
    """Core deterministic engine reconstructing resource states at audit cutoff."""

    def __init__(self, audit_at: datetime) -> None:
        self.audit_at = audit_at

    def reconstruct_case_state(
        self,
        packet: CaseEvidencePacket,
    ) -> CaseStateReconstruction:
        """Reconstruct the grounded resource state from a CaseEvidencePacket."""
        start_time = time.perf_counter()

        if packet.is_blocked:
            diagnostics = StateDiagnostics(
                case_id=packet.case_id,
                audit_at=packet.audit_at,
                coverage_scope=getattr(packet.diagnostics, "coverage_scope", "UNKNOWN"),
                unreadable_or_failed_files=list(getattr(packet.diagnostics, "failed_files", [])),
                deferred_files=list(getattr(packet.diagnostics, "deferred_files", [])),
                execution_time_ms=(time.perf_counter() - start_time) * 1000,
            )
            return CaseStateReconstruction(
                case_id=packet.case_id,
                audit_at=packet.audit_at,
                is_blocked=True,
                blocking_reason=packet.blocking_reason,
                is_diagnostic_mode=(packet.intent_decision == "BYPASS_DIAGNOSTIC"),
                subject_id=packet.stable_subject_reference,
                resources={},
                active_processes=[],
                restore_risks=[],
                scoped_absence_checks=[],
                diagnostics=diagnostics,
            )

        # 1. Group observations and activities by resource copy
        copy_assessments: dict[str, CopyStateAssessment] = {}
        resource_copies_map: dict[str, list[str]] = {}  # canonical_key -> list[copy_str]
        all_absence_checks: list[ScopedAbsenceCheck] = []
        conflicts_detected: list[str] = []
        recreations_detected: list[str] = []
        active_processes: list[str] = []
        restore_risks: list[str] = []
        process_observations: list[ProcessObservation] = []
        restore_observations: list[RestoreObservation] = []

        # Process selected observations
        for so in packet.selected_observations:
            obs = so.observation
            ts_info = SourceAwareTimestampInterpreter.interpret_observation(obs, self.audit_at)
            if not ts_info.is_eligible:
                continue

            facts = obs.extracted_facts or {}

            # Check observation type
            is_404 = facts.get("status_code") == 404 or facts.get("http_status") == 404
            is_not_found = (
                facts.get("result") in {"NOT_FOUND", "ZERO_ROWS", "EMPTY"}
                or facts.get("rows_returned") == 0
                or "404 Not Found" in str(facts)
                or "not found" in str(facts.get("message", "")).lower()
            )
            is_negative_lookup = is_404 or is_not_found

            is_pure_inventory_metadata = (
                obs.observation_type in {"INVENTORY_SCOPE", "TABLE_INVENTORY"}
                and "table_rows" not in facts
                and "resource_id" not in facts
                and not obs.resource_id
            )
            if is_pure_inventory_metadata:
                continue

            sys_id = obs.system_id or "unknown"
            r_id = obs.resource_id or (
                facts.get("resource_id") or "unspecified_resource"
            )
            c_type, store_loc = derive_copy_type(sys_id, obs.source_locator, facts, obs.scope_context)

            copy_key = CopyKey(
                system_id=sys_id,
                resource_id=r_id,
                copy_type=c_type,
                store_locator=store_loc,
            )
            copy_str = str(copy_key)
            canon_key = f"{sys_id}:{r_id}"
            resource_copies_map.setdefault(canon_key, []).append(copy_str)

            fields = extract_field_observations(facts) if not is_negative_lookup else {}
            proc_st, rest_st = extract_process_and_restore_state(facts)

            # Determine attribution
            has_matching_ident = any(
                ident in packet.subject_identifiers
                for ident in so.matched_identifiers or obs.subject_references
            )
            attr = SubjectAttribution.SUPPORTED if has_matching_ident else SubjectAttribution.NOT_ESTABLISHED

            observed_exist = ExistenceState.ABSENT if is_negative_lookup else ExistenceState.PRESENT

            # Create timeline event
            event = StateTimelineEvent(
                event_id=f"obs_{obs.evidence_id}_{obs.source_locator or ''}",
                event_time=ts_info.state_observation_time,
                event_type=obs.observation_type or ("NEGATIVE_LOOKUP" if is_negative_lookup else "OBSERVED_RECORD"),
                source_id=obs.evidence_id,
                source_type="EVIDENCE_FILE",
                source_locator=obs.source_locator,
                is_claim=False,
                observed_existence=observed_exist,
                time_role_basis=ts_info.time_role_basis,
                facts=facts,
            )

            if copy_str not in copy_assessments:
                copy_assessments[copy_str] = CopyStateAssessment(
                    copy_key=copy_key,
                    existence=observed_exist,
                    attribution=attr,
                    fields=fields,
                    process_state=proc_st,
                    restore_state=rest_st,
                    last_observation_time=ts_info.state_observation_time,
                    supporting_observations=[obs.evidence_id],
                    timeline=[event],
                )
            else:
                curr = copy_assessments[copy_str]
                curr.timeline.append(event)
                if obs.evidence_id not in curr.supporting_observations:
                    curr.supporting_observations.append(obs.evidence_id)
                # Later observation supersedes earlier observation
                if curr.last_observation_time is None or ts_info.state_observation_time > curr.last_observation_time:
                    curr.last_observation_time = ts_info.state_observation_time
                    curr.existence = observed_exist
                    curr.fields.update(fields)
                    if proc_st != ProcessState.NOT_APPLICABLE:
                        curr.process_state = proc_st
                    if rest_st != RestoreState.NOT_APPLICABLE:
                        curr.restore_state = rest_st
                elif ts_info.state_observation_time == curr.last_observation_time:
                    if observed_exist != curr.existence:
                        curr.existence = ExistenceState.CONFLICTED
            if proc_st in {ProcessState.ENABLED, ProcessState.DISABLED}:
                p_id = facts.get("process_id") or facts.get("connector_id") or r_id
                target_r = facts.get("target_resource_id") or facts.get("target_resource") or r_id
                process_observations.append(
                    ProcessObservation(
                        process_id=p_id,
                        system_id=sys_id,
                        target_resource=target_r,
                        target_copy=copy_str,
                        process_type=facts.get("process_type") or "DATA_FLOW",
                        state=proc_st,
                        is_claim=False,
                        evidence_id=obs.evidence_id,
                        timestamp=ts_info.state_observation_time,
                        details=str(facts.get("details") or facts.get("message") or ""),
                    )
                )

            if rest_st in {RestoreState.ALLOWED, RestoreState.BLOCKED}:
                b_id = facts.get("backup_id") or r_id
                target_r = facts.get("target_resource_id") or facts.get("target_resource") or r_id
                restore_observations.append(
                    RestoreObservation(
                        backup_id=b_id,
                        system_id=sys_id,
                        target_resource=target_r,
                        target_copy=copy_str,
                        restore_state=rest_st,
                        is_claim=False,
                        evidence_id=obs.evidence_id,
                        timestamp=ts_info.state_observation_time,
                        details=str(facts.get("details") or facts.get("message") or ""),
                    )
                )

        # Process system activity claims
        for sa in packet.selected_activities:
            act_event = sa
            ts_info = SourceAwareTimestampInterpreter.interpret_activity(act_event, self.audit_at)
            if not ts_info.is_eligible:
                continue

            sys_id = act_event.target_system or "unknown"
            r_id = act_event.resource_id
            canon_key = f"{sys_id}:{r_id}"

            # Timeline event for claim
            claim_event = StateTimelineEvent(
                event_id=f"act_{act_event.activity_id}",
                event_time=act_event.event_time,
                event_type=act_event.event_type,
                source_id=act_event.activity_id,
                source_type="SYSTEM_ACTIVITY",
                is_claim=True,
                claim_result=act_event.reported_result,
                time_role_basis=ts_info.time_role_basis,
                facts={"details": act_event.details, "event_type": act_event.event_type},
            )

            # Check for process disable or restore block claims
            if act_event.event_type == "DISABLE_DATA_FLOW":
                if act_event.reported_result == "SUCCESS":
                    active_processes.append(f"{act_event.activity_id}:CLAIMED_DISABLED")
                process_observations.append(
                    ProcessObservation(
                        process_id=act_event.resource_id,
                        system_id=sys_id,
                        target_resource=act_event.resource_id,
                        process_type="DATA_FLOW",
                        state=ProcessState.DISABLED if act_event.reported_result == "SUCCESS" else ProcessState.UNKNOWN,
                        is_claim=True,
                        claim_result=act_event.reported_result,
                        evidence_id=act_event.activity_id,
                        timestamp=act_event.event_time,
                        details=act_event.details,
                    )
                )
            elif act_event.event_type in {"RESTORE", "SYNC", "STREAM_SYNC"}:
                active_processes.append(f"{act_event.activity_id}:{act_event.event_type}")

            if act_event.event_type == "BLOCK_RESTORE":
                if act_event.reported_result == "SUCCESS":
                    restore_risks.append(f"{act_event.activity_id}:CLAIMED_BLOCKED")
                restore_observations.append(
                    RestoreObservation(
                        backup_id=act_event.resource_id,
                        system_id=sys_id,
                        target_resource=act_event.resource_id,
                        restore_state=RestoreState.BLOCKED if act_event.reported_result == "SUCCESS" else RestoreState.UNKNOWN,
                        is_claim=True,
                        claim_result=act_event.reported_result,
                        evidence_id=act_event.activity_id,
                        timestamp=act_event.event_time,
                        details=act_event.details,
                    )
                )

            # Attach claim to copy assessments
            relevant_copies = resource_copies_map.get(canon_key, [])
            if not relevant_copies:
                # Synthesize copy key for activity target
                c_key = CopyKey(system_id=sys_id, resource_id=r_id, copy_type=CopyType.PRIMARY)
                c_str = str(c_key)
                resource_copies_map.setdefault(canon_key, []).append(c_str)
                copy_assessments[c_str] = CopyStateAssessment(
                    copy_key=c_key,
                    existence=ExistenceState.UNKNOWN,
                    last_activity_time=act_event.event_time,
                    supporting_activities=[act_event.activity_id],
                    unverified_claims=[f"{act_event.event_type} {act_event.reported_result}"],
                    timeline=[claim_event],
                )
            else:
                for c_str in relevant_copies:
                    assessment = copy_assessments[c_str]
                    assessment.timeline.append(claim_event)
                    if act_event.activity_id not in assessment.supporting_activities:
                        assessment.supporting_activities.append(act_event.activity_id)
                    assessment.unverified_claims.append(f"{act_event.event_type} {act_event.reported_result}")
                    if assessment.last_activity_time is None or act_event.event_time >= assessment.last_activity_time:
                        assessment.last_activity_time = act_event.event_time

        # 2. Absence verification using scoped inventories and negative lookups
        for canon_key, copy_strs in list(resource_copies_map.items()):
            sys_id, r_id = canon_key.split(":", 1)

            # Check if any scoped inventories belong to a copy not yet observed (e.g. primary store inventory)
            for inv in packet.scoped_inventories:
                if inv.system_id == sys_id and inv.timestamp <= self.audit_at:
                    inv_facts = inv.extracted_facts or {}
                    inv_c_type, inv_store_loc_derived = derive_copy_type(sys_id, inv.source_locator, inv_facts)
                    inv_store_loc = inv_store_loc_derived or inv_facts.get("table_name") or inv.source_locator
                    inv_copy_key = CopyKey(
                        system_id=sys_id,
                        resource_id=r_id,
                        copy_type=inv_c_type,
                        store_locator=inv_store_loc,
                    )
                    inv_c_str = str(inv_copy_key)
                    if inv_c_str not in resource_copies_map[canon_key]:
                        inv_check = ScopedInventoryChecker.check_table_absence(
                            scoped_inventories=[inv],
                            system_id=sys_id,
                            target_resource_id=r_id,
                            subject_identifiers=packet.subject_identifiers,
                            audit_at=self.audit_at,
                            store_locator=inv_store_loc,
                        )
                        if inv_check and inv_check.membership_result == "ABSENT":
                            all_absence_checks.append(inv_check)
                            resource_copies_map[canon_key].append(inv_c_str)
                            ev_inv = StateTimelineEvent(
                                event_id=f"inv_abs_{inv_check.source_id}",
                                event_time=inv_check.timestamp,
                                event_type="SCOPED_INVENTORY_ABSENCE",
                                source_id=inv_check.source_id,
                                source_type="EVIDENCE_FILE",
                                source_locator=inv_check.source_locator,
                                observed_existence=ExistenceState.ABSENT,
                                time_role_basis=inv_check.completeness_basis,
                            )
                            copy_assessments[inv_c_str] = CopyStateAssessment(
                                copy_key=inv_copy_key,
                                existence=ExistenceState.ABSENT,
                                last_observation_time=inv_check.timestamp,
                                supporting_observations=[inv.source_id],
                                timeline=[ev_inv],
                            )

            for c_str in list(resource_copies_map[canon_key]):
                assessment = copy_assessments[c_str]

                # Check scoped table inventories
                absence_check = ScopedInventoryChecker.check_table_absence(
                    scoped_inventories=packet.scoped_inventories,
                    system_id=sys_id,
                    target_resource_id=r_id,
                    subject_identifiers=packet.subject_identifiers,
                    audit_at=self.audit_at,
                    store_locator=assessment.copy_key.store_locator,
                )
                if absence_check:
                    all_absence_checks.append(absence_check)
                    if absence_check.membership_result == "ABSENT":
                        ev_inv = StateTimelineEvent(
                            event_id=f"inv_abs_{absence_check.source_id}",
                            event_time=absence_check.timestamp,
                            event_type="SCOPED_INVENTORY_ABSENCE",
                            source_id=absence_check.source_id,
                            source_type="EVIDENCE_FILE",
                            source_locator=absence_check.source_locator,
                            observed_existence=ExistenceState.ABSENT,
                            time_role_basis=absence_check.completeness_basis,
                        )
                        assessment.timeline.append(ev_inv)

                        # If previously observed present, check chronological order
                        if assessment.existence == ExistenceState.PRESENT:
                            if assessment.last_observation_time and absence_check.timestamp > assessment.last_observation_time:
                                # Later scoped inventory proves record was deleted!
                                assessment.existence = ExistenceState.ABSENT
                                assessment.last_observation_time = absence_check.timestamp
                            elif assessment.last_observation_time and absence_check.timestamp < assessment.last_observation_time:
                                # Earlier inventory was absent, but later observation was PRESENT -> RECREATION!
                                assessment.is_recreated = True
                                assessment.recreation_details = (
                                    f"Observed present at {assessment.last_observation_time.isoformat()} "
                                    f"following verified absence in {absence_check.source_id} at {absence_check.timestamp.isoformat()}."
                                )
                                recreations_detected.append(f"{c_str}: {assessment.recreation_details}")
                            elif assessment.last_observation_time and absence_check.timestamp == assessment.last_observation_time:
                                assessment.existence = ExistenceState.CONFLICTED
                                conflict_msg = f"Equal-time contradictory observations at {absence_check.timestamp.isoformat()} in {c_str}: PRESENT vs ABSENT"
                                assessment.conflicts.append(conflict_msg)
                                conflicts_detected.append(conflict_msg)
                        else:
                            assessment.existence = ExistenceState.ABSENT
                            assessment.last_observation_time = absence_check.timestamp

                # Check negative lookups
                neg_lookup = ScopedInventoryChecker.check_negative_lookup(
                    selected_observations=packet.selected_observations,
                    system_id=sys_id,
                    target_resource_id=r_id,
                    audit_at=self.audit_at,
                    store_locator=assessment.copy_key.store_locator,
                    subject_identifiers=packet.subject_identifiers,
                )
                if neg_lookup:
                    all_absence_checks.append(neg_lookup)
                    if not any(ev.source_id == neg_lookup.source_id and ev.event_type == "NEGATIVE_LOOKUP" for ev in assessment.timeline):
                        ev_neg = StateTimelineEvent(
                            event_id=f"neg_lookup_{neg_lookup.source_id}",
                            event_time=neg_lookup.timestamp,
                            event_type="NEGATIVE_LOOKUP",
                            source_id=neg_lookup.source_id,
                            source_type="OBSERVATION",
                            source_locator=neg_lookup.source_locator,
                            observed_existence=ExistenceState.ABSENT,
                            time_role_basis=neg_lookup.completeness_basis,
                        )
                        assessment.timeline.append(ev_neg)

                    if assessment.existence == ExistenceState.PRESENT:
                        if assessment.last_observation_time and neg_lookup.timestamp > assessment.last_observation_time:
                            assessment.existence = ExistenceState.ABSENT
                            assessment.last_observation_time = neg_lookup.timestamp
                        elif assessment.last_observation_time and neg_lookup.timestamp < assessment.last_observation_time:
                            assessment.is_recreated = True
                            assessment.recreation_details = (
                                f"Observed present at {assessment.last_observation_time.isoformat()} "
                                f"following verified negative lookup in {neg_lookup.source_id} at {neg_lookup.timestamp.isoformat()}."
                            )
                            recreations_detected.append(f"{c_str}: {assessment.recreation_details}")
                        elif assessment.last_observation_time and neg_lookup.timestamp == assessment.last_observation_time:
                            assessment.existence = ExistenceState.CONFLICTED
                            conflict_msg = f"Equal-time contradictory observations at {neg_lookup.timestamp.isoformat()} in {c_str}: PRESENT vs ABSENT"
                            assessment.conflicts.append(conflict_msg)
                            conflicts_detected.append(conflict_msg)
                    else:
                        assessment.existence = ExistenceState.ABSENT
                        assessment.last_observation_time = neg_lookup.timestamp

                # Sort copy timeline chronologically
                assessment.timeline.sort(key=lambda ev: (ev.event_time, ev.event_id))

                # Historical conflict resolution:
                # Disagreements unresolved AT AUDIT_AT are determined by the latest events
                non_claim_events = [ev for ev in assessment.timeline if not ev.is_claim and ev.observed_existence is not None]
                if non_claim_events:
                    latest_t = max(ev.event_time for ev in non_claim_events)
                    latest_events = [ev for ev in non_claim_events if ev.event_time == latest_t]
                    states = {e.observed_existence for e in latest_events}
                    if len(states) > 1:
                        assessment.existence = ExistenceState.CONFLICTED
                        conflict_msg = f"Equal-time contradictory observations at {latest_t.isoformat()} in {c_str}: {states}"
                        if conflict_msg not in assessment.conflicts:
                            assessment.conflicts.append(conflict_msg)
                        if conflict_msg not in conflicts_detected:
                            conflicts_detected.append(conflict_msg)
                    else:
                        assessment.existence = next(iter(states))

        # 3. Build ResourceStateAggregate per canonical resource
        resources: dict[str, ResourceStateAggregate] = {}
        for canon_key, copy_strs in resource_copies_map.items():
            sys_id, r_id = canon_key.split(":", 1)
            copies_for_resource = {c_str: copy_assessments[c_str] for c_str in copy_strs}

            surviving = [c_str for c_str, c in copies_for_resource.items() if c.existence == ExistenceState.PRESENT]
            absent = [c_str for c_str, c in copies_for_resource.items() if c.existence == ExistenceState.ABSENT]
            has_conflicted = any(c.existence == ExistenceState.CONFLICTED for c in copies_for_resource.values())

            if surviving:
                agg_existence = ExistenceState.PRESENT
            elif has_conflicted:
                agg_existence = ExistenceState.CONFLICTED
            elif absent and len(absent) == len(copies_for_resource):
                agg_existence = ExistenceState.ABSENT
            else:
                agg_existence = ExistenceState.UNKNOWN

            # Check if any copy exposes direct PII
            has_pii = any(
                any(f.status == FieldStatus.EXPOSED for f in c.fields.values())
                for c in copies_for_resource.values()
            )

            has_recreation = any(c.is_recreated for c in copies_for_resource.values())

            # Data category derivation
            data_cat = "ACCOUNT_RECORD"
            if "analytics" in sys_id.lower() or "analytics" in r_id.lower():
                data_cat = "ANALYTICS_EVENT"
            elif "support" in sys_id.lower() or "ticket" in r_id.lower():
                data_cat = "SUPPORT_RECORD"
            elif "backup" in sys_id.lower() or "backup" in r_id.lower():
                data_cat = "DATABASE_BACKUP"
            elif "search" in sys_id.lower():
                data_cat = "SEARCH_INDEX_RECORD"
            elif "tombstone" in r_id.lower():
                data_cat = "ACCOUNT_TOMBSTONE"

            has_restore = any(c.restore_state == RestoreState.ALLOWED for c in copies_for_resource.values())
            if has_restore:
                restore_risks.append(f"{canon_key}:RESTORE_ALLOWED")

            resources[canon_key] = ResourceStateAggregate(
                system_id=sys_id,
                resource_id=r_id,
                canonical_key=canon_key,
                data_category=data_cat,
                aggregate_existence=agg_existence,
                copies=copies_for_resource,
                surviving_copies=surviving,
                absent_copies=absent,
                observed_pii_exposed=has_pii,
                has_recreation_risk=has_recreation,
                has_restore_risk=has_restore,
                conflicts=[conflict for c in copies_for_resource.values() for conflict in c.conflicts],
            )

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        diagnostics = StateDiagnostics(
            case_id=packet.case_id,
            audit_at=packet.audit_at,
            coverage_scope=getattr(packet.diagnostics, "coverage_scope", "KNOWN_COMPLETE"),
            total_resources_evaluated=len(resources),
            total_copies_evaluated=len(copy_assessments),
            conflicts_detected=conflicts_detected,
            unverified_claims_count=sum(len(c.unverified_claims) for c in copy_assessments.values()),
            recreations_detected=recreations_detected,
            stale_or_incomplete_warnings=list(packet.diagnostics.coverage_warnings),
            unreadable_or_failed_files=list(getattr(packet.diagnostics, "failed_files", [])),
            deferred_files=list(getattr(packet.diagnostics, "deferred_files", [])),
            execution_time_ms=elapsed_ms,
        )

        return CaseStateReconstruction(
            case_id=packet.case_id,
            audit_at=packet.audit_at,
            is_blocked=False,
            blocking_reason=None,
            is_diagnostic_mode=(packet.intent_decision == "BYPASS_DIAGNOSTIC"),
            subject_id=packet.stable_subject_reference,
            resources=resources,
            active_processes=sorted(list(set(active_processes))),
            restore_risks=sorted(list(set(restore_risks))),
            process_observations=process_observations,
            restore_observations=restore_observations,
            scoped_absence_checks=all_absence_checks,
            diagnostics=diagnostics,
        )
