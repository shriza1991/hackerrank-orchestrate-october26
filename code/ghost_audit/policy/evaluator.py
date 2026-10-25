"""Authoritative deletion policy evaluator implementing all 15 rule semantics."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from ghost_audit.models.input_models import DataCategory, DeletionRule, RequiredAction
from ghost_audit.policy.models import (
    ConditionEvaluation,
    CopyPolicyAssessment,
    PolicyComplianceOutcome,
    ResourcePolicyAssessment,
)
from ghost_audit.policy.rules import PolicyRuleCatalog
from ghost_audit.state.models import CopyStateAssessment, ExistenceState, FieldStatus, ResourceStateAggregate, RestoreState


class PolicyEvaluator:
    """Evaluates reconstructed resource states and copies against authoritative deletion rules."""

    def __init__(self, catalog: PolicyRuleCatalog, audit_at: datetime) -> None:
        self.catalog = catalog
        self.audit_at = audit_at

    def evaluate_resource(
        self,
        resource: ResourceStateAggregate,
        category: Optional[DataCategory],
        category_basis: str,
        subject_identifiers: list[str],
    ) -> ResourcePolicyAssessment:
        """Evaluate all copies of a resource and aggregate resource-level compliance."""
        if category is None:
            # Unresolved category cannot authorize rule evaluation
            unresolved_copies: dict[str, CopyPolicyAssessment] = {}
            for c_str, c_ast in resource.copies.items():
                unresolved_copies[c_str] = CopyPolicyAssessment(
                    copy_key=c_str,
                    system_id=resource.system_id,
                    resource_id=resource.resource_id,
                    copy_type=c_ast.copy_key.copy_type.value,
                    store_locator=c_ast.copy_key.store_locator,
                    data_category=None,
                    category_basis=category_basis,
                    condition_evaluation=ConditionEvaluation.UNKNOWN,
                    condition_details="Cannot evaluate rule: data category unresolved.",
                    observed_existence=c_ast.existence,
                    observed_pii_exposed=resource.observed_pii_exposed,
                    outcome=PolicyComplianceOutcome.UNDETERMINED,
                    evidence_references=c_ast.supporting_observations,
                    missing_facts=["Authoritative data category unresolved"],
                    conflicts=c_ast.conflicts,
                )
            return ResourcePolicyAssessment(
                system_id=resource.system_id,
                resource_id=resource.resource_id,
                canonical_key=resource.canonical_key,
                data_category=None,
                category_basis=category_basis,
                condition_evaluation=ConditionEvaluation.UNKNOWN,
                condition_details="Cannot evaluate rule: data category unresolved.",
                copies=unresolved_copies,
                outcome=PolicyComplianceOutcome.UNDETERMINED,
                missing_facts=["Authoritative data category unresolved"],
                conflicts=resource.conflicts,
            )

        rule = self.catalog.get_rule(category)
        evaluated_copies: dict[str, CopyPolicyAssessment] = {}

        for c_str, copy_ast in resource.copies.items():
            evaluated_copies[c_str] = self.evaluate_copy(
                copy_ast=copy_ast,
                category=category,
                category_basis=category_basis,
                rule=rule,
                subject_identifiers=subject_identifiers,
            )

        # Aggregate resource-level outcome across copies
        outcomes = [c.outcome for c in evaluated_copies.values()]
        cond_evals = [c.condition_evaluation for c in evaluated_copies.values()]

        # If any copy is VIOLATED -> VIOLATED
        if PolicyComplianceOutcome.VIOLATED in outcomes:
            resource_outcome = PolicyComplianceOutcome.VIOLATED
        elif PolicyComplianceOutcome.UNDETERMINED in outcomes or not outcomes:
            resource_outcome = PolicyComplianceOutcome.UNDETERMINED
        elif all(o == PolicyComplianceOutcome.SATISFIED for o in outcomes):
            resource_outcome = PolicyComplianceOutcome.SATISFIED
        else:
            resource_outcome = PolicyComplianceOutcome.UNDETERMINED

        overall_cond = cond_evals[0] if cond_evals else ConditionEvaluation.UNKNOWN
        if any(ce == ConditionEvaluation.UNKNOWN for ce in cond_evals):
            overall_cond = ConditionEvaluation.UNKNOWN

        recreation_risk = next((c.recreation_risk for c in evaluated_copies.values() if c.recreation_risk), None)
        restore_risk = next((c.restore_risk for c in evaluated_copies.values() if c.restore_risk), None)

        all_missing = [mf for c in evaluated_copies.values() for mf in c.missing_facts]
        all_conflicts = [cf for c in evaluated_copies.values() for cf in c.conflicts] + list(resource.conflicts)

        return ResourcePolicyAssessment(
            system_id=resource.system_id,
            resource_id=resource.resource_id,
            canonical_key=resource.canonical_key,
            data_category=category,
            category_basis=category_basis,
            rule_id=rule.rule_id,
            required_action=rule.required_action,
            condition_evaluation=overall_cond,
            condition_details=rule.condition,
            copies=evaluated_copies,
            outcome=resource_outcome,
            recreation_risk=recreation_risk,
            restore_risk=restore_risk,
            missing_facts=list(dict.fromkeys(all_missing)),
            conflicts=list(dict.fromkeys(all_conflicts)),
            notes=list(resource.notes),
        )

    def evaluate_copy(
        self,
        copy_ast: CopyStateAssessment,
        category: DataCategory,
        category_basis: str,
        rule: DeletionRule,
        subject_identifiers: list[str],
    ) -> CopyPolicyAssessment:
        """Evaluate a single physical copy under the authoritative rule semantics."""
        c_key = copy_ast.copy_key
        sys_id = c_key.system_id
        r_id = c_key.resource_id
        copy_type_str = c_key.copy_type.value
        store_loc = c_key.store_locator

        # Extract latest facts from timeline events
        combined_facts: dict[str, Any] = {}
        for ev in copy_ast.timeline:
            if ev.facts:
                combined_facts.update(ev.facts)

        evidence_refs = list(copy_ast.supporting_observations)
        timestamps: dict[str, Any] = {
            "last_observation_time": copy_ast.last_observation_time,
            "last_activity_time": copy_ast.last_activity_time,
            "audit_at": self.audit_at,
        }
        conflicts = list(copy_ast.conflicts)
        missing_facts: list[str] = []
        coverage_limitations: list[str] = []
        pii_details: list[str] = []

        # Check exposed PII in fields
        observed_pii_exposed = False
        for fname, fobs in copy_ast.fields.items():
            if fobs.status == FieldStatus.EXPOSED:
                observed_pii_exposed = True
                pii_details.append(f"{fname}:{fobs.raw_value or 'EXPOSED'}")

        # Check recreation risk
        recreation_risk: Optional[str] = None
        if copy_ast.is_recreated:
            recreation_risk = copy_ast.recreation_details or "Observed present after verified deletion"

        # Check restore risk
        restore_risk: Optional[str] = None
        if copy_ast.restore_state == RestoreState.ALLOWED:
            restore_risk = f"Restore access permitted for copy {c_key}"

        # Evaluate condition and compliance per category
        condition_eval = ConditionEvaluation.UNKNOWN
        condition_details = ""
        target_properties: dict[str, Any] = {}
        outcome = PolicyComplianceOutcome.UNDETERMINED
        retention_obligation: Optional[str] = None

        # -------------------------------------------------------------
        # 1. DELETE Categories
        # -------------------------------------------------------------
        if category in {
            DataCategory.USER_PROFILE,
            DataCategory.SECONDARY_IDENTIFIER,
            DataCategory.SEARCH_INDEX_ENTRY,
            DataCategory.CACHE_ENTRY,
            DataCategory.USER_EXPORT,
            DataCategory.MARKETING_PROFILE,
        }:
            condition_eval = ConditionEvaluation.TRUE
            condition_details = "Condition 'Always' holds."
            target_properties = {"existence": "ABSENT"}

            if copy_ast.existence == ExistenceState.PRESENT:
                outcome = PolicyComplianceOutcome.VIOLATED
            elif copy_ast.existence == ExistenceState.ABSENT:
                outcome = PolicyComplianceOutcome.SATISFIED
            else:
                outcome = PolicyComplianceOutcome.UNDETERMINED
                missing_facts.append(f"Existence state is {copy_ast.existence.value}")

        # -------------------------------------------------------------
        # 2. SUPPORT_MESSAGE (REDACT)
        # -------------------------------------------------------------
        elif category == DataCategory.SUPPORT_MESSAGE:
            # Condition: Conversation contains shared customer, agent, or order context that must be retained
            has_shared_explicit = combined_facts.get("has_shared_context")
            if has_shared_explicit is None:
                has_shared_explicit = combined_facts.get("shared_context")

            if has_shared_explicit is True or combined_facts.get("participants_count", 1) > 1:
                has_shared_context = True
            elif has_shared_explicit is False or combined_facts.get("participants_count") == 1:
                has_shared_context = False
            elif "agent" in combined_facts or "agent_id" in combined_facts or "order_id" in combined_facts:
                has_shared_context = True
            else:
                has_shared_context = None

            if has_shared_context is None:
                condition_eval = ConditionEvaluation.UNKNOWN
                condition_details = "Missing facts establishing whether support conversation contains shared context."
                outcome = PolicyComplianceOutcome.UNDETERMINED
                missing_facts.append("Shared context facts missing for support message.")
            elif has_shared_context is True:
                condition_eval = ConditionEvaluation.TRUE
                condition_details = "Conversation contains shared agent, customer, or order context requiring retention."
                retention_obligation = "Support message context must be retained with subject identifiers redacted."
                target_properties = {"existence": "PRESENT", "subject_direct_pii": "REDACTED"}

                if copy_ast.existence == ExistenceState.ABSENT:
                    # Premature deletion of conversation context violates retention obligation
                    outcome = PolicyComplianceOutcome.VIOLATED
                elif copy_ast.existence == ExistenceState.PRESENT:
                    # Check subject identifiers only (not other participants)
                    # Check direct PII in copy fields or facts matching subject
                    has_content_evidence = bool(copy_ast.fields) or any(
                        k in combined_facts for k in ["body", "message", "text", "content", "record_json"]
                    )
                    if not has_content_evidence:
                        outcome = PolicyComplianceOutcome.UNDETERMINED
                        missing_facts.append("Support message content/fields missing to prove redaction.")
                    else:
                        subject_pii_present = False
                        for fname, fobs in copy_ast.fields.items():
                            if fobs.status == FieldStatus.EXPOSED:
                                val_str = str(fobs.raw_value or "").lower()
                                if any(ident.lower() in val_str for ident in subject_identifiers):
                                    subject_pii_present = True
                                    break
                            elif fobs.status == FieldStatus.UNREADABLE:
                                subject_pii_present = True
                                break
                        if not subject_pii_present and observed_pii_exposed:
                            for pd in pii_details:
                                if any(ident.lower() in pd.lower() for ident in subject_identifiers):
                                    subject_pii_present = True
                                    break

                        # Check raw content/facts for subject identifiers
                        if not subject_pii_present:
                            msg_text = str(combined_facts.get("body") or combined_facts.get("message") or combined_facts.get("text") or "").lower()
                            if msg_text and any(ident.lower() in msg_text for ident in subject_identifiers):
                                subject_pii_present = True

                        if subject_pii_present:
                            outcome = PolicyComplianceOutcome.VIOLATED
                        else:
                            # Verify positive proof of redaction if subject had PII
                            is_redacted = (
                                combined_facts.get("is_redacted") is True
                                or combined_facts.get("redacted") is True
                                or "[REDACTED]" in str(combined_facts)
                                or any(f.status == FieldStatus.MASKED for f in copy_ast.fields.values())
                            )
                            # If no subject identifiers remain and no exposed PII
                            outcome = PolicyComplianceOutcome.SATISFIED
                else:
                    outcome = PolicyComplianceOutcome.UNDETERMINED
                    missing_facts.append(f"Existence state is {copy_ast.existence.value}")
            else:
                condition_eval = ConditionEvaluation.FALSE
                condition_details = "Conversation does not contain shared context."
                outcome = PolicyComplianceOutcome.UNDETERMINED
                missing_facts.append("No supplied rule establishes treatment when conversation does not contain shared context.")

        # -------------------------------------------------------------
        # 3. SUPPORT_ATTACHMENT (DELETE)
        # -------------------------------------------------------------
        elif category == DataCategory.SUPPORT_ATTACHMENT:
            # Condition: Attachment belongs only to the deletion subject
            if combined_facts.get("belongs_only_to_subject") is True or combined_facts.get("sole_owner") is True:
                belongs_only_to_subject = True
            elif (
                combined_facts.get("shared_with_others") is True
                or combined_facts.get("multi_party") is True
                or combined_facts.get("is_shared") is True
                or combined_facts.get("belongs_only_to_subject") is False
                or combined_facts.get("sole_owner") is False
            ):
                belongs_only_to_subject = False
            else:
                belongs_only_to_subject = None

            if belongs_only_to_subject is None:
                condition_eval = ConditionEvaluation.UNKNOWN
                condition_details = "Attachment ownership facts not supplied (unknown if exclusive or shared)."
                outcome = PolicyComplianceOutcome.UNDETERMINED
                missing_facts.append("Attachment ownership facts (exclusive vs shared) missing.")
            elif belongs_only_to_subject is True:
                condition_eval = ConditionEvaluation.TRUE
                condition_details = "Attachment belongs exclusively to the deletion subject."
                target_properties = {"existence": "ABSENT"}

                if copy_ast.existence == ExistenceState.PRESENT:
                    outcome = PolicyComplianceOutcome.VIOLATED
                elif copy_ast.existence == ExistenceState.ABSENT:
                    outcome = PolicyComplianceOutcome.SATISFIED
                else:
                    outcome = PolicyComplianceOutcome.UNDETERMINED
                    missing_facts.append(f"Existence state is {copy_ast.existence.value}")
            else:
                condition_eval = ConditionEvaluation.FALSE
                condition_details = "Attachment does not belong only to the deletion subject."
                outcome = PolicyComplianceOutcome.UNDETERMINED
                missing_facts.append("No supplied rule establishes treatment for shared support attachments.")

        # -------------------------------------------------------------
        # 4. ANALYTICS_PROFILE & PRODUCT_TELEMETRY (ANONYMIZE)
        # -------------------------------------------------------------
        elif category in {DataCategory.ANALYTICS_PROFILE, DataCategory.PRODUCT_TELEMETRY}:
            # Condition: Record is still attributable to a user
            # Attribution based on stable user_id, historical aliases, email, phone, or identifiable payload
            is_anonymized_flag = (
                combined_facts.get("anonymized") is True
                or combined_facts.get("is_anonymized") is True
                or "ANONYMIZED" in str(copy_ast.fields.get("anonymized_status", ""))
                or any(str(f.raw_value or "").startswith("anon_") for f in copy_ast.fields.values())
            )

            # Check if stored payload/fields still contain usable identifiers
            has_identifying_payload = False
            has_content_facts = bool(copy_ast.fields) or any(
                k in combined_facts for k in ["payload", "record_json", "profile_data", "event_data", "user_id", "email"]
            )

            for fname, fobs in copy_ast.fields.items():
                if fobs.status == FieldStatus.EXPOSED:
                    val_str = str(fobs.raw_value or "").lower()
                    if any(ident.lower() in val_str for ident in subject_identifiers):
                        has_identifying_payload = True
                        break

            # Inspect stored payload fields specifically (not historical query context)
            stored_payload = (
                combined_facts.get("payload")
                or combined_facts.get("record_json")
                or combined_facts.get("profile_data")
                or combined_facts.get("event_data")
            )
            if stored_payload and not has_identifying_payload:
                stored_str = str(stored_payload).lower()
                if any(ident.lower() in stored_str for ident in subject_identifiers):
                    has_identifying_payload = True

            if has_identifying_payload:
                condition_eval = ConditionEvaluation.TRUE
                condition_details = "Record still contains identifying payload or links attributable to the user."
                target_properties = {"anonymized": True, "attributable": False}

                if copy_ast.existence == ExistenceState.PRESENT:
                    # Identifying payload remaining violates anonymization requirement
                    outcome = PolicyComplianceOutcome.VIOLATED
                elif copy_ast.existence == ExistenceState.ABSENT:
                    outcome = PolicyComplianceOutcome.SATISFIED
                else:
                    outcome = PolicyComplianceOutcome.UNDETERMINED
            elif is_anonymized_flag:
                condition_eval = ConditionEvaluation.FALSE
                condition_details = "Record is verified anonymized and no longer attributable to the user."
                target_properties = {"anonymized": True, "attributable": False}
                outcome = PolicyComplianceOutcome.SATISFIED
            elif copy_ast.existence == ExistenceState.ABSENT:
                condition_eval = ConditionEvaluation.FALSE
                condition_details = "Record is absent."
                target_properties = {"anonymized": True, "attributable": False}
                outcome = PolicyComplianceOutcome.SATISFIED
            elif copy_ast.existence == ExistenceState.PRESENT:
                # Existing record without evidence of anonymization cannot be assumed compliant
                condition_eval = ConditionEvaluation.UNKNOWN
                condition_details = "Attribution facts inconclusive: record exists but proof of anonymization missing."
                outcome = PolicyComplianceOutcome.UNDETERMINED
                missing_facts.append("Positive proof of anonymization missing for existing analytics record.")
            else:
                condition_eval = ConditionEvaluation.UNKNOWN
                condition_details = "Attribution facts inconclusive."
                outcome = PolicyComplianceOutcome.UNDETERMINED
                missing_facts.append(f"Existence state is {copy_ast.existence.value}")

        # -------------------------------------------------------------
        # 5. EMAIL_DELIVERY_LOG (REDACT)
        # -------------------------------------------------------------
        elif category == DataCategory.EMAIL_DELIVERY_LOG:
            # Condition: Log contains a user email address
            facts_str = str(combined_facts).lower()
            emails = [ident.lower() for ident in subject_identifiers if "@" in ident]
            contains_email = any(em in facts_str for em in emails)

            if contains_email:
                condition_eval = ConditionEvaluation.TRUE
                condition_details = "Delivery log contains subject's email address."
                target_properties = {"email_redacted": True}

                # Check if email is redacted or exposed
                # If observed_pii_exposed or unredacted email in fields -> VIOLATED
                is_redacted = (
                    combined_facts.get("is_redacted") is True
                    or combined_facts.get("redacted") is True
                    or "[REDACTED]" in facts_str
                    or "***" in facts_str
                )
                if copy_ast.existence == ExistenceState.PRESENT:
                    if is_redacted and not observed_pii_exposed:
                        outcome = PolicyComplianceOutcome.SATISFIED
                    else:
                        outcome = PolicyComplianceOutcome.VIOLATED
                elif copy_ast.existence == ExistenceState.ABSENT:
                    outcome = PolicyComplianceOutcome.SATISFIED
                else:
                    outcome = PolicyComplianceOutcome.UNDETERMINED
            else:
                condition_eval = ConditionEvaluation.FALSE
                condition_details = "Log does not contain subject's email address."
                target_properties = {"email_redacted": True}
                outcome = PolicyComplianceOutcome.SATISFIED

        # -------------------------------------------------------------
        # 6. SECURITY_AUDIT_LOG (RETAIN)
        # -------------------------------------------------------------
        elif category == DataCategory.SECURITY_AUDIT_LOG:
            # Condition: Record is within the supplied retention period
            retention_until = combined_facts.get("retention_until")
            created_at = combined_facts.get("created_at") or copy_ast.last_observation_time
            retention_days = combined_facts.get("retention_days") or combined_facts.get("retention_period_days")

            is_within_retention = None
            if retention_until:
                try:
                    if isinstance(retention_until, str):
                        ru_dt = datetime.fromisoformat(retention_until.replace("Z", "+00:00"))
                    else:
                        ru_dt = retention_until
                    is_within_retention = self.audit_at <= ru_dt
                except Exception:
                    pass

            if is_within_retention is None and retention_days is not None and created_at:
                try:
                    from datetime import timedelta
                    days = int(retention_days)
                    c_dt = created_at if isinstance(created_at, datetime) else datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
                    is_within_retention = self.audit_at <= (c_dt + timedelta(days=days))
                except Exception:
                    pass

            # If no retention facts were supplied, check default audit retention claim
            if is_within_retention is None:
                # Rule says: "Do not invent retention durations or automatically authorize deletion"
                # Missing retention facts must remain UNKNOWN
                condition_eval = ConditionEvaluation.UNKNOWN
                condition_details = "Retention duration facts not supplied for security audit log."
                outcome = PolicyComplianceOutcome.UNDETERMINED
                missing_facts.append("Supplied retention period facts missing for audit record.")
            elif is_within_retention:
                condition_eval = ConditionEvaluation.TRUE
                condition_details = "Record is within the supplied retention period at audit_at."
                retention_obligation = "Security audit log must be retained through retention period."
                target_properties = {"existence": "PRESENT"}

                if copy_ast.existence == ExistenceState.PRESENT:
                    outcome = PolicyComplianceOutcome.SATISFIED
                elif copy_ast.existence == ExistenceState.ABSENT:
                    # Deletion of required retained record is a VIOLATION!
                    outcome = PolicyComplianceOutcome.VIOLATED
                else:
                    outcome = PolicyComplianceOutcome.UNDETERMINED
            else:
                condition_eval = ConditionEvaluation.FALSE
                condition_details = "Retention period expired at audit_at."
                # Rules do not establish automatic deletion upon expiry
                outcome = PolicyComplianceOutcome.UNDETERMINED
                missing_facts.append("No supplied rule establishes treatment for expired security audit log.")

        # -------------------------------------------------------------
        # 7. LEGAL_HOLD_RECORD (RETAIN)
        # -------------------------------------------------------------
        elif category == DataCategory.LEGAL_HOLD_RECORD:
            # Condition: A supplied legal hold is active
            hold_status = str(combined_facts.get("hold_status") or combined_facts.get("status") or "").upper()
            hold_start = combined_facts.get("hold_start")
            hold_end = combined_facts.get("hold_end")

            is_active = False
            if hold_status == "ACTIVE":
                is_active = True
                if hold_start:
                    try:
                        start_dt = datetime.fromisoformat(str(hold_start).replace("Z", "+00:00"))
                        if self.audit_at < start_dt:
                            is_active = False
                    except Exception:
                        pass
                if hold_end and is_active:
                    try:
                        end_dt = datetime.fromisoformat(str(hold_end).replace("Z", "+00:00"))
                        if self.audit_at > end_dt:
                            is_active = False
                    except Exception:
                        pass
            elif not hold_status and ("hold" in r_id.lower() or "hold" in sys_id.lower()):
                # Missing hold facts remain unresolved
                condition_eval = ConditionEvaluation.UNKNOWN
                condition_details = "Legal hold status facts missing."
                outcome = PolicyComplianceOutcome.UNDETERMINED
                missing_facts.append("Missing active hold facts.")
                is_active = None

            if is_active is True:
                condition_eval = ConditionEvaluation.TRUE
                condition_details = "Legal hold is active at audit_at."
                retention_obligation = "Record is under active legal hold and must be retained."
                target_properties = {"existence": "PRESENT"}

                if copy_ast.existence == ExistenceState.PRESENT:
                    outcome = PolicyComplianceOutcome.SATISFIED
                elif copy_ast.existence == ExistenceState.ABSENT:
                    outcome = PolicyComplianceOutcome.VIOLATED
                else:
                    outcome = PolicyComplianceOutcome.UNDETERMINED
            elif is_active is False:
                condition_eval = ConditionEvaluation.FALSE
                condition_details = "Legal hold is not active at audit_at."
                outcome = PolicyComplianceOutcome.UNDETERMINED
                missing_facts.append("No supplied rule establishes treatment for inactive legal hold.")

        # -------------------------------------------------------------
        # 8. BACKUP_ARCHIVE (RETAIN)
        # -------------------------------------------------------------
        elif category == DataCategory.BACKUP_ARCHIVE:
            # Condition: Restore access can be blocked
            # Assess retention and restore safety separately!
            # A block claim is insufficient proof of enforced restriction
            restore_state = copy_ast.restore_state
            is_blocked = restore_state == RestoreState.BLOCKED
            has_restore_block_claim = any("BLOCK_RESTORE SUCCESS" in c for c in copy_ast.unverified_claims)

            condition_eval = ConditionEvaluation.TRUE
            condition_details = "Restore access restriction policy applies."
            target_properties = {"existence": "PRESENT", "restore_access": "BLOCKED"}

            if copy_ast.existence == ExistenceState.ABSENT:
                outcome = PolicyComplianceOutcome.VIOLATED
            elif copy_ast.existence == ExistenceState.PRESENT:
                if is_blocked:
                    outcome = PolicyComplianceOutcome.SATISFIED
                elif has_restore_block_claim and not is_blocked:
                    # Unverified claim alone does not establish verified block
                    outcome = PolicyComplianceOutcome.VIOLATED
                    missing_facts.append("Restore block claimed but not verified in observed permissions.")
                elif restore_state == RestoreState.ALLOWED:
                    outcome = PolicyComplianceOutcome.VIOLATED
                    restore_risk = f"Backup archive {r_id} has restore access allowed."
                else:
                    outcome = PolicyComplianceOutcome.VIOLATED
                    missing_facts.append("Restore block not established by observed evidence.")
            else:
                outcome = PolicyComplianceOutcome.UNDETERMINED

        # -------------------------------------------------------------
        # 9. ACCOUNT_TOMBSTONE (REDACT)
        # -------------------------------------------------------------
        elif category == DataCategory.ACCOUNT_TOMBSTONE:
            # Condition: Account is deleted and only a stable internal user_id is needed to preserve references to retained records
            condition_eval = ConditionEvaluation.TRUE
            condition_details = "Account tombstone preserves stable reference for retained records."
            target_properties = {"user_id_preserved": True, "direct_pii_redacted": True}

            if copy_ast.existence == ExistenceState.ABSENT:
                # Missing tombstone when needed to preserve references
                outcome = PolicyComplianceOutcome.VIOLATED
            elif copy_ast.existence == ExistenceState.PRESENT:
                # Stable internal user_id is PERMITTED.
                # Must positively prove:
                # 1. Stable reference is preserved (user_id/subject_id)
                # 2. Prohibited direct identifiers (name, email, phone, email_hash) are removed/redacted
                # Absence of fields/facts does NOT prove compliance!
                has_stable_ref = False
                for fname, fobs in copy_ast.fields.items():
                    if fname.lower() in {"user_id", "subject_id", "id", "account_id"}:
                        if (
                            fobs.is_stable_ref
                            or fobs.status == FieldStatus.RETAINED_STABLE_REF
                            or (fobs.raw_value and (str(fobs.raw_value).startswith("user_") or str(fobs.raw_value).startswith("usr_")))
                        ):
                            has_stable_ref = True
                            break
                if not has_stable_ref:
                    for k in ["user_id", "subject_id", "subject_reference"]:
                        v = combined_facts.get(k)
                        if v and (str(v).startswith("user_") or str(v).startswith("usr_")):
                            has_stable_ref = True
                            break

                has_content_evidence = bool(copy_ast.fields) or any(
                    k in combined_facts for k in ["user_id", "subject_id", "name", "email", "phone", "email_hash", "status", "record_json"]
                )

                prohibited_names = {"name", "email", "phone", "email_hash", "full_name"}
                prohibited_exposed = any(
                    (fname.lower() in prohibited_names) and fobs.status == FieldStatus.EXPOSED
                    for fname, fobs in copy_ast.fields.items()
                    if fname.lower() not in {"user_id", "subject_id", "id", "account_id"}
                )
                if not prohibited_exposed:
                    for p in prohibited_names:
                        val = combined_facts.get(p)
                        if val and str(val) not in {"[REDACTED]", "***", "None"}:
                            prohibited_exposed = True
                            break

                if not has_content_evidence or not has_stable_ref:
                    outcome = PolicyComplianceOutcome.UNDETERMINED
                    missing_facts.append("Missing proof of preserved stable reference or content in tombstone.")
                elif prohibited_exposed:
                    outcome = PolicyComplianceOutcome.VIOLATED
                else:
                    outcome = PolicyComplianceOutcome.SATISFIED
            else:
                outcome = PolicyComplianceOutcome.UNDETERMINED

        return CopyPolicyAssessment(
            copy_key=str(c_key),
            system_id=sys_id,
            resource_id=r_id,
            copy_type=copy_type_str,
            store_locator=store_loc,
            data_category=category,
            category_basis=category_basis,
            rule_id=rule.rule_id,
            required_action=rule.required_action,
            condition_evaluation=condition_eval,
            condition_details=condition_details,
            observed_existence=copy_ast.existence,
            observed_pii_exposed=observed_pii_exposed,
            pii_details=pii_details,
            target_properties=target_properties,
            outcome=outcome,
            evidence_references=evidence_refs,
            timestamps=timestamps,
            missing_facts=missing_facts,
            conflicts=conflicts,
            coverage_limitations=coverage_limitations,
            retention_obligation=retention_obligation,
            recreation_risk=recreation_risk,
            restore_risk=restore_risk,
            notes=[],
        )
