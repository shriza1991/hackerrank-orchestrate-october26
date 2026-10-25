"""Evidence-grounded audit planning and remediation sequencing."""

from __future__ import annotations

import re
from typing import Optional

from ghost_audit.models.input_models import RequiredAction
from ghost_audit.models.output_models import (
    DeletionStatus,
    OutputRow,
    Step,
    StepOperation,
    StepPhase,
    StepState,
    step_canonical_key,
    validate_steps_sequence,
)
from ghost_audit.planner.models import CasePlan, PlannedStep
from ghost_audit.policy.models import CasePolicyAssessment, PolicyComplianceOutcome
from ghost_audit.retrieval.models import CaseEvidencePacket
from ghost_audit.state.models import CaseStateReconstruction, ExistenceState


def extract_participant_evidence_id(raw_id: str) -> str:
    """Extract participant-visible evidence ID (e.g. evidence_54, act_123, or audit ID)."""
    if not raw_id:
        return ""
    m = re.search(r"\b(evidence_\d+)\b", raw_id)
    if m:
        return m.group(1)
    m_act = re.search(r"\b(act_\w+|\d+)\b", raw_id)
    if m_act:
        return m_act.group(1)
    return raw_id.strip()


class AuditPlanGenerator:
    """Generates evidence-backed audit plans, findings, remediation, and verification steps."""

    def generate_plan(
        self,
        assessment: CasePolicyAssessment,
        recon: CaseStateReconstruction,
        packet: Optional[CaseEvidencePacket] = None,
    ) -> CasePlan:
        """Generate a complete, grounded CasePlan conforming to the challenge specification."""
        case_id = assessment.case_id

        # 1. Non-deletion requests vs unresolved intent errors
        if not assessment.is_authorized_deletion:
            if assessment.intent_status == "NON_DELETION":
                return CasePlan(
                    case_id=case_id,
                    status=DeletionStatus.NOT_APPLICABLE,
                    steps=[],
                    internal_steps=[],
                    is_unresolved=False,
                )
            # Otherwise blocked due to unclassified, ambiguous, or failed intent
            return CasePlan(
                case_id=case_id,
                status=DeletionStatus.INCOMPLETE,
                steps=[],
                internal_steps=[],
                is_unresolved=True,
                unresolved_reasons=[assessment.blocking_reason or "Intent authorization not established."],
            )

        # 2. Check for undetermined compliance or unresolved cases
        if assessment.overall_compliance == PolicyComplianceOutcome.UNDETERMINED:
            unresolved_reasons = list(assessment.unresolved_summary) + list(assessment.coverage_limitations)
            if not unresolved_reasons:
                unresolved_reasons.append("Insufficient evidence to establish compliance at audit_at.")
            return CasePlan(
                case_id=case_id,
                status=DeletionStatus.INCOMPLETE,  # Placeholder, marked unresolved
                steps=[],
                internal_steps=[],
                is_unresolved=True,
                unresolved_reasons=unresolved_reasons,
            )

        # 3. COMPLETE Cases: Only evidence-backed VERIFICATION steps
        if assessment.overall_compliance == PolicyComplianceOutcome.SATISFIED:
            planned_steps: list[PlannedStep] = []

            # Require at least one verified resource
            if not assessment.resources:
                return CasePlan(
                    case_id=case_id,
                    status=DeletionStatus.INCOMPLETE,
                    steps=[],
                    internal_steps=[],
                    is_unresolved=True,
                    unresolved_reasons=["Empty resource set cannot be proven COMPLETE."],
                )

            for canon_key, res in assessment.resources.items():
                sys_id = res.system_id
                r_id = res.resource_id

                # Select operation based on required action
                req_act = res.required_action
                if req_act == RequiredAction.RETAIN:
                    op = StepOperation.VERIFY_RECORD_PRESENT
                    st = StepState.PRESENT
                elif req_act == RequiredAction.REDACT:
                    op = StepOperation.VERIFY_RECORD_REDACTED
                    st = StepState.REDACTED
                elif req_act == RequiredAction.ANONYMIZE:
                    op = StepOperation.VERIFY_RECORD_ANONYMIZED
                    st = StepState.ANONYMIZED
                else:
                    op = StepOperation.VERIFY_RECORD_ABSENT
                    st = StepState.ABSENT

                # Find supporting evidence
                ev_id = self._find_resource_evidence(
                    canon_key=canon_key,
                    res=res,
                    recon=recon,
                    packet=packet,
                    is_absence=(st == StepState.ABSENT),
                )

                if not ev_id:
                    # Cannot prove compliance without evidence
                    return CasePlan(
                        case_id=case_id,
                        status=DeletionStatus.COMPLETE,
                        steps=[],
                        internal_steps=[],
                        is_unresolved=True,
                        unresolved_reasons=[f"Missing evidence to cite for verified resource {canon_key}"],
                    )

                planned_steps.append(
                    PlannedStep(
                        phase=StepPhase.VERIFICATION,
                        system_id=sys_id,
                        resource_id=r_id,
                        operation=op,
                        state=st,
                        evidence_id=ev_id,
                        reason=f"Verified compliant state for {canon_key} backed by {ev_id}",
                    )
                )

            # Build canonical output steps
            canonical_steps = self._format_and_sort_steps(planned_steps)
            validation_errors = validate_steps_sequence(DeletionStatus.COMPLETE, canonical_steps)
            if validation_errors:
                return CasePlan(
                    case_id=case_id,
                    status=DeletionStatus.COMPLETE,
                    steps=canonical_steps,
                    internal_steps=planned_steps,
                    is_unresolved=True,
                    unresolved_reasons=validation_errors,
                )

            return CasePlan(
                case_id=case_id,
                status=DeletionStatus.COMPLETE,
                steps=canonical_steps,
                internal_steps=planned_steps,
                is_unresolved=False,
            )

        # 4. INCOMPLETE Cases: FINDING, REMEDIATION, VERIFICATION
        findings: list[PlannedStep] = []
        remediations: list[PlannedStep] = []
        verifications: list[PlannedStep] = []
        dep_graph: dict[str, list[str]] = {}

        # 4A. Active data flows
        for pr in assessment.process_risks:
            if pr.is_active:
                ev_id = self._find_risk_evidence(pr.system_id, pr.process_id, pr.supporting_evidence, packet)
                if not ev_id:
                    return CasePlan(
                        case_id=case_id,
                        status=DeletionStatus.INCOMPLETE,
                        steps=[],
                        internal_steps=[],
                        is_unresolved=True,
                        unresolved_reasons=[f"Missing evidence proving active data flow {pr.process_id}"],
                    )
                findings.append(
                    PlannedStep(
                        phase=StepPhase.FINDING,
                        system_id=pr.system_id,
                        resource_id=pr.process_id,
                        operation=StepOperation.REPORT_ACTIVE_DATA_FLOW,
                        state=StepState.ACTIVE,
                        evidence_id=ev_id,
                        reason=pr.details,
                    )
                )
                remediations.append(
                    PlannedStep(
                        phase=StepPhase.REMEDIATION,
                        system_id=pr.system_id,
                        resource_id=pr.process_id,
                        operation=StepOperation.DISABLE_DATA_FLOW,
                        state=StepState.DISABLED,
                        evidence_id="",
                        execution_priority=10,  # Must disable flows first
                        reason=f"Disable active flow {pr.process_id}",
                    )
                )
                verifications.append(
                    PlannedStep(
                        phase=StepPhase.VERIFICATION,
                        system_id=pr.system_id,
                        resource_id=pr.process_id,
                        operation=StepOperation.VERIFY_DATA_FLOW_DISABLED,
                        state=StepState.DISABLED,
                        evidence_id="",
                        reason=f"Verify flow {pr.process_id} disabled",
                    )
                )

        # 4B. Restore risks
        for rr in assessment.restore_risks:
            if not rr.is_blocked:
                ev_id = self._find_risk_evidence(rr.system_id, rr.backup_id, rr.supporting_evidence, packet)
                if not ev_id:
                    return CasePlan(
                        case_id=case_id,
                        status=DeletionStatus.INCOMPLETE,
                        steps=[],
                        internal_steps=[],
                        is_unresolved=True,
                        unresolved_reasons=[f"Missing evidence proving restore risk {rr.backup_id}"],
                    )
                findings.append(
                    PlannedStep(
                        phase=StepPhase.FINDING,
                        system_id=rr.system_id,
                        resource_id=rr.backup_id,
                        operation=StepOperation.REPORT_RESTORE_RISK,
                        state=StepState.ACTIVE,
                        evidence_id=ev_id,
                        reason=rr.details,
                    )
                )
                remediations.append(
                    PlannedStep(
                        phase=StepPhase.REMEDIATION,
                        system_id=rr.system_id,
                        resource_id=rr.backup_id,
                        operation=StepOperation.BLOCK_RESTORE,
                        state=StepState.BLOCKED,
                        evidence_id="",
                        execution_priority=20,  # Block restores before mutating records
                        reason=f"Block restore access for {rr.backup_id}",
                    )
                )
                verifications.append(
                    PlannedStep(
                        phase=StepPhase.VERIFICATION,
                        system_id=rr.system_id,
                        resource_id=rr.backup_id,
                        operation=StepOperation.VERIFY_RESTORE_BLOCKED,
                        state=StepState.BLOCKED,
                        evidence_id="",
                        reason=f"Verify restore access blocked for {rr.backup_id}",
                    )
                )

        # 4C. Resource violations and verification
        for canon_key, res in assessment.resources.items():
            sys_id = res.system_id
            r_id = res.resource_id
            req_act = res.required_action

            if res.outcome == PolicyComplianceOutcome.VIOLATED:
                ev_id = self._find_resource_evidence(
                    canon_key=canon_key,
                    res=res,
                    recon=recon,
                    packet=packet,
                    is_absence=False,
                )
                if not ev_id:
                    return CasePlan(
                        case_id=case_id,
                        status=DeletionStatus.INCOMPLETE,
                        steps=[],
                        internal_steps=[],
                        is_unresolved=True,
                        unresolved_reasons=[f"Missing evidence proving violation for {canon_key}"],
                    )

                # Determine finding operation
                is_pii = any(c.observed_pii_exposed for c in res.copies.values()) or (
                    canon_key in recon.resources and recon.resources[canon_key].observed_pii_exposed
                )
                if req_act in {RequiredAction.REDACT, RequiredAction.ANONYMIZE} and is_pii:
                    find_op = StepOperation.REPORT_EXPOSED_PII
                else:
                    find_op = StepOperation.REPORT_REMAINING_RECORD

                findings.append(
                    PlannedStep(
                        phase=StepPhase.FINDING,
                        system_id=sys_id,
                        resource_id=r_id,
                        operation=find_op,
                        state=StepState.PRESENT,
                        evidence_id=ev_id,
                        reason=f"Policy violation on {canon_key}",
                    )
                )

                # Determine remediation operation
                if req_act == RequiredAction.REDACT:
                    rem_op = StepOperation.REDACT_RECORD
                    rem_st = StepState.REDACTED
                elif req_act == RequiredAction.ANONYMIZE:
                    rem_op = StepOperation.ANONYMIZE_RECORD
                    rem_st = StepState.ANONYMIZED
                else:
                    rem_op = StepOperation.DELETE_RECORD
                    rem_st = StepState.ABSENT

                remediations.append(
                    PlannedStep(
                        phase=StepPhase.REMEDIATION,
                        system_id=sys_id,
                        resource_id=r_id,
                        operation=rem_op,
                        state=rem_st,
                        evidence_id="",
                        execution_priority=50,
                        reason=f"Remediate {canon_key} via {rem_op.value}",
                    )
                )

            # Verification: covers all evaluated resources (both remediated and compliant)
            if req_act == RequiredAction.RETAIN:
                v_op = StepOperation.VERIFY_RECORD_PRESENT
                v_st = StepState.PRESENT
            elif req_act == RequiredAction.REDACT:
                v_op = StepOperation.VERIFY_RECORD_REDACTED
                v_st = StepState.REDACTED
            elif req_act == RequiredAction.ANONYMIZE:
                v_op = StepOperation.VERIFY_RECORD_ANONYMIZED
                v_st = StepState.ANONYMIZED
            else:
                v_op = StepOperation.VERIFY_RECORD_ABSENT
                v_st = StepState.ABSENT

            verifications.append(
                PlannedStep(
                    phase=StepPhase.VERIFICATION,
                    system_id=sys_id,
                    resource_id=r_id,
                    operation=v_op,
                    state=v_st,
                    evidence_id="",
                    reason=f"Verify required state {v_st.value} for {canon_key}",
                )
            )

        all_planned = findings + remediations + verifications
        canonical_steps = self._format_and_sort_steps(all_planned)

        validation_errors = validate_steps_sequence(DeletionStatus.INCOMPLETE, canonical_steps)
        if validation_errors:
            return CasePlan(
                case_id=case_id,
                status=DeletionStatus.INCOMPLETE,
                steps=canonical_steps,
                internal_steps=all_planned,
                execution_graph=dep_graph,
                is_unresolved=True,
                unresolved_reasons=validation_errors,
            )

        return CasePlan(
            case_id=case_id,
            status=DeletionStatus.INCOMPLETE,
            steps=canonical_steps,
            internal_steps=all_planned,
            execution_graph=dep_graph,
            is_unresolved=False,
        )

    def _format_and_sort_steps(self, planned_steps: list[PlannedStep]) -> list[Step]:
        """Deduplicate, sort canonically, and number consecutively from 1."""
        unique_steps_map: dict[tuple[StepPhase, StepOperation, str, str], PlannedStep] = {}
        for p in planned_steps:
            key = (p.phase, p.operation, p.system_id, p.resource_id)
            if key not in unique_steps_map:
                unique_steps_map[key] = p
            else:
                # If existing has no evidence_id and new does, prefer the one with evidence_id
                if not unique_steps_map[key].evidence_id and p.evidence_id:
                    unique_steps_map[key] = p

        # Build preliminary Step objects for canonical key sorting
        preliminary: list[Step] = []
        for p in unique_steps_map.values():
            preliminary.append(
                Step(
                    step_no=1,  # temporary
                    phase=p.phase,
                    system_id=p.system_id,
                    resource_id=p.resource_id,
                    operation=p.operation,
                    state=p.state,
                    evidence_id=p.evidence_id,
                )
            )

        # Sort canonically: phase -> operation -> system_id -> resource_id
        preliminary.sort(key=step_canonical_key)

        # Number consecutively from 1
        final_steps: list[Step] = []
        for i, s in enumerate(preliminary, start=1):
            final_steps.append(
                Step(
                    step_no=i,
                    phase=s.phase,
                    system_id=s.system_id,
                    resource_id=s.resource_id,
                    operation=s.operation,
                    state=s.state,
                    evidence_id=s.evidence_id,
                )
            )

        return final_steps

    def _find_resource_evidence(
        self,
        canon_key: str,
        res: Any,
        recon: CaseStateReconstruction,
        packet: Optional[CaseEvidencePacket],
        is_absence: bool = False,
    ) -> str:
        """Find participant-visible evidence ID proving compliant state or violation for a resource."""
        # 1. For absence checks, prefer the latest scoped absence proof before audit_at
        if is_absence:
            relevant_sacs = [
                sac for sac in recon.scoped_absence_checks
                if sac.system_id == res.system_id
                and (sac.resource_id == res.resource_id or not sac.resource_id)
                and sac.membership_result == "ABSENT"
            ]
            sorted_sacs = sorted(relevant_sacs, key=lambda s: s.timestamp, reverse=True)
            if sorted_sacs:
                ev = extract_participant_evidence_id(sorted_sacs[0].source_id)
                if ev:
                    return ev

        # 2. Check copy assessments on resource
        for copy_ast in res.copies.values():
            if copy_ast.evidence_references:
                for ref in copy_ast.evidence_references:
                    ev = extract_participant_evidence_id(ref)
                    if ev:
                        return ev

        # 3. Check state reconstruction copies timeline and observations
        if canon_key in recon.resources:
            recon_res = recon.resources[canon_key]
            for copy_state in recon_res.copies.values():
                for obs_id in copy_state.supporting_observations:
                    ev = extract_participant_evidence_id(obs_id)
                    if ev:
                        return ev
                for ev_event in copy_state.timeline:
                    if not ev_event.is_claim and ev_event.source_id:
                        ev = extract_participant_evidence_id(ev_event.source_id)
                        if ev:
                            return ev

        # 4. Check selected observations in packet
        if packet and packet.selected_observations:
            matching_obs = [
                so for so in packet.selected_observations
                if so.observation.system_id == res.system_id
                and (so.observation.resource_id == res.resource_id or not so.observation.resource_id)
            ]
            sorted_obs = sorted(matching_obs, key=lambda so: so.observation.capture_time, reverse=True)
            if sorted_obs:
                ev = extract_participant_evidence_id(sorted_obs[0].observation.evidence_id)
                if ev:
                    return ev

        # 5. Check selected activities in packet
        if packet and packet.selected_activities:
            matching_acts = [
                sa for sa in packet.selected_activities
                if sa.target_system == res.system_id
                and sa.resource_id == res.resource_id
            ]
            if matching_acts:
                ev = extract_participant_evidence_id(matching_acts[0].activity_id)
                if ev:
                    return ev

        return ""

    def _find_risk_evidence(
        self,
        system_id: str,
        resource_id: str,
        supporting_evidence: Sequence[str],
        packet: Optional[CaseEvidencePacket],
    ) -> str:
        """Find participant-visible evidence ID proving an active process or restore risk."""
        for ref in supporting_evidence:
            ev = extract_participant_evidence_id(ref)
            if ev:
                return ev
        if packet and packet.selected_observations:
            for so in packet.selected_observations:
                if so.observation.system_id == system_id and (so.observation.resource_id == resource_id or not so.observation.resource_id):
                    ev = extract_participant_evidence_id(so.observation.evidence_id)
                    if ev:
                        return ev
        if packet and packet.selected_activities:
            for sa in packet.selected_activities:
                if sa.target_system == system_id and sa.resource_id == resource_id:
                    ev = extract_participant_evidence_id(sa.activity_id)
                    if ev:
                        return ev
        return ""

