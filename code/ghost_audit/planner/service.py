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


def extract_participant_evidence_id(raw_id: str, allowed_ids: set[str] | None = None) -> str:
    """Validate one exact participant-visible file, activity, or audit ID."""
    if not raw_id:
        return ""
    candidate = raw_id.strip()
    if not re.fullmatch(r"(?:evidence|activity|audit)_\d+", candidate):
        return ""
    if allowed_ids is not None and candidate not in allowed_ids:
        return ""
    return candidate


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
            if recon.diagnostics and recon.diagnostics.coverage_scope != "KNOWN_COMPLETE":
                return CasePlan(
                    case_id=case_id,
                    status=DeletionStatus.INCOMPLETE,
                    is_unresolved=True,
                    unresolved_reasons=[
                        f"Relevant evidence coverage is {recon.diagnostics.coverage_scope}; COMPLETE is not proven."
                    ],
                )
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
                        supporting_evidence_ids=self._valid_evidence_ids(
                            [ref for copy in res.copies.values() for ref in copy.evidence_references],
                            packet,
                        ),
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

        # A demonstrated violation proves incompleteness, but unresolved
        # relevant resources mean no emitted remediation list can honestly be
        # presented as exhaustive.
        if assessment.unresolved_summary:
            return CasePlan(
                case_id=case_id,
                status=DeletionStatus.INCOMPLETE,
                is_unresolved=True,
                unresolved_reasons=list(assessment.unresolved_summary),
            )

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
                        supporting_evidence_ids=self._valid_evidence_ids(pr.supporting_evidence, packet),
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
                        supporting_evidence_ids=self._valid_evidence_ids(rr.supporting_evidence, packet),
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
                if req_act == RequiredAction.RETAIN:
                    return CasePlan(
                        case_id=case_id,
                        status=DeletionStatus.INCOMPLETE,
                        is_unresolved=True,
                        unresolved_reasons=[
                            f"Policy-required retained record {canon_key} is missing or invalid; "
                            "the submission vocabulary has no grounded repair operation."
                        ],
                    )
                if req_act not in {RequiredAction.DELETE, RequiredAction.REDACT, RequiredAction.ANONYMIZE}:
                    return CasePlan(
                        case_id=case_id,
                        status=DeletionStatus.INCOMPLETE,
                        is_unresolved=True,
                        unresolved_reasons=[f"Unknown required action for violated resource {canon_key}."],
                    )
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
                        supporting_evidence_ids=self._resource_evidence_ids(res, packet),
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
                elif req_act == RequiredAction.DELETE:
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

        # Populate a grounded execution graph. Presentation remains canonical
        # and independent of this graph.
        control_steps: list[tuple[PlannedStep, str | None]] = []
        for risk, step in zip(
            [risk for risk in assessment.process_risks if risk.is_active],
            [step for step in remediations if step.operation == StepOperation.DISABLE_DATA_FLOW],
        ):
            control_steps.append((step, risk.target_resource))
        for risk, step in zip(
            [risk for risk in assessment.restore_risks if not risk.is_blocked],
            [step for step in remediations if step.operation == StepOperation.BLOCK_RESTORE],
        ):
            control_steps.append((step, risk.target_resource))

        updated_remediations: list[PlannedStep] = []
        for step in remediations:
            node = self._step_id(step)
            dependencies: list[str] = []
            if step.operation in {
                StepOperation.DELETE_RECORD, StepOperation.REDACT_RECORD, StepOperation.ANONYMIZE_RECORD,
            }:
                for control, target in control_steps:
                    if target and target in {step.resource_id, f"{step.system_id}:{step.resource_id}"}:
                        dependencies.append(self._step_id(control))
            dependencies = sorted(set(dependencies))
            dep_graph[node] = dependencies
            updated_remediations.append(step.model_copy(update={"depends_on": dependencies}))
        remediations = updated_remediations

        if self._graph_has_cycle(dep_graph):
            return CasePlan(
                case_id=case_id,
                status=DeletionStatus.INCOMPLETE,
                internal_steps=findings + remediations + verifications,
                execution_graph=dep_graph,
                is_unresolved=True,
                unresolved_reasons=["Grounded remediation dependency graph contains a cycle."],
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
            relevant_sacs = [sac for sac in relevant_sacs if sac.timestamp <= recon.audit_at]
            sorted_sacs = sorted(relevant_sacs, key=lambda s: s.timestamp, reverse=True)
            if sorted_sacs:
                ev = extract_participant_evidence_id(
                    sorted_sacs[0].source_id, self._participant_ids(packet)
                )
                if ev:
                    return ev
            return ""

        # Select proof from the relevant violated/satisfied physical copy, not
        # an arbitrary first reference on the aggregate resource.
        desired = (
            PolicyComplianceOutcome.VIOLATED
            if res.outcome == PolicyComplianceOutcome.VIOLATED
            else PolicyComplianceOutcome.SATISFIED
        )
        for copy_ast in sorted(res.copies.values(), key=lambda copy: copy.copy_key):
            if copy_ast.outcome != desired:
                continue
            if copy_ast.evidence_references:
                for ref in copy_ast.evidence_references:
                    ev = extract_participant_evidence_id(ref, self._participant_ids(packet))
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
        allowed = self._participant_ids(packet)
        for ref in supporting_evidence:
            ev = extract_participant_evidence_id(ref, allowed)
            if ev:
                return ev
        return ""

    @staticmethod
    def _participant_ids(packet: Optional[CaseEvidencePacket]) -> set[str] | None:
        if packet is None:
            return None
        ids = {so.observation.evidence_id for so in packet.selected_observations}
        ids.update(sa.activity_id for sa in packet.selected_activities)
        ids.update(inventory.source_id for inventory in packet.scoped_inventories)
        ids.update(link.provenance.source_id for link in packet.linking_graph)
        return {value for value in ids if extract_participant_evidence_id(value)}

    def _valid_evidence_ids(
        self, values: list[str] | tuple[str, ...], packet: Optional[CaseEvidencePacket]
    ) -> list[str]:
        allowed = self._participant_ids(packet)
        return list(dict.fromkeys(
            evidence_id for value in values
            if (evidence_id := extract_participant_evidence_id(value, allowed))
        ))

    def _resource_evidence_ids(self, res, packet: Optional[CaseEvidencePacket]) -> list[str]:
        values = [
            ref
            for copy in res.copies.values()
            if copy.outcome == PolicyComplianceOutcome.VIOLATED
            for ref in copy.evidence_references
        ]
        return self._valid_evidence_ids(values, packet)

    @staticmethod
    def _step_id(step: PlannedStep) -> str:
        return f"{step.operation.value}:{step.system_id}:{step.resource_id}"

    @staticmethod
    def _graph_has_cycle(graph: dict[str, list[str]]) -> bool:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str) -> bool:
            if node in visiting:
                return True
            if node in visited:
                return False
            visiting.add(node)
            if any(visit(dep) for dep in graph.get(node, []) if dep in graph):
                return True
            visiting.remove(node)
            visited.add(node)
            return False

        return any(visit(node) for node in graph)
