"""Policy decision engine service coordinating category classification, rule evaluation, and risk assessments."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from ghost_audit.models.input_models import DataCategory, DeletionRequest
from ghost_audit.policy.category_classifier import GroundedCategoryClassifier
from ghost_audit.policy.evaluator import PolicyEvaluator
from ghost_audit.policy.models import (
    CasePolicyAssessment,
    PolicyComplianceOutcome,
    ProcessRiskAssessment,
    ResourcePolicyAssessment,
    RestoreRiskAssessment,
)
from ghost_audit.policy.rules import PolicyRuleCatalog
from ghost_audit.retrieval.models import CaseEvidencePacket
from ghost_audit.state.models import CaseStateReconstruction, CopyType, ExistenceState, ProcessState, RestoreState


class PolicyDecisionEngine:
    """Evidence-grounded policy decision engine assessing reconstructed case state against deletion policy."""

    def __init__(self, catalog: PolicyRuleCatalog) -> None:
        self.catalog = catalog

    @classmethod
    def from_rules_file(cls, rules_path: Path) -> PolicyDecisionEngine:
        """Initialize engine with authoritative rules loaded from CSV."""
        catalog = PolicyRuleCatalog.load_from_csv(rules_path)
        return cls(catalog)

    def assess_case(
        self,
        recon: CaseStateReconstruction,
        packet: Optional[CaseEvidencePacket] = None,
        request: Optional[DeletionRequest] = None,
        diagnostic: bool = False,
    ) -> CasePolicyAssessment:
        """Assess a single case's compliance, process risks, and restore risks at audit_at."""
        start_time = time.perf_counter()

        # Check authorization and diagnostic bypass
        # If the reconstruction was blocked due to non-deletion intent and diagnostic is False, remain blocked
        is_authorized = not recon.is_blocked
        is_diagnostic = diagnostic or recon.is_diagnostic_mode

        if not is_authorized and not is_diagnostic:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            is_non_deletion = (recon.blocking_reason and "NON_DELETION" in recon.blocking_reason) or (
                packet and packet.intent_decision == "NON_DELETION"
            )
            return CasePolicyAssessment(
                case_id=recon.case_id,
                audit_at=recon.audit_at,
                is_authorized_deletion=False,
                intent_status="NON_DELETION" if is_non_deletion else "BLOCKED",
                diagnostic_bypass=False,
                is_blocked=True,
                blocking_reason=recon.blocking_reason or "Intent authorization not established; blocked without diagnostic bypass.",
                resources={},
                process_risks=[],
                restore_risks=[],
                overall_compliance=PolicyComplianceOutcome.UNDETERMINED,
                violations_summary=[],
                unresolved_summary=["Intent authorization blocked; evaluation stopped."],
                coverage_limitations=[],
                evaluation_time_ms=elapsed_ms,
            )

        subject_identifiers = list(packet.subject_identifiers) if packet else []
        evaluator = PolicyEvaluator(catalog=self.catalog, audit_at=recon.audit_at)

        # 1. Evaluate each reconstructed resource
        evaluated_resources: dict[str, ResourcePolicyAssessment] = {}
        operational_resource_keys: list[str] = []
        for canon_key, res_agg in sorted(recon.resources.items()):
            if (
                res_agg.copies
                and all(copy.copy_key.copy_type == CopyType.SYSTEM_PROCESS for copy in res_agg.copies.values())
            ) or (
                res_agg.system_id == "integration_service"
                and res_agg.resource_id.startswith("data_flow_")
            ):
                operational_resource_keys.append(canon_key)
                continue
            # Inspect first copy facts/timeline to aid category classification
            first_copy = next(iter(res_agg.copies.values())) if res_agg.copies else None
            facts = {}
            timeline = []
            if first_copy:
                for ev in first_copy.timeline:
                    if ev.facts:
                        facts.update(ev.facts)
                timeline = list(first_copy.timeline)

            category, basis = GroundedCategoryClassifier.classify(
                system_id=res_agg.system_id,
                resource_id=res_agg.resource_id,
                store_locator=first_copy.copy_key.store_locator if first_copy else None,
                facts=facts,
                timeline=timeline,
                existing_label=res_agg.data_category,
            )

            res_assessment = evaluator.evaluate_resource(
                resource=res_agg,
                category=category,
                category_basis=basis,
                subject_identifiers=subject_identifiers,
            )
            evaluated_resources[canon_key] = res_assessment

        # 2. Assess process risks
        process_risks: list[ProcessRiskAssessment] = []
        unresolved_processes: list[str] = []
        if recon.process_observations:
            for pobs in recon.process_observations:
                if pobs.is_claim:
                    if pobs.state == ProcessState.DISABLED:
                        is_observed_disabled = any(
                            o.process_id == pobs.process_id and o.state == ProcessState.DISABLED and not o.is_claim
                            for o in recon.process_observations
                        )
                        if not is_observed_disabled:
                            process_risks.append(
                                ProcessRiskAssessment(
                                    process_id=pobs.process_id,
                                    system_id=pobs.system_id,
                                    target_resource=pobs.target_resource,
                                    target_copy=pobs.target_copy,
                                    risk_type="UNVERIFIED_DISABLE",
                                    is_active=True,
                                    details=f"Disable claimed for {pobs.process_id} in {pobs.system_id} but unverified in active process state.",
                                    supporting_evidence=[pobs.evidence_id] if pobs.evidence_id else [],
                                )
                            )
                    elif pobs.state == ProcessState.UNKNOWN:
                        unresolved_processes.append(
                            f"Process {pobs.process_id} state is supported only by an unverified operational claim."
                        )
                else:
                    if pobs.state == ProcessState.ENABLED:
                        process_risks.append(
                            ProcessRiskAssessment(
                                process_id=pobs.process_id,
                                system_id=pobs.system_id,
                                target_resource=pobs.target_resource,
                                target_copy=pobs.target_copy,
                                risk_type="ACTIVE_DATA_FLOW",
                                is_active=True,
                                details=f"Active data flow {pobs.process_id} observed enabled in {pobs.system_id}.",
                                supporting_evidence=[pobs.evidence_id] if pobs.evidence_id else [],
                            )
                        )
        else:
            for proc_str in recon.active_processes:
                proc_parts = proc_str.split(":", 1)
                proc_id = proc_parts[0]
                proc_type = proc_parts[1] if len(proc_parts) > 1 else "UNKNOWN"
                if proc_type == "CLAIMED_DISABLED":
                    process_risks.append(
                        ProcessRiskAssessment(
                            process_id=proc_id,
                            system_id="integration_service",
                            risk_type="UNVERIFIED_DISABLE",
                            is_active=True,
                            details="Disable claimed in activity log but unverified in active process state.",
                            supporting_evidence=[proc_id],
                        )
                    )
                elif proc_type == "STREAM_SYNC":
                    process_risks.append(
                        ProcessRiskAssessment(
                            process_id=proc_id,
                            system_id="integration_service",
                            risk_type="ACTIVE_STREAM_SYNC",
                            is_active=True,
                            details="Active stream sync observed or running.",
                            supporting_evidence=[proc_id],
                        )
                    )

        # 3. Assess restore risks
        restore_risks: list[RestoreRiskAssessment] = []
        if recon.restore_observations:
            for robs in recon.restore_observations:
                if robs.is_claim:
                    if robs.restore_state == RestoreState.BLOCKED:
                        is_observed_blocked = any(
                            o.backup_id == robs.backup_id and o.restore_state == RestoreState.BLOCKED and not o.is_claim
                            for o in recon.restore_observations
                        )
                        if not is_observed_blocked:
                            restore_risks.append(
                                RestoreRiskAssessment(
                                    backup_id=robs.backup_id,
                                    system_id=robs.system_id,
                                    target_resource=robs.target_resource,
                                    target_copy=robs.target_copy,
                                    risk_type="UNVERIFIED_BLOCK",
                                    is_blocked=False,
                                    details=f"Restore block claimed for {robs.backup_id} in {robs.system_id} but unverified in storage permissions.",
                                    supporting_evidence=[robs.evidence_id] if robs.evidence_id else [],
                                )
                            )
                else:
                    if robs.restore_state == RestoreState.ALLOWED:
                        restore_risks.append(
                            RestoreRiskAssessment(
                                backup_id=robs.backup_id,
                                system_id=robs.system_id,
                                target_resource=robs.target_resource,
                                target_copy=robs.target_copy,
                                risk_type="RESTORE_PERMITTED",
                                is_blocked=False,
                                details=f"Backup archive {robs.backup_id} in {robs.system_id} has restore access allowed.",
                                supporting_evidence=[robs.evidence_id] if robs.evidence_id else [],
                            )
                        )
        else:
            for rest_str in recon.restore_risks:
                if ":RESTORE_ALLOWED" in rest_str:
                    key = rest_str.replace(":RESTORE_ALLOWED", "")
                    sys_name, b_id = key.split(":", 1) if ":" in key else ("backup_service", key)
                    restore_risks.append(
                        RestoreRiskAssessment(
                            backup_id=b_id,
                            system_id=sys_name,
                            risk_type="RESTORE_PERMITTED",
                            is_blocked=False,
                            details=f"Backup archive {b_id} in {sys_name} has restore access allowed.",
                            supporting_evidence=[],
                        )
                    )
                elif ":CLAIMED_BLOCKED" in rest_str:
                    b_id = rest_str.split(":", 1)[0]
                    restore_risks.append(
                        RestoreRiskAssessment(
                            backup_id=b_id,
                            system_id="backup_service",
                            risk_type="UNVERIFIED_BLOCK",
                            is_blocked=False,
                            details="Restore block was claimed in activity log but unverified in storage permissions.",
                            supporting_evidence=[b_id],
                        )
                    )

        # 4. Synthesize overall compliance
        violations: list[str] = []
        unresolved: list[str] = []

        for c_key, res_ast in evaluated_resources.items():
            if res_ast.outcome == PolicyComplianceOutcome.VIOLATED:
                violations.append(f"Resource {c_key} violates policy {res_ast.rule_id} ({res_ast.data_category})")
            elif res_ast.outcome == PolicyComplianceOutcome.UNDETERMINED:
                unresolved.append(f"Resource {c_key} compliance is undetermined: {'; '.join(res_ast.missing_facts)}")

        for pr in process_risks:
            if pr.is_active:
                violations.append(f"Active data flow risk {pr.process_id} ({pr.risk_type})")

        for rr in restore_risks:
            if not rr.is_blocked:
                violations.append(f"Unblocked restore risk {rr.backup_id} ({rr.risk_type})")

        unresolved.extend(unresolved_processes)
        for canon_key in operational_resource_keys:
            process_id = canon_key.split(":", 1)[1]
            if not any(p.process_id == process_id for p in recon.process_observations):
                unresolved.append(f"Process {process_id} has no grounded current operational state.")

        coverage_limitations = (
            list(recon.diagnostics.deferred_files) + list(recon.diagnostics.unreadable_or_failed_files)
            if recon.diagnostics
            else []
        )

        # Distinguish demonstrated case-specific limitations from unknown corpus-level deferred files
        case_specific_limitations = [
            f"Resource {c_key} coverage limitation: {'; '.join(r.coverage_limitations)}"
            for c_key, r in evaluated_resources.items()
            if r.coverage_limitations
        ]
        if case_specific_limitations:
            unresolved.extend(case_specific_limitations)

        if violations:
            overall_outcome = PolicyComplianceOutcome.VIOLATED
        elif unresolved:
            overall_outcome = PolicyComplianceOutcome.UNDETERMINED
        elif evaluated_resources and all(r.outcome == PolicyComplianceOutcome.SATISFIED for r in evaluated_resources.values()):
            overall_outcome = PolicyComplianceOutcome.SATISFIED
        else:
            overall_outcome = PolicyComplianceOutcome.UNDETERMINED

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return CasePolicyAssessment(
            case_id=recon.case_id,
            audit_at=recon.audit_at,
            is_authorized_deletion=True,
            intent_status="AUTHORIZED_DELETION" if not is_diagnostic else "DIAGNOSTIC_BYPASS",
            diagnostic_bypass=is_diagnostic,
            is_blocked=False,
            resources=evaluated_resources,
            process_risks=process_risks,
            restore_risks=restore_risks,
            overall_compliance=overall_outcome,
            violations_summary=violations,
            unresolved_summary=unresolved,
            coverage_limitations=coverage_limitations,
            evaluation_time_ms=elapsed_ms,
        )

    def assess_batch(
        self,
        reconstructions: list[CaseStateReconstruction],
        packets: Optional[list[CaseEvidencePacket]] = None,
        diagnostic: bool = False,
    ) -> list[CasePolicyAssessment]:
        """Assess a batch of reconstructed cases."""
        packets_by_case = {p.case_id: p for p in packets} if packets else {}
        results: list[CasePolicyAssessment] = []
        for recon in reconstructions:
            p = packets_by_case.get(recon.case_id)
            assessment = self.assess_case(recon=recon, packet=p, diagnostic=diagnostic)
            results.append(assessment)
        return results
