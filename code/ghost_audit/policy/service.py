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
from ghost_audit.state.models import CaseStateReconstruction, ExistenceState


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
            return CasePolicyAssessment(
                case_id=recon.case_id,
                audit_at=recon.audit_at,
                is_authorized_deletion=False,
                intent_status="BLOCKED",
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
        for canon_key, res_agg in sorted(recon.resources.items()):
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
        for proc_str in recon.active_processes:
            # format: f"{activity_id}:{event_type}" or f"{act_id}:CLAIMED_DISABLED"
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
            elif proc_type in {"SYNC", "STREAM_SYNC", "RESTORE"}:
                process_risks.append(
                    ProcessRiskAssessment(
                        process_id=proc_id,
                        system_id="integration_service",
                        risk_type=f"ACTIVE_{proc_type}",
                        is_active=True,
                        details=f"Active data flow or sync process '{proc_type}' observed or running.",
                        supporting_evidence=[proc_id],
                    )
                )

        # 3. Assess restore risks
        restore_risks: list[RestoreRiskAssessment] = []
        for rest_str in recon.restore_risks:
            # format: f"{act_id}:CLAIMED_BLOCKED" or f"{canon_key}:RESTORE_ALLOWED"
            rest_parts = rest_str.split(":", 1)
            b_id = rest_parts[0]
            rest_type = rest_parts[1] if len(rest_parts) > 1 else "RESTORE_RISK"

            if rest_type == "CLAIMED_BLOCKED":
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
            elif rest_type == "RESTORE_ALLOWED":
                restore_risks.append(
                    RestoreRiskAssessment(
                        backup_id=b_id,
                        system_id="backup_service",
                        risk_type="RESTORE_PERMITTED",
                        is_blocked=False,
                        details="Backup archive restore access is currently permitted.",
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

        coverage_limitations = list(recon.diagnostics.deferred_files) + list(
            recon.diagnostics.unreadable_or_failed_files
        )

        if violations:
            overall_outcome = PolicyComplianceOutcome.VIOLATED
        elif unresolved or coverage_limitations:
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
