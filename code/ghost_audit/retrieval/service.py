"""High-level evidence retrieval service managing case-level retrieval pipelines."""

from __future__ import annotations

import time
from typing import Optional, Sequence

from ghost_audit.identity.service import IdentityResolutionService
from ghost_audit.intent.models import IntentDecision
from ghost_audit.intent.service import IntentClassificationService
from ghost_audit.models.input_models import DeletionRequest
from ghost_audit.models.intermediate_models import IdentityResolutionStatus
from ghost_audit.retrieval.index import CorpusIndex
from ghost_audit.retrieval.linker import EvidenceLinker
from ghost_audit.retrieval.models import CaseEvidencePacket, RetrievalDiagnostics


class EvidenceRetrievalService:
    """Unified service for deterministic, offline evidence linking and retrieval."""

    def __init__(
        self,
        index: CorpusIndex,
        identity_service: IdentityResolutionService,
        intent_service: Optional[IntentClassificationService] = None,
        max_depth: int = 5,
    ) -> None:
        self.index = index
        self.identity_service = identity_service
        self.intent_service = intent_service
        self.linker = EvidenceLinker(index=index, max_depth=max_depth)

    def retrieve_for_case(
        self,
        case: DeletionRequest,
        diagnostic_mode: bool = False,
    ) -> CaseEvidencePacket:
        """Retrieve evidence packet for a single deletion audit case at its audit_at cutoff."""
        start_time = time.perf_counter()

        # 1. Intent Classification Check
        intent_decision: Optional[str] = None
        if diagnostic_mode:
            intent_decision = "BYPASS_DIAGNOSTIC"
        else:
            if self.intent_service:
                try:
                    intent_res = self.intent_service.classify(case.request_text)
                    intent_decision = intent_res.decision.value

                    if intent_res.decision == IntentDecision.NON_DELETION:
                        diag = RetrievalDiagnostics(
                            case_id=case.case_id,
                            audit_at=case.audit_at,
                            coverage_warnings=["Request does not authorize deletion."],
                            execution_time_ms=(time.perf_counter() - start_time) * 1000,
                        )
                        return CaseEvidencePacket(
                            case_id=case.case_id,
                            email=case.email,
                            requested_at=case.requested_at,
                            reported_status=case.reported_status.value if hasattr(case.reported_status, "value") else str(case.reported_status),
                            reported_at=case.reported_at,
                            audit_at=case.audit_at,
                            intent_decision=intent_decision,
                            identity_status=IdentityResolutionStatus.UNRESOLVED,
                            diagnostics=diag,
                            is_blocked=True,
                            blocking_reason=f"NON_DELETION: Intent classification determined non-deletion ({intent_res.reason.value}). Investigation skipped.",
                        )
                    elif intent_res.decision == IntentDecision.AMBIGUOUS:
                        diag = RetrievalDiagnostics(
                            case_id=case.case_id,
                            audit_at=case.audit_at,
                            coverage_warnings=["Request intent is ambiguous."],
                            execution_time_ms=(time.perf_counter() - start_time) * 1000,
                        )
                        return CaseEvidencePacket(
                            case_id=case.case_id,
                            email=case.email,
                            requested_at=case.requested_at,
                            reported_status=case.reported_status.value if hasattr(case.reported_status, "value") else str(case.reported_status),
                            reported_at=case.reported_at,
                            audit_at=case.audit_at,
                            intent_decision=intent_decision,
                            identity_status=IdentityResolutionStatus.UNRESOLVED,
                            diagnostics=diag,
                            is_blocked=True,
                            blocking_reason="AMBIGUOUS: Request intent is ambiguous and cannot be verified as an authorized deletion request.",
                        )
                except Exception as ex:
                    # When offline without model configured, fall back to explicit diagnostic bypass note
                    intent_decision = f"ERROR_FALLBACK:{type(ex).__name__}"
            else:
                intent_decision = "DELETION_REQUEST"

        # 2. Identity Resolution
        id_result = self.identity_service.resolve_request(case)
        if id_result.resolution_status != IdentityResolutionStatus.RESOLVED:
            diag = RetrievalDiagnostics(
                case_id=case.case_id,
                audit_at=case.audit_at,
                coverage_warnings=[f"Identity resolution status: {id_result.resolution_status.value}."],
                execution_time_ms=(time.perf_counter() - start_time) * 1000,
            )
            return CaseEvidencePacket(
                case_id=case.case_id,
                email=case.email,
                requested_at=case.requested_at,
                reported_status=case.reported_status.value if hasattr(case.reported_status, "value") else str(case.reported_status),
                reported_at=case.reported_at,
                audit_at=case.audit_at,
                intent_decision=intent_decision,
                identity_status=id_result.resolution_status,
                stable_subject_reference=None,
                diagnostics=diag,
                is_blocked=True,
                blocking_reason=f"IDENTITY_UNRESOLVED: Resolution status is {id_result.resolution_status.value}. Evidence linking blocked.",
            )

        # 3. Deterministic Evidence Linking
        (
            selected_obs,
            selected_acts,
            scoped_inv,
            links,
            grounded_res,
            rejected_links,
            diagnostics,
        ) = self.linker.link_case(
            case_id=case.case_id,
            audit_at=case.audit_at,
            identity_result=id_result,
        )

        # Extract subject identifiers for packet
        subject_idents = self.linker._extract_subject_identifiers(id_result)["all"]

        return CaseEvidencePacket(
            case_id=case.case_id,
            email=case.email,
            requested_at=case.requested_at,
            reported_status=case.reported_status.value if hasattr(case.reported_status, "value") else str(case.reported_status),
            reported_at=case.reported_at,
            audit_at=case.audit_at,
            intent_decision=intent_decision,
            identity_status=id_result.resolution_status,
            stable_subject_reference=id_result.stable_subject_reference,
            subject_identifiers=subject_idents,
            grounded_resources=grounded_res,
            selected_observations=selected_obs,
            selected_activities=selected_acts,
            scoped_inventories=scoped_inv,
            linking_graph=links,
            ambiguous_or_rejected_links=rejected_links,
            diagnostics=diagnostics,
            is_blocked=False,
            blocking_reason=None,
        )

    def retrieve_batch(
        self,
        cases: Sequence[DeletionRequest],
        diagnostic_mode: bool = False,
    ) -> list[CaseEvidencePacket]:
        """Process a sequence of cases deterministically and return their evidence packets."""
        sorted_cases = sorted(cases, key=lambda c: c.case_id)
        packets = []
        for case in sorted_cases:
            packets.append(self.retrieve_for_case(case, diagnostic_mode=diagnostic_mode))
        return packets
