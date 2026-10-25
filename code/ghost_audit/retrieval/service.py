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
        failed_files: Sequence[str] = (),
        deferred_files: Sequence[str] = (),
        manifest_errors: Sequence[str] = (),
    ) -> None:
        self.index = index
        self.identity_service = identity_service
        self.intent_service = intent_service
        self.failed_files = list(failed_files)
        self.deferred_files = list(deferred_files)
        self.manifest_errors = list(manifest_errors)
        self.linker = EvidenceLinker(index=index, max_depth=max_depth)

    def retrieve_for_case(
        self,
        case: DeletionRequest,
        diagnostic_mode: bool = False,
        precomputed_intent: Optional[Any] = None,
    ) -> CaseEvidencePacket:
        """Retrieve evidence packet for a single deletion audit case at its audit_at cutoff."""
        start_time = time.perf_counter()

        # 1. Intent Classification Check
        intent_decision: Optional[str] = None
        if diagnostic_mode:
            intent_decision = "BYPASS_DIAGNOSTIC"
        elif precomputed_intent is not None:
            if hasattr(precomputed_intent, "intent"):
                dec = precomputed_intent.intent.decision
                reason = getattr(precomputed_intent.intent.reason_code, "value", str(precomputed_intent.intent.reason_code))
            else:
                dec = getattr(precomputed_intent, "decision", None)
                reason = getattr(precomputed_intent, "reason_code", getattr(precomputed_intent, "reason", "UNKNOWN"))

            intent_decision = dec.value if hasattr(dec, "value") else str(dec)
            if dec == IntentDecision.NON_DELETION:
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
                    blocking_reason=f"NON_DELETION: Intent classification determined non-deletion ({reason}). Investigation skipped.",
                )
            elif dec == IntentDecision.AMBIGUOUS:
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
                    blocking_reason=f"AMBIGUOUS: Request intent is ambiguous ({reason}). Investigation blocked.",
                )
            elif dec != IntentDecision.DELETION_REQUEST:
                diag = RetrievalDiagnostics(
                    case_id=case.case_id,
                    audit_at=case.audit_at,
                    coverage_warnings=[f"Unrecognized intent decision: {dec}"],
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
                    blocking_reason=f"INTENT_UNRESOLVED: Invalid intent decision {dec}. Investigation blocked.",
                )
        else:
            if self.intent_service:
                try:
                    if hasattr(self.intent_service, "classify_request"):
                        intent_res = self.intent_service.classify_request(case)
                    elif hasattr(self.intent_service, "classify_text"):
                        intent_res = self.intent_service.classify_text(case.request_text, case_id=case.case_id)
                    else:
                        intent_res = self.intent_service.classify(case.request_text)

                    if hasattr(intent_res, "intent"):
                        dec = intent_res.intent.decision
                        reason = getattr(intent_res.intent.reason_code, "value", str(intent_res.intent.reason_code))
                    else:
                        dec = getattr(intent_res, "decision", None)
                        reason = getattr(intent_res, "reason_code", getattr(intent_res, "reason", "UNKNOWN"))

                    intent_decision = dec.value if hasattr(dec, "value") else str(dec)

                    if dec == IntentDecision.NON_DELETION:
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
                            blocking_reason=f"NON_DELETION: Intent classification determined non-deletion ({reason}). Investigation skipped.",
                        )
                    elif dec == IntentDecision.AMBIGUOUS:
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
                            blocking_reason=f"AMBIGUOUS: Request intent is ambiguous ({reason}). Investigation blocked.",
                        )
                    elif dec != IntentDecision.DELETION_REQUEST:
                        diag = RetrievalDiagnostics(
                            case_id=case.case_id,
                            audit_at=case.audit_at,
                            coverage_warnings=[f"Unrecognized intent decision: {dec}"],
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
                            blocking_reason=f"INTENT_UNRESOLVED: Invalid intent decision {dec}. Investigation blocked.",
                        )
                except Exception as ex:
                    # Missing classification, configuration failure, or provider failure must NOT authorize investigation!
                    diag = RetrievalDiagnostics(
                        case_id=case.case_id,
                        audit_at=case.audit_at,
                        coverage_warnings=[f"Intent classification failed: {type(ex).__name__}: {str(ex)}"],
                        execution_time_ms=(time.perf_counter() - start_time) * 1000,
                    )
                    return CaseEvidencePacket(
                        case_id=case.case_id,
                        email=case.email,
                        requested_at=case.requested_at,
                        reported_status=case.reported_status.value if hasattr(case.reported_status, "value") else str(case.reported_status),
                        reported_at=case.reported_at,
                        audit_at=case.audit_at,
                        intent_decision=f"ERROR:{type(ex).__name__}",
                        identity_status=IdentityResolutionStatus.UNRESOLVED,
                        diagnostics=diag,
                        is_blocked=True,
                        blocking_reason=f"INTENT_UNRESOLVED: Intent classification failed ({type(ex).__name__}). Investigation not authorized without explicit diagnostic mode.",
                    )
            else:
                # Missing intent service must NOT authorize investigation!
                diag = RetrievalDiagnostics(
                    case_id=case.case_id,
                    audit_at=case.audit_at,
                    coverage_warnings=["No intent classification service provided."],
                    execution_time_ms=(time.perf_counter() - start_time) * 1000,
                )
                return CaseEvidencePacket(
                    case_id=case.case_id,
                    email=case.email,
                    requested_at=case.requested_at,
                    reported_status=case.reported_status.value if hasattr(case.reported_status, "value") else str(case.reported_status),
                    reported_at=case.reported_at,
                    audit_at=case.audit_at,
                    intent_decision=None,
                    identity_status=IdentityResolutionStatus.UNRESOLVED,
                    diagnostics=diag,
                    is_blocked=True,
                    blocking_reason="INTENT_UNRESOLVED: No intent classification provided and diagnostic mode not enabled. Investigation blocked.",
                )

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
            failed_files=self.failed_files,
            deferred_files=self.deferred_files,
            manifest_errors=self.manifest_errors,
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
