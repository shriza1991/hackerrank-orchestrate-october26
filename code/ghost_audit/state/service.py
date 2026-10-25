"""High-level service coordinating case-level resource-state reconstruction."""

from __future__ import annotations

from typing import Sequence

from ghost_audit.retrieval.models import CaseEvidencePacket
from ghost_audit.state.models import CaseStateReconstruction
from ghost_audit.state.reconstruction import ResourceStateEngine


class ResourceStateReconstructionService:
    """Service providing state reconstruction over validated CaseEvidencePacket objects."""

    def reconstruct_case(self, packet: CaseEvidencePacket) -> CaseStateReconstruction:
        """Reconstruct resource state for a single case evidence packet."""
        engine = ResourceStateEngine(audit_at=packet.audit_at)
        return engine.reconstruct_case_state(packet)

    def reconstruct_batch(
        self,
        packets: Sequence[CaseEvidencePacket],
    ) -> list[CaseStateReconstruction]:
        """Reconstruct resource states for a batch of case evidence packets deterministically."""
        sorted_packets = sorted(packets, key=lambda p: p.case_id)
        results: list[CaseStateReconstruction] = []
        for pkt in sorted_packets:
            results.append(self.reconstruct_case(pkt))
        return results
