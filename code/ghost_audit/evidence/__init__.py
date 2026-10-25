"""Ghost Audit structured evidence ingestion package."""

from ghost_audit.evidence.models import (
    EvidenceIngestionSummary,
    FileIngestionResult,
    IngestionStatus,
    ObservationType,
)
from ghost_audit.evidence.service import EvidenceIngestionService


__all__ = [
    "EvidenceIngestionService",
    "EvidenceIngestionSummary",
    "FileIngestionResult",
    "IngestionStatus",
    "ObservationType",
]
