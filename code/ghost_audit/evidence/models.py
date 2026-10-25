"""Domain models for structured evidence ingestion."""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field

from ghost_audit.models.intermediate_models import EvidenceObservation


class IngestionStatus(str, Enum):
    """Ingestion outcome status for a manifest evidence file."""

    PARSED = "PARSED"      # Fully parsed structured file, facts extracted without fatal error
    PARTIAL = "PARTIAL"    # Parsed with warnings, unparsed fragments, or recoverable issues
    FAILED = "FAILED"      # Fatal parsing error (e.g. malformed JSON, SQL syntax/security error)
    DEFERRED = "DEFERRED"  # Multimodal files (PDF, image) explicitly deferred to Task 7


class ObservationType(str, Enum):
    """Classification of extracted evidence observations."""

    STORED_RECORD = "STORED_RECORD"      # Persisted database row, document, or export record
    LOOKUP_RESULT = "LOOKUP_RESULT"      # Query/lookup result (e.g. hit, NOT_FOUND, row count)
    INVENTORY_SCOPE = "INVENTORY_SCOPE"  # Scope boundary, table count, or empty collection
    PROCESS_CONFIG = "PROCESS_CONFIG"    # Data flow connector, backup restore permission
    OPERATIONAL_CLAIM = "OPERATIONAL_CLAIM"  # System export started, checkpoint, log claim
    RAW_FRAGMENT = "RAW_FRAGMENT"        # Unrecognized meaningful line preserved with diagnostics


class FileIngestionResult(BaseModel):
    """Structured ingestion result for a single evidence file."""

    model_config = ConfigDict(frozen=True)

    file_id: str
    file_path: str
    origin: str
    format: str
    status: IngestionStatus
    parser_name: str
    parser_version: str
    observation_count: int = 0
    observations: list[EvidenceObservation] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    unparsed_fragments: list[dict[str, Any]] = Field(default_factory=list)
    content_digest: Optional[str] = None
    execution_time_ms: float = 0.0


class EvidenceIngestionSummary(BaseModel):
    """Aggregate summary of evidence ingestion across manifest files."""

    model_config = ConfigDict(frozen=True)

    manifest_file_count: int
    parsed_count: int
    partial_count: int
    failed_count: int
    deferred_count: int
    total_observations: int
    by_format: dict[str, dict[str, int]] = Field(default_factory=dict)
    file_results: list[FileIngestionResult] = Field(default_factory=list)
    manifest_errors: list[str] = Field(default_factory=list)
