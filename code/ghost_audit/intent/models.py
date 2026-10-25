"""Strict semantic and operational contracts for request intent."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, model_validator

from ghost_audit.llm.types import ProviderUsage


class IntentDecision(str, Enum):
    """Whether the text itself authorizes deletion."""

    DELETION_REQUEST = "DELETION_REQUEST"
    NON_DELETION = "NON_DELETION"
    AMBIGUOUS = "AMBIGUOUS"


class IntentReason(str, Enum):
    """Small, stable taxonomy explaining an intent decision."""

    DIRECT_DELETION = "DIRECT_DELETION"
    PRIOR_DELETION_FOLLOWUP = "PRIOR_DELETION_FOLLOWUP"
    EXPORT_THEN_DELETE = "EXPORT_THEN_DELETE"
    ACCESS_OR_EXPORT_ONLY = "ACCESS_OR_EXPORT_ONLY"
    PROFILE_CORRECTION = "PROFILE_CORRECTION"
    MARKETING_OPT_OUT = "MARKETING_OPT_OUT"
    TEMPORARY_DEACTIVATION = "TEMPORARY_DEACTIVATION"
    INFORMATIONAL_QUESTION = "INFORMATIONAL_QUESTION"
    EXPLICIT_NON_DELETION = "EXPLICIT_NON_DELETION"
    CONFLICTING_INSTRUCTIONS = "CONFLICTING_INSTRUCTIONS"
    INSUFFICIENT_CLARITY = "INSUFFICIENT_CLARITY"


_REASONS_BY_DECISION = {
    IntentDecision.DELETION_REQUEST: {
        IntentReason.DIRECT_DELETION,
        IntentReason.PRIOR_DELETION_FOLLOWUP,
        IntentReason.EXPORT_THEN_DELETE,
    },
    IntentDecision.NON_DELETION: {
        IntentReason.ACCESS_OR_EXPORT_ONLY,
        IntentReason.PROFILE_CORRECTION,
        IntentReason.MARKETING_OPT_OUT,
        IntentReason.TEMPORARY_DEACTIVATION,
        IntentReason.INFORMATIONAL_QUESTION,
        IntentReason.EXPLICIT_NON_DELETION,
    },
    IntentDecision.AMBIGUOUS: {
        IntentReason.CONFLICTING_INSTRUCTIONS,
        IntentReason.INSUFFICIENT_CLARITY,
    },
}


class IntentModelOutput(BaseModel):
    """Only model-generated semantic fields; every property is required."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    decision: IntentDecision
    reason_code: IntentReason
    supporting_quote: StrictStr = Field(min_length=1, max_length=1000)
    explanation: StrictStr = Field(min_length=1, max_length=300)

    @model_validator(mode="after")
    def validate_reason_consistency(self) -> "IntentModelOutput":
        if self.reason_code not in _REASONS_BY_DECISION[self.decision]:
            raise ValueError(
                f"Reason {self.reason_code.value} is inconsistent with {self.decision.value}."
            )
        if not self.supporting_quote.strip() or not self.explanation.strip():
            raise ValueError("Supporting quote and explanation must be nonblank.")
        return self


@dataclass(frozen=True)
class IntentOperationalMetadata:
    """Non-semantic call provenance, kept outside model-controlled output."""

    case_id: str | None
    prompt_version: str
    provider: str
    requested_model: str
    provider_model: str | None
    cache_hit: bool
    attempt_count: int
    usage_attempt_ids: tuple[str, ...]
    usage: ProviderUsage | None
    classification_success: Literal[True] = True


@dataclass(frozen=True)
class IntentClassificationResult:
    intent: IntentModelOutput
    metadata: IntentOperationalMetadata


class CachedIntentEntry(BaseModel):
    """A classification bound to the exact input and model/prompt provenance."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    request_text_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    prompt_version: StrictStr = Field(min_length=1)
    provider: StrictStr | None
    model: StrictStr | None
    intent: IntentModelOutput


class IntentCacheFile(BaseModel):
    """Versioned, all-or-nothing precomputed intent cache file."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    version: Literal[1]
    classifications: dict[StrictStr, CachedIntentEntry]
