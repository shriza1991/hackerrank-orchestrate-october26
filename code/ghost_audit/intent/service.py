"""Reusable intent-classification service over the existing model gateway."""

from __future__ import annotations

from ghost_audit.intent.models import (
    IntentClassificationResult,
    IntentModelOutput,
    IntentOperationalMetadata,
)
from ghost_audit.intent.prompt import PROMPT_VERSION, build_intent_messages
from ghost_audit.llm.errors import GatewayError
from ghost_audit.llm.gateway import ModelGateway
from ghost_audit.llm.types import ModelRequest
from ghost_audit.models.input_models import DeletionRequest


class IntentContextValidationError(GatewayError):
    """The response is schema-valid but not grounded in its request text."""


class IntentClassificationService:
    def __init__(self, gateway: ModelGateway):
        self.gateway = gateway

    def classify_request(
        self, request: DeletionRequest, *, run_id: str = "intent-classification"
    ) -> IntentClassificationResult:
        return self.classify_text(request.request_text, case_id=request.case_id, run_id=run_id)

    def classify_text(
        self, request_text: str, *, case_id: str | None = None,
        run_id: str = "intent-classification",
    ) -> IntentClassificationResult:
        if not isinstance(request_text, str) or not request_text.strip():
            raise ValueError("Request text must be a nonblank string.")
        before = len(self.gateway.usage.records)
        model_request = ModelRequest(
            task_name="classify_intent",
            template_version=PROMPT_VERSION,
            messages=build_intent_messages(request_text),
            response_model=IntentModelOutput,
            case_id=case_id,
            run_id=run_id,
        )
        result = self.gateway.call(model_request)
        if result.parsed.supporting_quote not in request_text:
            raise IntentContextValidationError(
                "Model supporting_quote is not an exact substring of the original request text."
            )
        records = self.gateway.usage.records[before:]
        metadata = IntentOperationalMetadata(
            case_id=case_id,
            prompt_version=PROMPT_VERSION,
            provider=result.provider,
            requested_model=result.requested_model,
            provider_model=result.provider_model,
            cache_hit=result.cache_hit,
            attempt_count=result.attempt_count,
            usage_attempt_ids=tuple(record.attempt_id for record in records),
            usage=result.usage,
        )
        return IntentClassificationResult(intent=result.parsed, metadata=metadata)
