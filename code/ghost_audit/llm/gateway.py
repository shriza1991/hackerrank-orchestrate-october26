"""Structured model gateway with bounded retries, caching, and observability."""

from __future__ import annotations

import json
import time
from typing import Callable

from pydantic import ValidationError

from ghost_audit.llm.cache import ResponseCache, request_fingerprint
from ghost_audit.llm.config import ModelSettings
from ghost_audit.llm.errors import (
    AuthenticationError, InvalidStructuredResponseError, RateLimitError,
    RefusalError, ServerError, TimeoutError, TransportError, TruncatedResponseError,
)
from ghost_audit.llm.transport import ModelTransport
from ghost_audit.llm.types import ModelRequest, ModelResult, ProviderUsage, UsageRecord
from ghost_audit.llm.usage import UsageTracker, estimate_cost


class ModelGateway:
    def __init__(self, settings: ModelSettings, transport: ModelTransport, *,
                 usage: UsageTracker | None = None, cache: ResponseCache | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        self.settings = settings
        self.transport = transport
        self.usage = usage or UsageTracker()
        self.cache = cache or ResponseCache(settings.cache_dir)
        self.sleep = sleep
        self.clock = clock

    def call(self, request: ModelRequest):
        self.settings.require_live()
        requested_model = self.settings.model or ""
        key = request_fingerprint(request, endpoint=self.settings.endpoint_identity,
                                  provider=self.settings.provider, model=requested_model,
                                  max_output_tokens=self.settings.max_output_tokens)
        logical_id = f"{request.run_id}:{len({record.logical_request_id for record in self.usage.records}) + 1}"
        start = self.clock()
        if self.settings.cache_enabled:
            cached = self.cache.load(key, request.response_model)
            if cached is not None:
                parsed, record = cached
                original = ProviderUsage(**record["usage"]) if record.get("usage") is not None else None
                self.usage.add(self._record(request, logical_id, 0, "CACHE_HIT", False, original,
                                            record.get("provider_model"), 0.0,
                                            record.get("provider_request_id"), reused=True))
                return ModelResult(parsed, requested_model, record.get("provider_model"),
                                   self.settings.provider, True, 0, self.clock() - start, original,
                                   record.get("provider_request_id"))

        for attempt in range(1, self.settings.max_attempts + 1):
            attempt_start = self.clock()
            try:
                response = self.transport.send(request, self.settings)
            except AuthenticationError:
                self.usage.add(self._record(request, logical_id, attempt, "AUTHENTICATION_ERROR", True,
                                            None, None, self.clock() - attempt_start, None))
                raise AuthenticationError("Provider authentication or permission failed.") from None
            except TransportError as exc:
                latency = self.clock() - attempt_start
                self.usage.add(self._record(request, logical_id, attempt, type(exc).__name__.upper(), True,
                                            exc.usage, None, latency, exc.request_id))
                if not exc.retryable or attempt >= self.settings.max_attempts:
                    raise self._safe_transport_error(exc) from None
                exponential = self.settings.initial_backoff * (2 ** (attempt - 1))
                if exc.retry_after is not None and exc.retry_after > self.settings.max_backoff:
                    raise self._safe_transport_error(exc) from None
                delay = min(self.settings.max_backoff, max(exponential, exc.retry_after or 0.0))
                self.sleep(delay)
                continue

            latency = self.clock() - attempt_start
            if response.truncated:
                self.usage.add(self._record(request, logical_id, attempt, "TRUNCATED", True, response.usage,
                                            response.model, latency, response.request_id))
                raise TruncatedResponseError("Provider response was incomplete or truncated.")
            if response.refusal is not None:
                self.usage.add(self._record(request, logical_id, attempt, "REFUSAL", True, response.usage,
                                            response.model, latency, response.request_id))
                raise RefusalError("Provider refused the structured request.")
            if response.content is None or not response.content.strip():
                self.usage.add(self._record(request, logical_id, attempt, "INVALID_RESPONSE", True, response.usage,
                                            response.model, latency, response.request_id))
                raise InvalidStructuredResponseError("Provider returned an empty structured response.")
            try:
                parsed = request.response_model.model_validate_json(response.content, strict=True)
            except (ValidationError, json.JSONDecodeError, ValueError) as exc:
                self.usage.add(self._record(request, logical_id, attempt, "INVALID_RESPONSE", True, response.usage,
                                            response.model, latency, response.request_id))
                raise InvalidStructuredResponseError("Provider response failed strict schema validation.") from exc

            self.usage.add(self._record(request, logical_id, attempt, "SUCCESS", True, response.usage,
                                        response.model, latency, response.request_id))
            if self.settings.cache_enabled:
                self.cache.store(key, parsed=parsed, provider_model=response.model,
                                 request_id=response.request_id, usage=response.usage)
            return ModelResult(parsed, requested_model, response.model, self.settings.provider,
                               False, attempt, self.clock() - start, response.usage, response.request_id)
        raise AssertionError("bounded attempt loop exhausted unexpectedly")

    def _record(self, request, logical_id: str, attempt: int, outcome: str, new: bool,
                usage: ProviderUsage | None, provider_model: str | None, latency: float,
                provider_request_id: str | None, reused: bool = False) -> UsageRecord:
        return UsageRecord(
            logical_request_id=logical_id, run_id=request.run_id, task_name=request.task_name,
            case_id=request.case_id, attempt_id=f"{logical_id}:{attempt}", outcome=outcome,
            provider=self.settings.provider, requested_model=self.settings.model or "",
            provider_model=provider_model,
            input_tokens=usage.input_tokens if usage is not None and new else None,
            output_tokens=usage.output_tokens if usage is not None and new else None,
            input_details=usage.input_details if usage is not None and new else {},
            output_details=usage.output_details if usage is not None and new else {},
            estimated_cost=estimate_cost(usage, self.settings.input_price_per_million,
                                         self.settings.output_price_per_million) if new else None,
            new_api_request=new,
            reused_input_tokens=(usage.input_tokens or 0) if reused and usage else 0,
            reused_output_tokens=(usage.output_tokens or 0) if reused and usage else 0,
            latency_seconds=latency, provider_request_id=provider_request_id,
        )

    @staticmethod
    def _safe_transport_error(error: TransportError) -> TransportError:
        kwargs = {"retryable": error.retryable, "retry_after": error.retry_after,
                  "usage": error.usage, "request_id": error.request_id}
        if isinstance(error, RateLimitError):
            return RateLimitError("Provider rate limit reached.", **kwargs)
        if isinstance(error, TimeoutError):
            return TimeoutError("Model request timed out.", **kwargs)
        if isinstance(error, ServerError):
            return ServerError("Provider server failure.", **kwargs)
        return TransportError("Model provider request failed.", **kwargs)
