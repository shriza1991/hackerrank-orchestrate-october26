"""Replaceable transport plus one real OpenAI Responses API adapter."""

from __future__ import annotations

import json
import builtins
import socket
import urllib.error
import urllib.request
from typing import Any, Protocol

from ghost_audit.llm.config import ModelSettings
from ghost_audit.llm.errors import AuthenticationError, RateLimitError, ServerError, TimeoutError, TransportError
from ghost_audit.llm.types import ModelRequest, ProviderResponse, ProviderUsage


class ModelTransport(Protocol):
    def send(self, request: ModelRequest, settings: ModelSettings) -> ProviderResponse: ...


def _usage(value: Any) -> ProviderUsage | None:
    if not isinstance(value, dict):
        return None
    input_details = value.get("input_tokens_details") if isinstance(value.get("input_tokens_details"), dict) else {}
    output_details = value.get("output_tokens_details") if isinstance(value.get("output_tokens_details"), dict) else {}
    return ProviderUsage(
        input_tokens=value.get("input_tokens") if type(value.get("input_tokens")) is int else None,
        output_tokens=value.get("output_tokens") if type(value.get("output_tokens")) is int else None,
        input_details={k: v for k, v in input_details.items() if type(v) is int and v >= 0},
        output_details={k: v for k, v in output_details.items() if type(v) is int and v >= 0},
    )


class OpenAIResponsesTransport:
    """Dependency-free HTTPS adapter for ``POST /v1/responses``."""

    def send(self, request: ModelRequest, settings: ModelSettings) -> ProviderResponse:
        settings.require_live()
        schema = request.response_model.model_json_schema()
        payload: dict[str, Any] = {
            "model": settings.model,
            "input": [message.model_dump(mode="json") for message in request.messages],
            "text": {"format": {"type": "json_schema", "name": request.task_name,
                                "strict": True, "schema": schema}},
            "store": False,
        }
        payload.update(request.generation_parameters)
        if settings.max_output_tokens is not None:
            payload["max_output_tokens"] = settings.max_output_tokens
        url = settings.api_base_url.rstrip("/") + "/responses"
        http_request = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), method="POST",
            headers={"Authorization": f"Bearer {settings.api_key}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(http_request, timeout=settings.request_timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
                header_request_id = response.headers.get("x-request-id")
        except urllib.error.HTTPError as exc:
            self._raise_http(exc)
        except (TimeoutError,):
            raise
        except (socket.timeout, builtins.TimeoutError) as exc:
            raise TimeoutError("Model request timed out.", retryable=True) from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, socket.timeout):
                raise TimeoutError("Model request timed out.", retryable=True) from exc
            raise TransportError("Unable to connect to model provider.", retryable=True) from exc
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise TransportError("Provider returned an unreadable response.", retryable=False) from exc

        status = body.get("status")
        truncated = status == "incomplete" or bool(body.get("incomplete_details"))
        text_parts: list[str] = []
        refusal = None
        for output in body.get("output", []) if isinstance(body.get("output"), list) else []:
            for content in output.get("content", []) if isinstance(output, dict) and isinstance(output.get("content"), list) else []:
                if not isinstance(content, dict):
                    continue
                if content.get("type") == "refusal" or content.get("refusal"):
                    refusal = str(content.get("refusal") or "Provider refused the request.")
                elif content.get("type") == "output_text" and isinstance(content.get("text"), str):
                    text_parts.append(content["text"])
        return ProviderResponse(
            content="".join(text_parts) or None,
            model=body.get("model") if isinstance(body.get("model"), str) else None,
            usage=_usage(body.get("usage")),
            request_id=header_request_id or (body.get("id") if isinstance(body.get("id"), str) else None),
            truncated=truncated,
            refusal=refusal,
        )

    @staticmethod
    def _raise_http(exc: urllib.error.HTTPError) -> None:
        status = exc.code
        request_id = exc.headers.get("x-request-id") if exc.headers else None
        error_code = None
        try:
            error_body = json.loads(exc.read().decode("utf-8"))
            error_value = error_body.get("error") if isinstance(error_body, dict) else None
            if isinstance(error_value, dict) and isinstance(error_value.get("code"), str):
                error_code = error_value["code"]
        except (OSError, UnicodeError, json.JSONDecodeError):
            pass
        retry_after = None
        if exc.headers and exc.headers.get("Retry-After"):
            try:
                retry_after = max(0.0, float(exc.headers["Retry-After"]))
            except ValueError:
                retry_after = None
        # Deliberately exclude the provider body: it can echo submitted content
        # or other sensitive details. Stable categories are enough for callers.
        if status in {401, 403}:
            raise AuthenticationError(f"Provider authentication or permission failed (HTTP {status}).")
        if status == 429:
            nonretryable_limits = {
                "credit_balance_exhausted", "organization_spend_limit_exceeded",
                "project_spend_limit_exceeded", "organization_usage_limit_exceeded",
            }
            if error_code in nonretryable_limits:
                raise TransportError("Provider account limit prevents this request.", retryable=False,
                                     request_id=request_id)
            raise RateLimitError("Provider rate limit reached.", retryable=True,
                                 retry_after=retry_after, request_id=request_id)
        if status in {408, 409}:
            raise TransportError(f"Transient provider error (HTTP {status}).", retryable=True,
                                 retry_after=retry_after, request_id=request_id)
        if status >= 500:
            raise ServerError(f"Provider server failure (HTTP {status}).", retryable=True,
                              retry_after=retry_after, request_id=request_id)
        raise TransportError(f"Provider rejected request (HTTP {status}).", retryable=False,
                             request_id=request_id)
