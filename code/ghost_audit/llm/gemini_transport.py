"""Google Gemini transport implemented with the official Google Gen AI SDK."""

from __future__ import annotations

import builtins
import socket
from typing import Any

from ghost_audit.llm.config import ModelSettings
from ghost_audit.llm.errors import (
    AuthenticationError,
    RateLimitError,
    ServerError,
    TimeoutError,
    TransportError,
)
from ghost_audit.llm.types import ModelRequest, ProviderResponse, ProviderUsage


def _nonnegative_int(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _gemini_json_schema(model) -> dict[str, Any]:
    """Convert Pydantic JSON Schema to Gemini's documented supported subset."""

    raw = model.model_json_schema()
    definitions = raw.get("$defs", {})
    supported = {
        "type", "properties", "required", "items", "prefixItems", "enum",
        "format", "minimum", "maximum", "minItems", "maxItems", "title",
        "description", "additionalProperties", "anyOf",
    }

    def adapt(value: Any) -> Any:
        if isinstance(value, list):
            return [adapt(item) for item in value]
        if not isinstance(value, dict):
            return value
        reference = value.get("$ref")
        if isinstance(reference, str) and reference.startswith("#/$defs/"):
            name = reference.rsplit("/", 1)[-1]
            return adapt(definitions[name])
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key == "$defs" or key not in supported:
                continue
            if key == "properties":
                result[key] = {name: adapt(schema) for name, schema in item.items()}
            else:
                result[key] = adapt(item)
        return result

    return adapt(raw)


class GeminiGenerateContentTransport:
    """Synchronous structured-output adapter for ``client.models.generate_content``."""

    _SUPPORTED_PARAMETERS = {
        "temperature", "top_p", "top_k", "candidate_count", "stop_sequences", "seed",
    }

    def send(self, request: ModelRequest, settings: ModelSettings) -> ProviderResponse:
        settings.require_live()
        try:
            from google import genai
            from google.genai import errors, types
        except ImportError as exc:
            raise TransportError(
                "Google Gen AI SDK is not installed; install google-genai.", retryable=False
            ) from exc

        unsupported = sorted(set(request.generation_parameters) - self._SUPPORTED_PARAMETERS)
        if unsupported:
            raise TransportError(
                f"Gemini transport does not support generation parameters: {unsupported}.",
                retryable=False,
            )

        systems = [message.content for message in request.messages if message.role == "system"]
        contents = []
        for message in request.messages:
            if message.role == "system":
                continue
            role = "model" if message.role == "assistant" else "user"
            contents.append(
                types.Content(role=role, parts=[types.Part.from_text(text=message.content)])
            )

        config_values: dict[str, Any] = {
            "system_instruction": "\n\n".join(systems) if systems else None,
            "response_mime_type": "application/json",
            "response_json_schema": _gemini_json_schema(request.response_model),
            **request.generation_parameters,
        }
        if settings.max_output_tokens is not None:
            config_values["max_output_tokens"] = settings.max_output_tokens

        client = genai.Client(
            api_key=settings.api_key,
            http_options=types.HttpOptions(
                timeout=int(settings.request_timeout * 1000),
                retry_options=types.HttpRetryOptions(attempts=1),
            ),
        )
        try:
            response = client.models.generate_content(
                model=settings.model or "",
                contents=contents,
                config=types.GenerateContentConfig(**config_values),
            )
        except errors.APIError as exc:
            raise self._map_api_error(exc) from None
        except (socket.timeout, builtins.TimeoutError) as exc:
            raise TimeoutError("Model request timed out.", retryable=True) from exc
        except OSError as exc:
            raise TransportError("Unable to connect to model provider.", retryable=True) from exc
        finally:
            client.close()

        usage = self._usage(response.usage_metadata)
        candidates = response.candidates or []
        finish_reasons = {
            str(getattr(candidate, "finish_reason", "")).upper() for candidate in candidates
        }
        truncated = any("MAX_TOKENS" in reason for reason in finish_reasons)
        blocked = getattr(getattr(response, "prompt_feedback", None), "block_reason", None)
        refusal = None
        if blocked:
            refusal = "Gemini blocked the structured request."
        elif any(
            token in reason
            for reason in finish_reasons
            for token in ("SAFETY", "BLOCKLIST", "PROHIBITED", "SPII", "RECITATION")
        ):
            refusal = "Gemini refused the structured request."

        return ProviderResponse(
            content=response.text if isinstance(response.text, str) else None,
            model=getattr(response, "model_version", None) or settings.model,
            usage=usage,
            request_id=getattr(response, "response_id", None),
            truncated=truncated,
            refusal=refusal,
        )

    @staticmethod
    def _usage(metadata: Any) -> ProviderUsage | None:
        if metadata is None:
            return None
        input_tokens = _nonnegative_int(getattr(metadata, "prompt_token_count", None))
        output_tokens = _nonnegative_int(getattr(metadata, "candidates_token_count", None))
        input_details: dict[str, int] = {}
        output_details: dict[str, int] = {}
        cached = _nonnegative_int(getattr(metadata, "cached_content_token_count", None))
        thoughts = _nonnegative_int(getattr(metadata, "thoughts_token_count", None))
        tool_prompt = _nonnegative_int(getattr(metadata, "tool_use_prompt_token_count", None))
        if cached is not None:
            input_details["cached_content_tokens"] = cached
        if tool_prompt is not None:
            input_details["tool_use_prompt_tokens"] = tool_prompt
        if thoughts is not None:
            output_details["thoughts_tokens"] = thoughts
        return ProviderUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            input_details=input_details,
            output_details=output_details,
        )

    @staticmethod
    def _map_api_error(exc) -> TransportError:
        code = getattr(exc, "code", None)
        request_id = None
        response = getattr(exc, "response", None)
        headers = getattr(response, "headers", None)
        if headers:
            request_id = headers.get("x-request-id") or headers.get("x-goog-request-id")
        if code in {401, 403}:
            return AuthenticationError("Provider authentication or permission failed.")
        if code == 429:
            return RateLimitError("Provider rate limit reached.", retryable=True, request_id=request_id)
        if isinstance(code, int) and code >= 500:
            return ServerError("Provider server failure.", retryable=True, request_id=request_id)
        return TransportError("Provider rejected request.", retryable=False, request_id=request_id)
