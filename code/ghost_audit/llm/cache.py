"""Content-addressed cache for validated structured responses."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from ghost_audit.llm.errors import CacheError
from ghost_audit.llm.types import ModelRequest, ProviderUsage

CACHE_VERSION = 1


def request_fingerprint(request: ModelRequest, *, endpoint: str, provider: str, model: str,
                        max_output_tokens: int | None) -> str:
    value = {
        "version": CACHE_VERSION,
        "endpoint": endpoint,
        "provider": provider,
        "model": model,
        "task_name": request.task_name,
        "template_version": request.template_version,
        "messages": [message.model_dump(mode="json") for message in request.messages],
        "schema": request.response_model.model_json_schema(),
        "generation_parameters": request.generation_parameters,
        "max_output_tokens": max_output_tokens,
    }
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CacheError(f"Request cannot be deterministically cached: {exc}") from exc
    return hashlib.sha256(encoded).hexdigest()


class ResponseCache:
    def __init__(self, directory: Path):
        self.directory = Path(directory)

    def path_for(self, key: str) -> Path:
        return self.directory / f"{key}.json"

    def load(self, key: str, response_model: type[BaseModel]) -> tuple[BaseModel, dict] | None:
        path = self.path_for(key)
        if not path.exists():
            return None
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(record, dict):
                raise CacheError(f"Corrupted cache entry: {path}")
            if record.get("version") != CACHE_VERSION:
                raise CacheError(f"Incompatible cache entry: {path}")
            # Fresh responses use strict JSON validation. Re-serialize the
            # JSON-compatible cached value through the same path so enum values
            # behave identically without permitting primitive coercion.
            parsed = response_model.model_validate_json(
                json.dumps(record["parsed"], ensure_ascii=False), strict=True
            )
            for name in ("provider_model", "provider_request_id"):
                if record.get(name) is not None and not isinstance(record.get(name), str):
                    raise CacheError(f"Corrupted cache entry: {path}")
            usage_value = record.get("usage")
            if usage_value is not None:
                if not isinstance(usage_value, dict):
                    raise CacheError(f"Corrupted cache entry: {path}")
                ProviderUsage(**usage_value)
            return parsed, record
        except CacheError:
            raise
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError,
                AttributeError, ValidationError) as exc:
            raise CacheError(f"Corrupted cache entry: {path}") from exc

    def store(self, key: str, *, parsed: BaseModel, provider_model: str | None,
              request_id: str | None, usage: ProviderUsage | None) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        record: dict[str, Any] = {
            "version": CACHE_VERSION,
            "parsed": parsed.model_dump(mode="json"),
            "provider_model": provider_model,
            "provider_request_id": request_id,
            "usage": asdict(usage) if usage is not None else None,
        }
        target = self.path_for(key)
        try:
            fd, temp_name = tempfile.mkstemp(prefix=f".{key}.", suffix=".tmp", dir=self.directory)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(record, handle, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                handle.flush(); os.fsync(handle.fileno())
            os.replace(temp_name, target)
        except OSError as exc:
            raise CacheError(f"Unable to write cache entry: {target}") from exc
        finally:
            if 'temp_name' in locals() and os.path.exists(temp_name):
                os.unlink(temp_name)
