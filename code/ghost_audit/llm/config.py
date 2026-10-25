"""Environment-backed model settings with deferred live-call requirements."""

from __future__ import annotations

import os
import math
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Mapping

from ghost_audit.config import REPO_ROOT
from ghost_audit.llm.errors import ConfigurationError


def _decimal(env: Mapping[str, str], name: str) -> Decimal | None:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return None
    try:
        value = Decimal(raw)
    except InvalidOperation as exc:
        raise ConfigurationError(f"{name} must be a decimal number.") from exc
    if not value.is_finite() or value < 0:
        raise ConfigurationError(f"{name} must be nonnegative.")
    return value


def _float(env: Mapping[str, str], name: str, default: float) -> float:
    try:
        value = float(env.get(name, str(default)))
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be numeric.") from exc
    if not math.isfinite(value) or value < 0:
        raise ConfigurationError(f"{name} must be nonnegative.")
    return value


def _int(env: Mapping[str, str], name: str, default: int | None) -> int | None:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer.") from exc


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false.")


@dataclass(frozen=True)
class ModelSettings:
    api_key: str | None = None
    model: str | None = None
    api_base_url: str = "https://api.openai.com/v1"
    provider: str = "openai"
    request_timeout: float = 30.0
    max_attempts: int = 3
    initial_backoff: float = 0.5
    max_backoff: float = 8.0
    cache_enabled: bool = True
    cache_dir: Path = REPO_ROOT / ".cache" / "ghost_audit_llm"
    input_price_per_million: Decimal | None = None
    output_price_per_million: Decimal | None = None
    max_output_tokens: int | None = None

    def __post_init__(self) -> None:
        if not self.provider.strip():
            raise ConfigurationError("Provider label must be nonblank.")
        if not self.api_base_url.startswith(("https://", "http://")):
            raise ConfigurationError("API base URL must use http or https.")
        if self.request_timeout <= 0:
            raise ConfigurationError("Request timeout must be greater than zero.")
        if not 1 <= self.max_attempts <= 10:
            raise ConfigurationError("Maximum attempts must be between 1 and 10.")
        if self.initial_backoff < 0 or self.max_backoff < 0 or self.initial_backoff > self.max_backoff:
            raise ConfigurationError("Backoff values must be nonnegative and initial must not exceed maximum.")
        if self.max_output_tokens is not None and self.max_output_tokens <= 0:
            raise ConfigurationError("Maximum output tokens must be positive when set.")
        for name, value in (("input price", self.input_price_per_million),
                            ("output price", self.output_price_per_million)):
            if value is not None and (not value.is_finite() or value < 0):
                raise ConfigurationError(f"{name} must be nonnegative.")
        object.__setattr__(self, "cache_dir", Path(self.cache_dir).resolve())

    @property
    def endpoint_identity(self) -> str:
        return self.api_base_url.rstrip("/")

    def require_live(self) -> None:
        missing = []
        if not self.api_key or not self.api_key.strip():
            if self.provider.strip().lower() == "gemini":
                missing.append("GHOST_AUDIT_API_KEY or GEMINI_API_KEY")
            else:
                missing.append("GHOST_AUDIT_API_KEY or OPENAI_API_KEY")
        if not self.model or not self.model.strip():
            missing.append("GHOST_AUDIT_MODEL")
        if missing:
            raise ConfigurationError("Live model call requires: " + ", ".join(missing) + ".")


def get_model_settings(environ: Mapping[str, str] | None = None) -> ModelSettings:
    env = os.environ if environ is None else environ
    provider = env.get("GHOST_AUDIT_PROVIDER", "openai").strip().lower()
    attempts = _int(env, "GHOST_AUDIT_MAX_ATTEMPTS", 3)
    max_tokens = _int(env, "GHOST_AUDIT_MAX_OUTPUT_TOKENS", None)
    return ModelSettings(
        api_key=(
            env.get("GHOST_AUDIT_API_KEY")
            or (env.get("GEMINI_API_KEY") if provider == "gemini" else env.get("OPENAI_API_KEY"))
        ),
        model=env.get("GHOST_AUDIT_MODEL"),
        api_base_url=env.get("GHOST_AUDIT_API_BASE_URL") or (
            "https://generativelanguage.googleapis.com" if provider == "gemini"
            else "https://api.openai.com/v1"
        ),
        provider=provider,
        request_timeout=_float(env, "GHOST_AUDIT_REQUEST_TIMEOUT", 30.0),
        max_attempts=attempts if attempts is not None else 3,
        initial_backoff=_float(env, "GHOST_AUDIT_INITIAL_BACKOFF", 0.5),
        max_backoff=_float(env, "GHOST_AUDIT_MAX_BACKOFF", 8.0),
        cache_enabled=_bool(env, "GHOST_AUDIT_CACHE_ENABLED", True),
        cache_dir=Path(env.get("GHOST_AUDIT_CACHE_DIR", str(REPO_ROOT / ".cache" / "ghost_audit_llm"))),
        input_price_per_million=_decimal(env, "GHOST_AUDIT_INPUT_PRICE_PER_MILLION"),
        output_price_per_million=_decimal(env, "GHOST_AUDIT_OUTPUT_PRICE_PER_MILLION"),
        max_output_tokens=max_tokens,
    )
