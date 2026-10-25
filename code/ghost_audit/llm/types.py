"""Provider-neutral request, response, and usage contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
import re
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

ResponseT = TypeVar("ResponseT", bound=BaseModel)


class Message(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1)


@dataclass(frozen=True)
class ModelRequest(Generic[ResponseT]):
    task_name: str
    template_version: str
    messages: tuple[Message, ...]
    response_model: type[ResponseT]
    generation_parameters: dict[str, Any] = field(default_factory=dict)
    case_id: str | None = None
    run_id: str = "default"

    def __post_init__(self) -> None:
        if not self.task_name.strip() or not self.template_version.strip():
            raise ValueError("Task name and template version must be nonblank.")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.task_name):
            raise ValueError("Task name must be 1-64 letters, digits, underscores, or hyphens.")
        if not self.messages:
            raise ValueError("At least one message is required.")
        reserved = {"model", "input", "text", "store", "max_output_tokens"}
        overlap = sorted(reserved.intersection(self.generation_parameters))
        if overlap:
            raise ValueError(f"Generation parameters cannot override reserved fields: {overlap}.")


@dataclass(frozen=True)
class ProviderUsage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    input_details: dict[str, int] = field(default_factory=dict)
    output_details: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for value in (self.input_tokens, self.output_tokens, *self.input_details.values(), *self.output_details.values()):
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError("Token usage values must be nonnegative integers or unknown.")


@dataclass(frozen=True)
class ProviderResponse:
    content: str | None
    model: str | None
    usage: ProviderUsage | None
    request_id: str | None = None
    truncated: bool = False
    refusal: str | None = None


@dataclass(frozen=True)
class ModelResult(Generic[ResponseT]):
    parsed: ResponseT
    requested_model: str
    provider_model: str | None
    provider: str
    cache_hit: bool
    attempt_count: int
    latency_seconds: float
    usage: ProviderUsage | None
    provider_request_id: str | None = None


@dataclass(frozen=True)
class UsageRecord:
    logical_request_id: str
    run_id: str
    task_name: str
    case_id: str | None
    attempt_id: str
    outcome: str
    provider: str
    requested_model: str
    provider_model: str | None
    input_tokens: int | None
    output_tokens: int | None
    input_details: dict[str, int]
    output_details: dict[str, int]
    estimated_cost: Decimal | None
    new_api_request: bool
    reused_input_tokens: int = 0
    reused_output_tokens: int = 0
    latency_seconds: float = 0.0
    provider_request_id: str | None = None
