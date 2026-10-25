"""Synthetic structured-output smoke check; never touches challenge cases."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr

from ghost_audit.config import REPO_ROOT
from ghost_audit.llm.config import get_model_settings
from ghost_audit.llm.errors import GatewayError
from ghost_audit.llm.gateway import ModelGateway
from ghost_audit.llm.transport_factory import create_model_transport
from ghost_audit.llm.types import Message, ModelRequest
from ghost_audit.llm.usage import UsageTracker


class SmokeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    ok: StrictBool
    message: StrictStr


def run_smoke(*, live: bool, write_report: bool = False) -> int:
    settings = get_model_settings()
    if not live:
        print("Model smoke check: offline configuration only (no API request made).")
        print(f"Provider: {settings.provider}")
        print(f"Model configured: {bool(settings.model)}")
        print(f"Credentials configured: {bool(settings.api_key)}")
        print("Use --live to authorize a potentially paid synthetic request.")
        return 0
    tracker = UsageTracker()
    gateway = ModelGateway(settings, create_model_transport(settings), usage=tracker)
    request = ModelRequest(
        task_name="synthetic_smoke",
        template_version="1",
        messages=(
            Message(role="system", content="Return only the requested structured synthetic result."),
            Message(role="user", content="Set ok to true and message to the exact text: synthetic gateway ready"),
        ),
        response_model=SmokeResponse,
        run_id="development-smoke",
    )
    try:
        result = gateway.call(request)
    except GatewayError as exc:
        print(f"Model smoke failed: {exc}")
        return 1
    print(f"Provider/model: {result.provider}/{result.provider_model or result.requested_model}")
    print(f"Cache hit: {result.cache_hit}")
    print(f"Attempts: {result.attempt_count}")
    print(f"Validated result: ok={result.parsed.ok}, message={result.parsed.message!r}")
    print(f"Usage summary: {tracker.summary()['overall']}")
    if write_report:
        path = REPO_ROOT / "artifacts" / "model-smoke-usage.md"
        tracker.write_markdown(path)
        print(f"Development usage report: {path}")
    return 0
