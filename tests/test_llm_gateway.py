"""Offline tests for structured model calls, retries, caching, and accounting."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, StrictStr

from ghost_audit.llm.cache import ResponseCache, request_fingerprint
from ghost_audit.llm.config import ModelSettings, get_model_settings
from ghost_audit.llm.errors import (
    AuthenticationError, CacheError, ConfigurationError, InvalidStructuredResponseError,
    RefusalError, ServerError, TimeoutError, TransportError, TruncatedResponseError,
)
from ghost_audit.llm.gateway import ModelGateway
from ghost_audit.llm.types import Message, ModelRequest, ProviderResponse, ProviderUsage, UsageRecord
from ghost_audit.llm.usage import UsageTracker, estimate_cost


class SyntheticResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    ok: StrictBool
    count: StrictInt


class OtherResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: StrictStr


class FakeTransport:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def send(self, request, settings):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def settings(tmp_path, **changes):
    values = dict(api_key="secret-key", model="model-test", cache_dir=tmp_path / "cache",
                  cache_enabled=False, max_attempts=3, initial_backoff=0.1, max_backoff=1.0)
    values.update(changes)
    return ModelSettings(**values)


def request(*, prompt="synthetic", model=SyntheticResponse, params=None):
    return ModelRequest(task_name="synthetic_test", template_version="1",
                        messages=(Message(role="user", content=prompt),), response_model=model,
                        generation_parameters=params or {}, run_id="run-test")


def response(content='{"ok":true,"count":2}', usage=None, **changes):
    values = dict(content=content, model="model-returned", usage=usage, request_id="req-test")
    values.update(changes)
    return ProviderResponse(**values)


def test_configuration_is_deferred_until_live_call(tmp_path):
    config = get_model_settings({})
    assert config.model is None and config.api_key is None
    with pytest.raises(ConfigurationError, match="Live model call requires"):
        ModelGateway(config, FakeTransport([])).call(request())


@pytest.mark.parametrize("env", [
    {"GHOST_AUDIT_MAX_ATTEMPTS": "0"}, {"GHOST_AUDIT_MAX_ATTEMPTS": "11"},
    {"GHOST_AUDIT_REQUEST_TIMEOUT": "0"}, {"GHOST_AUDIT_INPUT_PRICE_PER_MILLION": "-1"},
    {"GHOST_AUDIT_INITIAL_BACKOFF": "2", "GHOST_AUDIT_MAX_BACKOFF": "1"},
    {"GHOST_AUDIT_CACHE_ENABLED": "perhaps"},
    {"GHOST_AUDIT_REQUEST_TIMEOUT": "nan"},
    {"GHOST_AUDIT_OUTPUT_PRICE_PER_MILLION": "Infinity"},
])
def test_configuration_numeric_validation(env):
    with pytest.raises(ConfigurationError):
        get_model_settings(env)


def test_successful_structured_response_and_usage(tmp_path):
    usage = ProviderUsage(11, 7, {"cached_tokens": 2}, {"reasoning_tokens": 3})
    tracker = UsageTracker(); transport = FakeTransport([response(usage=usage)])
    result = ModelGateway(settings(tmp_path), transport, usage=tracker).call(request())
    assert result.parsed == SyntheticResponse(ok=True, count=2)
    assert result.requested_model == "model-test" and result.provider_model == "model-returned"
    assert result.attempt_count == 1 and not result.cache_hit
    assert tracker.records[0].input_details == {"cached_tokens": 2}


def test_request_rejects_reserved_provider_payload_overrides():
    with pytest.raises(ValueError, match="reserved"):
        request(params={"model": "bypass"})


@pytest.mark.parametrize("content", [
    "not-json", '{"ok":"true","count":2}', '{"ok":true}',
    '{"ok":true,"count":2,"extra":1}', "{}",
])
def test_invalid_structured_responses_are_not_repaired(tmp_path, content):
    transport = FakeTransport([response(content=content)])
    with pytest.raises(InvalidStructuredResponseError):
        ModelGateway(settings(tmp_path), transport).call(request())
    assert transport.calls == 1


def test_truncation_and_refusal_are_distinct(tmp_path):
    with pytest.raises(TruncatedResponseError):
        ModelGateway(settings(tmp_path), FakeTransport([response(truncated=True)])).call(request())
    with pytest.raises(RefusalError):
        ModelGateway(settings(tmp_path), FakeTransport([response(refusal="no")])).call(request())


def test_authentication_failure_is_not_retried(tmp_path):
    transport = FakeTransport([AuthenticationError("secret-key rejected")])
    with pytest.raises(AuthenticationError) as caught:
        ModelGateway(settings(tmp_path), transport).call(request())
    assert transport.calls == 1 and "secret-key" not in str(caught.value)


def test_retryable_failure_is_bounded_and_observable(tmp_path):
    sleeps = []; tracker = UsageTracker()
    transport = FakeTransport([ServerError("temporary", retryable=True),
                               ServerError("temporary", retryable=True), response()])
    result = ModelGateway(settings(tmp_path), transport, usage=tracker, sleep=sleeps.append).call(request())
    assert result.attempt_count == 3 and transport.calls == 3
    assert sleeps == [0.1, 0.2]
    assert [record.outcome for record in tracker.records][-1] == "SUCCESS"


def test_retry_after_above_configured_limit_stops(tmp_path):
    transport = FakeTransport([ServerError("wait", retryable=True, retry_after=5)])
    with pytest.raises(ServerError):
        ModelGateway(settings(tmp_path, max_backoff=1), transport, sleep=lambda _: pytest.fail("slept")).call(request())
    assert transport.calls == 1


def test_timeout_retries_then_fails(tmp_path):
    transport = FakeTransport([TimeoutError("timeout", retryable=True)] * 2)
    with pytest.raises(TimeoutError):
        ModelGateway(settings(tmp_path, max_attempts=2), transport, sleep=lambda _: None).call(request())
    assert transport.calls == 2


def test_usage_retained_for_schema_invalid_and_unknown_for_unmetered_failure(tmp_path):
    known = ProviderUsage(5, 6)
    tracker = UsageTracker()
    with pytest.raises(InvalidStructuredResponseError):
        ModelGateway(settings(tmp_path), FakeTransport([response("bad", usage=known)]), usage=tracker).call(request())
    assert tracker.records[0].input_tokens == 5
    tracker2 = UsageTracker()
    with pytest.raises(TransportError):
        ModelGateway(settings(tmp_path, max_attempts=1),
                     FakeTransport([TransportError("network", retryable=True)]), usage=tracker2).call(request())
    assert tracker2.records[0].input_tokens is None
    assert tracker2.summary()["overall"]["unknown_usage_attempts"] == 1


def test_cache_hit_revalidates_without_transport_or_new_billing(tmp_path):
    config = settings(tmp_path, cache_enabled=True)
    tracker = UsageTracker(); first = FakeTransport([response(usage=ProviderUsage(9, 4))])
    ModelGateway(config, first, usage=tracker).call(request())
    second = FakeTransport([])
    result = ModelGateway(config, second, usage=tracker).call(request())
    assert result.cache_hit and result.attempt_count == 0 and second.calls == 0
    assert tracker.records[-1].new_api_request is False
    assert tracker.records[-1].reused_input_tokens == 9
    assert tracker.summary()["overall"]["new_api_attempts"] == 1
    assert tracker.summary()["overall"]["logical_requests"] == 2


@pytest.mark.parametrize("change", ["prompt", "schema", "model", "parameters"])
def test_cache_key_changes_for_every_effective_input(tmp_path, change):
    config = settings(tmp_path, cache_enabled=True)
    base = request(); gateway = ModelGateway(config, FakeTransport([response()]))
    gateway.call(base)
    changed_request, changed_config = base, config
    if change == "prompt": changed_request = request(prompt="different")
    if change == "schema": changed_request = request(model=OtherResponse)
    if change == "parameters": changed_request = request(params={"temperature": 0})
    if change == "model": changed_config = settings(tmp_path, cache_enabled=True, model="other-model")
    transport = FakeTransport([response(content='{"text":"ok"}' if change == "schema" else None)])
    if change != "schema": transport.outcomes = [response()]
    ModelGateway(changed_config, transport).call(changed_request)
    assert transport.calls == 1


def test_corrupted_cache_entry_is_explicit(tmp_path):
    config = settings(tmp_path, cache_enabled=True); req = request()
    key = request_fingerprint(req, endpoint=config.endpoint_identity, provider=config.provider,
                              model=config.model, max_output_tokens=config.max_output_tokens)
    cache = ResponseCache(config.cache_dir); cache.directory.mkdir(parents=True)
    cache.path_for(key).write_text("{broken", encoding="utf-8")
    with pytest.raises(CacheError, match="Corrupted"):
        ModelGateway(config, FakeTransport([]), cache=cache).call(req)


def test_retry_tokens_and_exact_decimal_cost_are_aggregated(tmp_path):
    config = settings(tmp_path, input_price_per_million=Decimal("2.5"),
                      output_price_per_million=Decimal("10"))
    tracker = UsageTracker()
    failure = ServerError("temporary", retryable=True, usage=ProviderUsage(100, 50))
    ModelGateway(config, FakeTransport([failure, response(usage=ProviderUsage(20, 10))]),
                 usage=tracker, sleep=lambda _: None).call(request())
    summary = tracker.summary()["overall"]
    assert estimate_cost(ProviderUsage(100, 50), Decimal("2.5"), Decimal("10")) == Decimal("0.00075")
    assert summary["known_input_tokens"] == 120 and summary["known_output_tokens"] == 60
    assert summary["estimated_cost"] == Decimal("0.000900")


def test_missing_prices_and_per_model_totals(tmp_path):
    tracker = UsageTracker()
    ModelGateway(settings(tmp_path, model="m1"), FakeTransport([response(usage=ProviderUsage(1, 2), model="m1")]), usage=tracker).call(request())
    ModelGateway(settings(tmp_path, model="m2"), FakeTransport([response(usage=ProviderUsage(3, 4), model="m2")]), usage=tracker).call(request(prompt="two"))
    summary = tracker.summary()
    assert summary["overall"]["estimated_cost"] is None
    assert set(summary["per_provider_model"]) == {"openai/m1", "openai/m2"}
    assert summary["overall"]["known_input_tokens"] == 4
    markdown = tracker.render_markdown()
    assert "openai/m1" in markdown and "openai/m2" in markdown


def test_transport_error_message_redacts_credentials(tmp_path):
    secret = "highly-secret-key"
    transport = FakeTransport([TransportError(f"server echoed {secret}", retryable=False)])
    with pytest.raises(TransportError) as caught:
        ModelGateway(settings(tmp_path, api_key=secret), transport).call(request())
    assert secret not in str(caught.value)


def test_cli_without_live_authorization_never_calls_network(tmp_path, repo_root):
    env = os.environ.copy()
    for name in list(env):
        if name.startswith("GHOST_AUDIT_") or name == "OPENAI_API_KEY": env.pop(name)
    completed = subprocess.run([sys.executable, str(repo_root / "code" / "main.py"), "model-smoke"],
                               cwd=tmp_path, env=env, text=True, capture_output=True)
    assert completed.returncode == 0
    assert "no API request made" in completed.stdout
    assert "--live" in completed.stdout
