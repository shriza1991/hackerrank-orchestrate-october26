"""Gemini provider selection and usage-accounting regressions."""

from types import SimpleNamespace

import pytest

from ghost_audit.llm.config import ModelSettings, get_model_settings
from ghost_audit.llm.errors import ConfigurationError
from ghost_audit.intent.models import IntentModelOutput
from ghost_audit.llm.gemini_transport import GeminiGenerateContentTransport, _gemini_json_schema
from ghost_audit.llm.transport import OpenAIResponsesTransport
from ghost_audit.llm.transport_factory import create_model_transport


def test_gemini_provider_reads_only_gemini_key(tmp_path):
    settings = get_model_settings({
        "GHOST_AUDIT_PROVIDER": "GeMiNi",
        "GEMINI_API_KEY": "gemini-secret",
        "OPENAI_API_KEY": "openai-secret",
        "GHOST_AUDIT_MODEL": "gemini-test",
        "GHOST_AUDIT_CACHE_DIR": str(tmp_path),
    })
    assert settings.provider == "gemini"
    assert settings.api_key == "gemini-secret"
    assert isinstance(create_model_transport(settings), GeminiGenerateContentTransport)


def test_transport_factory_rejects_unknown_provider(tmp_path):
    settings = ModelSettings(
        api_key="key", model="model", provider="unknown", cache_dir=tmp_path
    )
    with pytest.raises(ConfigurationError, match="Unsupported"):
        create_model_transport(settings)


def test_transport_factory_preserves_openai_default(tmp_path):
    settings = ModelSettings(api_key="key", model="model", cache_dir=tmp_path)
    assert isinstance(create_model_transport(settings), OpenAIResponsesTransport)


def test_gemini_usage_metadata_maps_actual_totals_and_details():
    usage = GeminiGenerateContentTransport._usage(SimpleNamespace(
        prompt_token_count=101,
        candidates_token_count=17,
        cached_content_token_count=11,
        thoughts_token_count=3,
        tool_use_prompt_token_count=2,
    ))
    assert usage.input_tokens == 101
    assert usage.output_tokens == 17
    assert usage.input_details == {
        "cached_content_tokens": 11,
        "tool_use_prompt_tokens": 2,
    }
    assert usage.output_details == {"thoughts_tokens": 3}


def test_gemini_schema_adapter_inlines_refs_and_drops_unsupported_constraints():
    schema = _gemini_json_schema(IntentModelOutput)
    rendered = str(schema)
    assert "$ref" not in rendered and "$defs" not in rendered
    assert "minLength" not in rendered and "maxLength" not in rendered
    assert schema["properties"]["decision"]["enum"] == [
        "DELETION_REQUEST", "NON_DELETION", "AMBIGUOUS"
    ]
