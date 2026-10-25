"""Provider transport selection for the shared model gateway."""

from ghost_audit.llm.config import ModelSettings
from ghost_audit.llm.errors import ConfigurationError
from ghost_audit.llm.gemini_transport import GeminiGenerateContentTransport
from ghost_audit.llm.transport import ModelTransport, OpenAIResponsesTransport


def create_model_transport(settings: ModelSettings) -> ModelTransport:
    provider = settings.provider.strip().lower()
    if provider == "openai":
        return OpenAIResponsesTransport()
    if provider == "gemini":
        return GeminiGenerateContentTransport()
    raise ConfigurationError(f"Unsupported GHOST_AUDIT_PROVIDER: {settings.provider!r}.")
