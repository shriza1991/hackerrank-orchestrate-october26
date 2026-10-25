"""Stable, credential-safe model gateway error categories."""

from __future__ import annotations

from typing import Optional


class GatewayError(RuntimeError):
    """Base class for gateway failures safe to show to callers."""


class ConfigurationError(GatewayError):
    pass


class AuthenticationError(GatewayError):
    pass


class InvalidStructuredResponseError(GatewayError):
    pass


class TruncatedResponseError(GatewayError):
    pass


class RefusalError(GatewayError):
    pass


class CacheError(GatewayError):
    pass


class TransportError(GatewayError):
    """Provider or connection failure, optionally eligible for retry."""

    def __init__(self, message: str, *, retryable: bool = False, retry_after: float | None = None,
                 usage=None, request_id: Optional[str] = None):
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after
        self.usage = usage
        self.request_id = request_id


class RateLimitError(TransportError):
    pass


class TimeoutError(TransportError):
    pass


class ServerError(TransportError):
    pass
