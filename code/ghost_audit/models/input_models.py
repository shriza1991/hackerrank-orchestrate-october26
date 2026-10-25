"""Input data contracts and domain models."""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, field_validator

from ghost_audit.timestamps import parse_iso_timestamp


class ReportedStatus(str, Enum):
    """Reported deletion workflow claims."""

    COMPLETE = "COMPLETE"
    PARTIALLY_COMPLETE = "PARTIALLY_COMPLETE"
    NOT_STARTED = "NOT_STARTED"


class ReportedResult(str, Enum):
    """Reported result for system activity operations."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


class DataCategory(str, Enum):
    """Data categories defined in deletion rules."""

    ACCOUNT_TOMBSTONE = "ACCOUNT_TOMBSTONE"
    ANALYTICS_PROFILE = "ANALYTICS_PROFILE"
    BACKUP_ARCHIVE = "BACKUP_ARCHIVE"
    CACHE_ENTRY = "CACHE_ENTRY"
    EMAIL_DELIVERY_LOG = "EMAIL_DELIVERY_LOG"
    LEGAL_HOLD_RECORD = "LEGAL_HOLD_RECORD"
    MARKETING_PROFILE = "MARKETING_PROFILE"
    PRODUCT_TELEMETRY = "PRODUCT_TELEMETRY"
    SEARCH_INDEX_ENTRY = "SEARCH_INDEX_ENTRY"
    SECONDARY_IDENTIFIER = "SECONDARY_IDENTIFIER"
    SECURITY_AUDIT_LOG = "SECURITY_AUDIT_LOG"
    SUPPORT_ATTACHMENT = "SUPPORT_ATTACHMENT"
    SUPPORT_MESSAGE = "SUPPORT_MESSAGE"
    USER_EXPORT = "USER_EXPORT"
    USER_PROFILE = "USER_PROFILE"


class RequiredAction(str, Enum):
    """Required actions specified by deletion rules."""

    DELETE = "DELETE"
    REDACT = "REDACT"
    ANONYMIZE = "ANONYMIZE"
    RETAIN = "RETAIN"


class AuditFieldName(str, Enum):
    """Field names appearing in user audit logs."""

    PHONE = "phone"
    EMAIL = "email"
    EMAIL_HASH = "email_hash"


class DeletionRequest(BaseModel):
    """Deletion audit request."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    email: str
    requested_at: datetime
    reported_status: ReportedStatus
    reported_at: datetime
    audit_at: datetime
    request_text: str

    @field_validator("requested_at", "reported_at", "audit_at", mode="before")
    @classmethod
    def validate_timestamp(cls, v: str | datetime) -> datetime:
        return parse_iso_timestamp(v)


class UserIdentity(BaseModel):
    """Current user identity snapshot."""

    model_config = ConfigDict(frozen=True)

    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: datetime

    @field_validator("updated_at", mode="before")
    @classmethod
    def validate_timestamp(cls, v: str | datetime) -> datetime:
        return parse_iso_timestamp(v)


class UserAuditLogEntry(BaseModel):
    """Historical change to an identity field."""

    model_config = ConfigDict(frozen=True)

    audit_id: str
    user_id: str
    event_time: datetime
    field_name: str
    old_value: str
    new_value: str

    @field_validator("event_time", mode="before")
    @classmethod
    def validate_timestamp(cls, v: str | datetime) -> datetime:
        return parse_iso_timestamp(v)


class SystemActivityEvent(BaseModel):
    """Global system activity record."""

    model_config = ConfigDict(frozen=True)

    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: ReportedResult
    details: str

    @field_validator("event_time", mode="before")
    @classmethod
    def validate_timestamp(cls, v: str | datetime) -> datetime:
        return parse_iso_timestamp(v)


class DeletionRule(BaseModel):
    """Policy rule defining treatment for a data category."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    data_category: DataCategory
    condition: str
    required_action: RequiredAction


class EvidenceManifestEntry(BaseModel):
    """Manifest entry referencing an evidence file."""

    model_config = ConfigDict(frozen=True)

    file_id: str
    file_path: str
    origin: str
    captured_at: datetime

    @field_validator("captured_at", mode="before")
    @classmethod
    def validate_timestamp(cls, v: str | datetime) -> datetime:
        return parse_iso_timestamp(v)
