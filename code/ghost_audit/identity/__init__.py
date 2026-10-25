"""Historical identity resolution package for Ghost Data Still Exists."""

from ghost_audit.identity.index import IdentityIndex
from ghost_audit.identity.models import (
    IdentifierInterval,
    IdentifierProvenance,
    SourceType,
    UserHistoryTimeline,
)
from ghost_audit.identity.normalization import (
    normalize_email,
    normalize_email_hash,
    normalize_phone,
    normalize_user_id,
)
from ghost_audit.identity.service import IdentityResolutionService
from ghost_audit.identity.timeline import reconstruct_user_timeline
from ghost_audit.models.intermediate_models import (
    IdentityResolutionResult,
    IdentityResolutionStatus,
)

__all__ = [
    "IdentifierInterval",
    "IdentifierProvenance",
    "IdentityIndex",
    "IdentityResolutionResult",
    "IdentityResolutionService",
    "IdentityResolutionStatus",
    "SourceType",
    "UserHistoryTimeline",
    "normalize_email",
    "normalize_email_hash",
    "normalize_phone",
    "normalize_user_id",
    "reconstruct_user_timeline",
]
