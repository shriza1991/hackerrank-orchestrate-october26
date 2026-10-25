"""Shared helper utilities for evidence parsing."""

import hashlib
from datetime import datetime
from typing import Any, Iterable

from ghost_audit.timestamps import parse_iso_timestamp


SUBJECT_KEY_CANDIDATES = {
    "user_id",
    "customer_reference",
    "subject_reference",
    "subject_key",
    "lookup_key",
    "correlation_key",
    "email",
    "customer_email",
    "requester_email",
    "owner_email",
    "phone",
    "customer_phone",
    "requester_phone",
    "owner_phone",
    "email_hash",
}


def compute_content_digest(content: bytes | str) -> str:
    """Compute deterministic SHA-256 digest of file content."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def extract_subject_references(data: Any) -> list[str]:
    """Extract explicit subject identifiers present in a dictionary or collection."""
    refs: set[str] = set()

    if isinstance(data, dict):
        for k, v in data.items():
            if k in SUBJECT_KEY_CANDIDATES and isinstance(v, str):
                cleaned = v.strip()
                if cleaned and cleaned.lower() not in {"null", "none", "no direct identifier", ""}:
                    refs.add(cleaned)
            elif isinstance(v, (dict, list)):
                refs.update(extract_subject_references(v))
    elif isinstance(data, (list, tuple)):
        for item in data:
            refs.update(extract_subject_references(item))

    return sorted(refs)


def make_observation_id(evidence_id: str, index: int) -> str:
    """Generate a deterministic internal observation ID.
    
    This ID is explicitly internal and does not represent a final-output evidence citation.
    """
    return f"obs:{evidence_id}:{index:05d}"
