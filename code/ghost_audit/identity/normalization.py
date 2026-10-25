"""Field-specific identity normalization utilities.

Adheres strictly to the task specification:
- Email: trim whitespace, case-insensitive match, preserve original spelling,
  no plus-tag or dot removal, no substring matching.
- Phone: conservative formatting normalization (strip spaces, hyphens, parentheses, dots),
  preserve country-code prefix (+), do not infer missing country codes, no suffix matching.
- Email hash: treat supplied hashes as identifiers; normalize hex case only when confirmed hex;
  never invent or hash email addresses.
- Stable user ID: exact string matching; no prefix/suffix collisions (e.g. user_10 vs user_100).
- Empty strings represent absence/clearing and are not treated as valid searchable identifiers.
"""

from __future__ import annotations

import re

HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")
PHONE_FORMAT_CHARS = re.compile(r"[\s\-\(\)\.]")


def normalize_email(email: str | None) -> str:
    """Normalize email address for case-insensitive exact matching.

    Trims surrounding whitespace and lowercases.
    Preserves dots, plus-tags, and all punctuation without provider heuristics.
    Returns empty string if input is None or whitespace-only.
    """
    if email is None:
        return ""
    cleaned = email.strip()
    return cleaned.lower() if cleaned else ""


def normalize_phone(phone: str | None) -> str:
    """Conservatively normalize phone number formatting while preserving country code.

    Strips whitespace, hyphens, parentheses, and dots.
    Preserves leading '+' for international country codes.
    Does NOT infer missing country codes or truncate.
    Returns empty string if input is None or contains no digits.
    """
    if phone is None:
        return ""
    cleaned = phone.strip()
    if not cleaned:
        return ""
    has_plus = cleaned.startswith("+")
    stripped = PHONE_FORMAT_CHARS.sub("", cleaned)
    if has_plus and not stripped.startswith("+"):
        stripped = "+" + stripped
    # If there are no digits at all, it's not a valid phone identifier
    if not any(char.isdigit() for char in stripped):
        return ""
    return stripped


def is_hexadecimal(value: str) -> bool:
    """Return True if the non-empty string consists solely of hexadecimal characters."""
    return bool(value and HEX_PATTERN.match(value))


def normalize_email_hash(email_hash: str | None) -> str:
    """Normalize email hash value.

    Trims surrounding whitespace.
    If the value is confirmed hexadecimal (e.g., SHA-256 or MD5 hex digest),
    normalizes to lowercase hex.
    Otherwise preserves original characters without inventing hashes.
    Returns empty string if input is None or whitespace-only.
    """
    if email_hash is None:
        return ""
    cleaned = email_hash.strip()
    if not cleaned:
        return ""
    if is_hexadecimal(cleaned):
        return cleaned.lower()
    return cleaned


def normalize_user_id(user_id: str | None) -> str:
    """Normalize stable user ID for exact string matching.

    Trims surrounding whitespace.
    """
    if user_id is None:
        return ""
    return user_id.strip()
