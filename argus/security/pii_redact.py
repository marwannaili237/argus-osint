"""
Argus OSINT – Security: PII Redaction Middleware

Redacts sensitive Personally Identifiable Information from API
responses for non-admin users to prevent accidental data leaks.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ── Patterns to redact ───────────────────────────────────────────────

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.IGNORECASE)),
    ("phone", re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")),
    ("api_key", re.compile(r"(?i)(?:api[_-]?key|token|secret|password)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_\-]{16,}")),
]


def redact_value(text: str) -> str:
    """Redact all PII patterns in a string."""
    for _name, pattern in _PATTERNS:
        text = pattern.sub(lambda m: _mask(m.group()), text)
    return text


def _mask(match: str) -> str:
    """Replace a matched string with a masked version, preserving length hints."""
    length = len(match)
    if length <= 2:
        return "**"
    visible = max(2, length // 4)
    return match[:visible] + "*" * (length - visible)


def redact_dict(data: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    """Recursively redact PII from all string values in a dictionary."""
    if depth > 10:
        return data

    redacted: dict[str, Any] = {}
    for key, value in data.items():
        # Skip fields that are intentionally non-PII identifiers
        if key in {"id", "type", "status", "priority", "classification", "version", "plugin_name", "cached", "execution_time"}:
            redacted[key] = value
        elif isinstance(value, str):
            redacted[key] = redact_value(value)
        elif isinstance(value, dict):
            redacted[key] = redact_dict(value, depth + 1)
        elif isinstance(value, list):
            redacted[key] = [redact_item(item, depth + 1) for item in value]
        else:
            redacted[key] = value
    return redacted


def redact_item(item: Any, depth: int = 0) -> Any:
    """Redact a single item (dict, list element, or string)."""
    if isinstance(item, dict):
        return redact_dict(item, depth)
    if isinstance(item, str):
        return redact_value(item)
    if isinstance(item, list):
        return [redact_item(i, depth + 1) for i in item]
    return item


def redact_response_body(body: bytes, is_admin: bool = False) -> bytes:
    """Redact PII from a JSON response body if the user is not an admin.

    Returns the original body unchanged for admin users or non-JSON responses.
    """
    if is_admin:
        return body

    try:
        text = body.decode("utf-8")
        data = json.loads(text)
        redacted = redact_dict(data) if isinstance(data, dict) else redact_item(data)
        return json.dumps(redacted, ensure_ascii=False).encode("utf-8")
    except (UnicodeDecodeError, json.JSONDecodeError):
        logger.debug("Skipping PII redaction for non-JSON response body")
        return body
