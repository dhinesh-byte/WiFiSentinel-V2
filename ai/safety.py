"""Input bounds and basic sensitive-string handling."""

from __future__ import annotations

import re

from .schemas import MAX_MESSAGE_CHARS

_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:password|passphrase|api[_ -]?key|access[_ -]?token|secret|credential)\b\s*(?:[:=]|is|equals)\s*[^\s,;]+"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)https?://[^/:\s]+:[^/@\s]+@"),
)


def valid_message(value) -> str:
    if not isinstance(value, str):
        raise ValueError("Message must be text.")
    message = value.strip()
    if not message:
        raise ValueError("Enter a message for VulnScan AI.")
    if len(message) > MAX_MESSAGE_CHARS:
        raise ValueError(f"Messages are limited to {MAX_MESSAGE_CHARS} characters.")
    return message


def redact_sensitive_text(value: str) -> str:
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    return value


def contains_secret(value: str) -> bool:
    return redact_sensitive_text(value) != value