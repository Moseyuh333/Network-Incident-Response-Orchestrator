"""Secret redaction helpers for logs, reports, and provider errors."""

from __future__ import annotations

import re
from collections.abc import Iterable


_AUTH_HEADER_RE = re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+")
_API_KEY_RE = re.compile(r"(?i)((?:api[_-]?key|key|token|secret)\s*[:=]\s*)[^\s,;]+")


def redact_secrets(value: object, secrets: Iterable[str | None] = ()) -> str:
    """Return *value* as text with known secret material removed."""
    text = str(value)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    text = _AUTH_HEADER_RE.sub(r"\1[REDACTED]", text)
    return _API_KEY_RE.sub(r"\1[REDACTED]", text)
