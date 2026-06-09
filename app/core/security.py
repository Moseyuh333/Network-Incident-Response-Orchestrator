"""Input validation and security utilities."""

from __future__ import annotations

import ipaddress
import re


def is_valid_ip(value: str) -> bool:
    """Return True if *value* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_private_ip(value: str) -> bool:
    """Return True if *value* is a private/internal IP address."""
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def validate_ip_or_raise(value: str) -> str:
    """Validate IP, raise ValueError if invalid."""
    if not is_valid_ip(value):
        raise ValueError(f"Invalid IP address: {value}")
    return value


# Regex patterns for web-attack detection (defensive, non-exploit samples)
_WEB_ATTACK_PATTERNS: list[re.Pattern] = [
    re.compile(r"('|%27).*(union|select|insert|update|delete|drop)\b", re.IGNORECASE),
    re.compile(r"(union\s+select|select\s+.*\s+from)", re.IGNORECASE),
    re.compile(r"(\.\./|\.\.\\)+", re.IGNORECASE),  # path traversal
    re.compile(r"(;|\||`)\s*(cat|ls|whoami|id|pwd|curl|wget)\b", re.IGNORECASE),
    re.compile(r"(\bor\b|\band\b)\s+\d+\s*=\s*\d+", re.IGNORECASE),  # tautology
    re.compile(r"(<script|javascript:|onerror=|onload=)", re.IGNORECASE),  # XSS
    re.compile(r"(/etc/passwd|/proc/|cmd\.exe|win\.ini)", re.IGNORECASE),
]


def detect_web_attack_patterns(url: str) -> list[str]:
    """Return list of pattern names matching in *url*."""
    if not url:
        return []
    matches: list[str] = []
    for pat in _WEB_ATTACK_PATTERNS:
        if pat.search(url):
            matches.append(pat.pattern[:60])
    return matches


# Common safe-looking URI used in demo data
SAFE_DEMO_PAYLOADS = [
    "' OR '1'='1",
    "../../etc/passwd",
    "; cat /etc/passwd",
    "<script>alert(1)</script>",
]
