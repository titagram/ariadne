"""Deterministic secret redaction for evidence and reports.

Redacts common secret patterns from text while preserving safe content and
tracking what was redacted. Every redactor is a stateless callable that
returns a ``RedactionResult`` with the redacted text and a redaction count.

This service is designed to be applied *before* evidence is stored or
reports are rendered so that secrets never appear in the dossier.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class RedactionResult(NamedTuple):
    """Result of a redaction operation.

    Attributes:
        text: The input text with secrets replaced.
        redacted_count: Number of distinct secrets that were replaced.
    """

    text: str
    redacted_count: int


_REDACTED = "[REDACTED]"

# ---------------------------------------------------------------------------
# Pattern definitions — ordered so earlier patterns don't consume material
# needed by later patterns.
# ---------------------------------------------------------------------------

# Private key blocks (multi-line, must come before other patterns)
_PRIVATE_KEY_RE = re.compile(
    r"(-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PRIVATE|ENCRYPTED)\s+PRIVATE\s+KEY-----\n)"
    r".*?"
    r"(-----END\s+(?:RSA|EC|DSA|OPENSSH|PRIVATE|ENCRYPTED)\s+PRIVATE\s+KEY-----)",
    re.DOTALL,
)

# Bearer tokens and JWT-like strings
_BEARER_RE = re.compile(
    r"(Bearer\s+)([A-Za-z0-9\-_.=+/]{4,})",
    re.IGNORECASE,
)

# Basic auth credentials in Authorization header
_BASIC_AUTH_RE = re.compile(
    r"(Authorization:\s*Basic\s+)([A-Za-z0-9+/=]{4,})",
    re.IGNORECASE,
)

# URL credentials: scheme://user:pass@host or scheme://user@host
_URL_CREDENTIALS_RE = re.compile(
    r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^@/\s]+@)",
)

# Cookie values (name=value pairs)
_COOKIE_VALUE_RE = re.compile(
    r"(Cookie:\s*[^=]+=\s*)([^\s;]+)",
    re.IGNORECASE,
)

# API keys and tokens (common prefixes)
_API_KEY_RE = re.compile(
    r"(api[_-]?key\s*[:=]\s*)(\S+)",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(
    r"(token\s*[:=]\s*)(\S+)",
    re.IGNORECASE,
)
_SECRET_RE = re.compile(
    r"(secret\s*[:=]\s*)(\S+)",
    re.IGNORECASE,
)

# Password fields in various formats
_PASSWORD_RE = re.compile(
    r"(password\s*[:=]\s*[\"']?)([^\"'\s;]+)",
    re.IGNORECASE,
)
_PASSWD_RE = re.compile(
    r"(passwd?\s*[:=]\s*[\"']?)([^\"'\s;]+)",
    re.IGNORECASE,
)

# NTLM hashes (32 hex characters)
_NTLM_HASH_RE = re.compile(
    r"[0-9a-fA-F]{32}",
)

# CTF flags: HTB{...}, FLAG{...}, CTF{...}
_FLAG_RE = re.compile(
    r"(\b(?:HTB|FLAG|CTF)\{)[^}]*\}",
)


class RedactionService:
    """A stateless secret redactor for text content.

    Applies a deterministic set of regular expressions to identify and
    replace common secret patterns.  Returns a ``RedactionResult`` with
    the redacted text and a count of replaced secrets rather than mutating
    input in place.
    """

    def __init__(self) -> None:
        self._patterns: list[re.Pattern] = [
            _PRIVATE_KEY_RE,
            _BEARER_RE,
            _BASIC_AUTH_RE,
            _URL_CREDENTIALS_RE,
            _COOKIE_VALUE_RE,
            _API_KEY_RE,
            _TOKEN_RE,
            _SECRET_RE,
            _PASSWORD_RE,
            _PASSWD_RE,
            _FLAG_RE,
            _NTLM_HASH_RE,
        ]

    def redact(self, text: str | None) -> RedactionResult:
        """Redact all known secret patterns from *text*.

        Args:
            text: The input string to redact.  ``None`` is treated as
                  empty string.

        Returns:
            A ``RedactionResult`` with the redacted text and count of
            unique replacements made.
        """
        if not text:
            return RedactionResult(text="", redacted_count=0)

        result = text
        count = 0

        for pattern in self._patterns:
            result, new_count = pattern.subn(
                self._replacer,
                result,
            )
            count += new_count

        return RedactionResult(text=result, redacted_count=count)

    @staticmethod
    def _replacer(match: re.Match) -> str:
        """Replace match with preserved prefix + [REDACTED]."""
        groups = match.groups()
        if groups:
            # Capture groups: keep the first (prefix), redact the rest
            prefix = groups[0] if groups[0] else ""
            return f"{prefix}{_REDACTED}"
        return _REDACTED
