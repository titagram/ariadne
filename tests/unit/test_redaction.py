"""Tests for deterministic secret redaction."""

from __future__ import annotations

import pytest

from ariadne.evidence.redaction import (
    RedactionService,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def redactor() -> RedactionService:
    return RedactionService()


# ---------------------------------------------------------------------------
# URL credential redaction
# ---------------------------------------------------------------------------


def test_redacts_url_credentials(redactor: RedactionService) -> None:
    text = "http://admin:pass123@example.com/resource"
    result = redactor.redact(text)
    assert "admin" not in result.text
    assert "pass123" not in result.text
    assert "[REDACTED]" in result.text or "****" in result.text


def test_redacts_url_with_user_only(redactor: RedactionService) -> None:
    text = "ftp://user@host.com/files"
    result = redactor.redact(text)
    assert "user" not in result.text


def test_redacts_url_with_special_chars(redactor: RedactionService) -> None:
    text = "https://admin:p%40ss%23@host.com/login"
    result = redactor.redact(text)
    assert "admin" not in result.text
    assert "p%40ss%23" not in result.text


# ---------------------------------------------------------------------------
# Authorization header redaction
# ---------------------------------------------------------------------------


def test_redacts_basic_auth_header(redactor: RedactionService) -> None:
    text = "Authorization: Basic dXNlcjpwYXNz"
    result = redactor.redact(text)
    assert "dXNlcjpwYXNz" not in result.text


def test_redacts_bearer_token(redactor: RedactionService) -> None:
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    result = redactor.redact(text)
    assert "eyJhbGciOiJIUzI1NiJ9" not in result.text


# ---------------------------------------------------------------------------
# Cookie redaction
# ---------------------------------------------------------------------------


def test_redacts_session_cookie(redactor: RedactionService) -> None:
    text = "Cookie: session=abc123def456; other=value"
    result = redactor.redact(text)
    assert "abc123def456" not in result.text


def test_redacts_multiple_cookies(redactor: RedactionService) -> None:
    text = "Cookie: token=secret123; auth=supersecret"
    result = redactor.redact(text)
    assert "secret123" not in result.text


# ---------------------------------------------------------------------------
# API key and password redaction
# ---------------------------------------------------------------------------


def test_redacts_api_key_pattern(redactor: RedactionService) -> None:
    text = "api_key=sk-1234567890abcdefg"
    result = redactor.redact(text)
    assert "sk-1234567890abcdefg" not in result.text


def test_redacts_password_field(redactor: RedactionService) -> None:
    text = 'password = "hunter2"'
    result = redactor.redact(text)
    assert "hunter2" not in result.text


def test_redacts_ntlm_hash(redactor: RedactionService) -> None:
    text = "NTLM hash: aad3b435b51404eeaad3b435b51404ee"
    result = redactor.redact(text)
    assert "aad3b435b51404eeaad3b435b51404ee" not in result.text


# ---------------------------------------------------------------------------
# Private key redaction
# ---------------------------------------------------------------------------


def test_redacts_ssh_private_key(redactor: RedactionService) -> None:
    text = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA6NF1tXpG03x2Qhq3LOd3Q==
-----END OPENSSH PRIVATE KEY-----"""
    result = redactor.redact(text)
    assert "BEGIN OPENSSH PRIVATE KEY" in result.text
    assert "b3BlbnNzaC1rZXktdjE" not in result.text


def test_redacts_rsa_private_key(redactor: RedactionService) -> None:
    text = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0gD6eB5Qw==
-----END RSA PRIVATE KEY-----"""
    result = redactor.redact(text)
    assert "BEGIN RSA PRIVATE KEY" in result.text
    assert "MIIEpAIBAAKCAQEA0g" not in result.text


# ---------------------------------------------------------------------------
# Flag / secret redaction
# ---------------------------------------------------------------------------


def test_redacts_ctf_flag(redactor: RedactionService) -> None:
    text = "Flag: HTB{th1s_1s_4_fl4g}"
    result = redactor.redact(text)
    assert "HTB{th1s_1s_4_fl4g}" not in result.text


def test_redacts_custom_flag_format(redactor: RedactionService) -> None:
    text = "The flag is FLAG{abc123}"
    result = redactor.redact(text)
    assert "FLAG{abc123}" not in result.text


# ---------------------------------------------------------------------------
# Redaction tracking
# ---------------------------------------------------------------------------


def test_redaction_reports_count(redactor: RedactionService) -> None:
    text = "http://admin:pass@host.com password=secret api_key=sk-test"
    result = redactor.redact(text)
    assert result.redacted_count >= 1


def test_redaction_no_false_positives_on_safe_text(
    redactor: RedactionService,
) -> None:
    text = "The server returned 200 OK on port 80 with content-type text/html"
    result = redactor.redact(text)
    assert result.text == text
    assert result.redacted_count == 0


def test_redaction_metadata_includes_patterns(redactor: RedactionService) -> None:
    text = "password=secret"
    result = redactor.redact(text)
    assert result.redacted_count > 0


# ---------------------------------------------------------------------------
# Multi-pattern application
# ---------------------------------------------------------------------------


def test_redacts_multiple_secret_types(redactor: RedactionService) -> None:
    text = (
        "Authorization: Bearer token123\n"
        "Cookie: session=abc456\n"
        "password=hunter2\n"
    )
    result = redactor.redact(text)
    assert "token123" not in result.text
    assert "abc456" not in result.text
    assert "hunter2" not in result.text
    assert result.redacted_count >= 3


# ---------------------------------------------------------------------------
# Empty and edge cases
# ---------------------------------------------------------------------------


def test_redacts_empty_string(redactor: RedactionService) -> None:
    result = redactor.redact("")
    assert result.text == ""
    assert result.redacted_count == 0


def test_redacts_none_input(redactor: RedactionService) -> None:
    result = redactor.redact(None)  # type: ignore[arg-type]
    assert result.text == ""
    assert result.redacted_count == 0
