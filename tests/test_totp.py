"""Tests for TOTP (RFC 6238) service."""

from __future__ import annotations

import base64

import pytest

from localsecretvault.services.totp import (
    decode_totp_secret,
    generate_totp_secret,
    hotp,
    normalize_base32,
    provisioning_uri,
    totp_now,
    totp_remaining_seconds,
    verify_totp,
)

# RFC 6238 test vectors (SHA1, 8 digits) use secret "12345678901234567890"
# For 6-digit codes we use well-known base32 secrets and check determinism + drift.
RFC_SECRET_RAW = b"12345678901234567890"
RFC_SECRET_B32 = base64.b32encode(RFC_SECRET_RAW).decode().rstrip("=")  # GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ


class TestSecretHandling:
    def test_generate_secret_is_base32(self) -> None:
        secret = generate_totp_secret()
        assert secret.isupper() or secret.isdigit()
        decoded = base64.b32decode(normalize_base32(secret))
        assert len(decoded) >= 16

    def test_generate_secret_unique(self) -> None:
        assert generate_totp_secret() != generate_totp_secret()

    def test_generate_secret_min_length(self) -> None:
        with pytest.raises(ValueError):
            generate_totp_secret(10)

    def test_normalize_strips_spaces_and_dashes(self) -> None:
        assert normalize_base32("abcd efgh") == "ABCDEFGH"  # noqa: S105
        assert normalize_base32("abcd-efgh-ijkl") == "ABCDEFGHIJKL===="  # noqa: S105

    def test_decode_roundtrip(self) -> None:
        decoded = decode_totp_secret(RFC_SECRET_B32)
        assert decoded == RFC_SECRET_RAW

    def test_decode_invalid_secret(self) -> None:
        with pytest.raises(ValueError):
            decode_totp_secret("not!valid!base32!!")


class TestCodeGeneration:
    def test_deterministic(self) -> None:
        code1 = totp_now(RFC_SECRET_B32, at_time=1_700_000_000)
        code2 = totp_now(RFC_SECRET_B32, at_time=1_700_000_000)
        assert code1 == code2

    def test_code_format(self) -> None:
        code = totp_now(RFC_SECRET_B32, at_time=1_700_000_000)
        assert len(code) == 6
        assert code.isdigit()

    def test_code_changes_with_time(self) -> None:
        code1 = totp_now(RFC_SECRET_B32, at_time=1_700_000_000)
        code2 = totp_now(RFC_SECRET_B32, at_time=1_700_000_030)
        assert code1 != code2

    def test_custom_digits(self) -> None:
        code = totp_now(RFC_SECRET_B32, at_time=1_700_000_000, digits=8)
        assert len(code) == 8

    def test_invalid_period(self) -> None:
        with pytest.raises(ValueError):
            totp_now(RFC_SECRET_B32, period=0)

    def test_rfc6238_vectors_30s(self) -> None:
        """RFC 6238 SHA-1 vectors: time/count pairs with known HOTP values (8 digits)."""
        # (unix_time, expected_totp_8digits) — RFC 6238 Appendix B, SHA-1
        vectors: list[tuple[int, str]] = [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ]
        for unix_time, expected in vectors:
            assert hotp(RFC_SECRET_B32, unix_time // 30, digits=8) == expected

    def test_verify_current_code(self) -> None:
        code = totp_now(RFC_SECRET_B32, at_time=1_700_000_000)
        assert verify_totp(RFC_SECRET_B32, code, at_time=1_700_000_000)

    def test_verify_rejects_wrong_code(self) -> None:
        assert not verify_totp(RFC_SECRET_B32, "000000", at_time=1_700_000_000)

    def test_verify_accepts_drift(self) -> None:
        code_prev = totp_now(RFC_SECRET_B32, at_time=1_700_000_000 - 30)
        assert verify_totp(RFC_SECRET_B32, code_prev, at_time=1_700_000_000, valid_window=1)

    def test_verify_rejects_far_drift(self) -> None:
        code_old = totp_now(RFC_SECRET_B32, at_time=1_700_000_000 - 300)
        assert not verify_totp(RFC_SECRET_B32, code_old, at_time=1_700_000_000, valid_window=1)

    def test_verify_rejects_non_numeric(self) -> None:
        assert not verify_totp(RFC_SECRET_B32, "abcdef")
        assert not verify_totp(RFC_SECRET_B32, "")
        assert not verify_totp(RFC_SECRET_B32, "12345")  # wrong length


class TestUtilityFunctions:
    def test_remaining_seconds_bounds(self) -> None:
        remaining = totp_remaining_seconds(at_time=1_700_000_000)
        assert 0 < remaining <= 30

    def test_provisioning_uri_format(self) -> None:
        uri = provisioning_uri("alice@example.com", RFC_SECRET_B32, issuer="MyApp")
        assert uri.startswith("otpauth://totp/MyApp:alice%40example.com?")
        assert RFC_SECRET_B32 in uri
        assert "issuer=MyApp" in uri
        assert "digits=6" in uri
        assert "period=30" in uri
