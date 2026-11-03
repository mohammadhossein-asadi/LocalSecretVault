"""RFC 6238 TOTP (time-based one-time password) support.

Pure-standard-library implementation (HMAC-SHA1 via hashlib/hmac).
No network access, no third-party dependencies.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
import urllib.parse

# Default TOTP parameters
DEFAULT_PERIOD = 30
DEFAULT_DIGITS = 6
DEFAULT_ALGORITHM = "SHA1"

# A minimal, high-frequency word set is NOT used here — TOTP secrets are base32.
BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def generate_totp_secret(length: int = 32) -> str:
    """Generate a random TOTP secret as base32 (no padding).

    Args:
        length: Number of random bytes (before base32 encoding). 20+ recommended.

    Returns:
        Base32-encoded secret string (uppercase, no '=' padding).
    """
    import secrets

    if length < 16:
        raise ValueError("TOTP secret must be at least 16 bytes of entropy.")
    raw = secrets.token_bytes(length)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def normalize_base32(secret: str) -> str:
    """Normalize a base32 secret: strip spaces, uppercase, re-pad for decode."""
    cleaned = secret.strip().replace(" ", "").replace("-", "").upper()
    # Strip existing padding, then re-pad to a multiple of 8
    cleaned = cleaned.rstrip("=")
    padding = (8 - len(cleaned) % 8) % 8
    return cleaned + "=" * padding


def decode_totp_secret(secret: str) -> bytes:
    """Decode a base32 TOTP secret into raw bytes.

    Raises ValueError if the secret is not valid base32.
    """
    normalized = normalize_base32(secret)
    try:
        return base64.b32decode(normalized, casefold=True)
    except Exception as exc:
        raise ValueError("Invalid base32 TOTP secret.") from exc


def hotp(secret: str, counter: int, digits: int = DEFAULT_DIGITS) -> str:
    """RFC 4226 HMAC-based one-time password."""
    key = decode_totp_secret(secret)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    )
    return str(code_int % (10**digits)).zfill(digits)


def totp_now(
    secret: str,
    period: int = DEFAULT_PERIOD,
    digits: int = DEFAULT_DIGITS,
    at_time: float | None = None,
) -> str:
    """Generate the current TOTP code for a secret.

    Args:
        secret: Base32-encoded TOTP secret.
        period: Time step in seconds (default 30).
        digits: Code length (default 6).
        at_time: Unix timestamp to use (defaults to now). Useful for tests.

    Returns:
        The current OTP code as a zero-padded string.
    """
    if period <= 0:
        raise ValueError("TOTP period must be positive.")
    timestamp = at_time if at_time is not None else time.time()
    counter = int(timestamp // period)
    return hotp(secret, counter, digits)


def totp_remaining_seconds(period: int = DEFAULT_PERIOD, at_time: float | None = None) -> int:
    """Seconds remaining until the current TOTP code expires."""
    timestamp = at_time if at_time is not None else time.time()
    return period - int(timestamp) % period


def verify_totp(
    secret: str,
    code: str,
    period: int = DEFAULT_PERIOD,
    digits: int = DEFAULT_DIGITS,
    valid_window: int = 1,
    at_time: float | None = None,
) -> bool:
    """Verify a TOTP code, allowing +/- `valid_window` time steps of drift.

    Uses constant-time comparison to avoid timing attacks.
    """
    if not code or not code.isdigit() or len(code) != digits:
        return False
    timestamp = at_time if at_time is not None else time.time()
    current_counter = int(timestamp // period)

    for offset in range(-valid_window, valid_window + 1):
        counter = current_counter + offset
        if counter < 0:
            continue
        expected = hotp(secret, counter, digits)
        if hmac.compare_digest(expected, code):
            return True
    return False


def provisioning_uri(
    account: str,
    secret: str,
    issuer: str = "LocalSecretVault",
    period: int = DEFAULT_PERIOD,
    digits: int = DEFAULT_DIGITS,
) -> str:
    """Build an otpauth:// provisioning URI for QR codes / authenticator apps."""
    # The colon separating issuer and account must NOT be percent-encoded;
    # it is the label delimiter per the otpauth:// convention.
    label = f"{urllib.parse.quote(issuer)}:{urllib.parse.quote(account)}"
    params = urllib.parse.urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": DEFAULT_ALGORITHM,
            "period": period,
            "digits": digits,
        }
    )
    return f"otpauth://totp/{label}?{params}"
