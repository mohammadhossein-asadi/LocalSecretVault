"""AES-256-GCM authenticated encryption for vault data."""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-GCM standard nonce size
NONCE_LENGTH = 12


def generate_nonce(length: int = NONCE_LENGTH) -> bytes:
    """Generate a cryptographically secure random nonce."""
    return secrets.token_bytes(length)


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
    """Encrypt plaintext with AES-256-GCM.

    Returns nonce || ciphertext (including GCM tag).
    The nonce is prepended so decryption can extract it.
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")

    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    return nonce + ciphertext


def decrypt(key: bytes, data: bytes, associated_data: bytes | None = None) -> bytes:
    """Decrypt AES-256-GCM ciphertext.

    Expects input format: nonce || ciphertext_with_tag.
    Raises ValueError on authentication failure or invalid data.
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")

    if len(data) < NONCE_LENGTH:
        raise ValueError("Ciphertext too short: missing nonce")

    nonce = data[:NONCE_LENGTH]
    ciphertext = data[NONCE_LENGTH:]

    if not ciphertext:
        raise ValueError("Ciphertext too short: empty payload")

    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except Exception as exc:
        # Never reveal whether decryption failed vs authentication failed
        raise ValueError("Vault authentication failed.") from exc
