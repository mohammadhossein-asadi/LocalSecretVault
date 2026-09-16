"""Tests for the cryptographic engine."""

from __future__ import annotations

import pytest

from localsecretvault.crypto.cipher import (
    NONCE_LENGTH,
    decrypt,
    encrypt,
    generate_nonce,
)
from localsecretvault.crypto.format import (
    VaultAuthError,
    VaultFormatError,
    create_vault,
    is_valid_vault,
    unlock_vault,
    update_vault,
)
from localsecretvault.crypto.kdf import (
    KDFParams,
    derive_key,
    generate_salt,
)

# ── KDF Tests ─────────────────────────────────────────────


class TestKDF:
    """Tests for Argon2id key derivation."""

    def test_generate_salt_length(self) -> None:
        salt = generate_salt()
        assert len(salt) == 32

    def test_generate_salt_randomness(self) -> None:
        salt1 = generate_salt()
        salt2 = generate_salt()
        assert salt1 != salt2

    def test_derive_key_returns_32_bytes(self) -> None:
        salt = generate_salt()
        params = KDFParams(time_cost=1, memory_cost=8192, parallelism=1)
        key = derive_key("password", salt, params)
        assert len(key) == 32

    def test_derive_key_deterministic(self) -> None:
        salt = generate_salt()
        params = KDFParams(time_cost=1, memory_cost=8192, parallelism=1)
        key1 = derive_key("password", salt, params)
        key2 = derive_key("password", salt, params)
        assert key1 == key2

    def test_derive_key_different_passwords(self) -> None:
        salt = generate_salt()
        params = KDFParams(time_cost=1, memory_cost=8192, parallelism=1)
        key1 = derive_key("password1", salt, params)
        key2 = derive_key("password2", salt, params)
        assert key1 != key2

    def test_derive_key_different_salts(self) -> None:
        params = KDFParams(time_cost=1, memory_cost=8192, parallelism=1)
        key1 = derive_key("password", generate_salt(), params)
        key2 = derive_key("password", generate_salt(), params)
        assert key1 != key2

    def test_derive_key_empty_password_raises(self) -> None:
        salt = generate_salt()
        params = KDFParams()
        with pytest.raises(ValueError, match="must not be empty"):
            derive_key("", salt, params)

    def test_kdf_params_to_dict(self) -> None:
        params = KDFParams()
        d = params.to_dict()
        assert d["algorithm"] == "argon2id"
        assert d["time_cost"] == 3
        assert d["memory_cost"] == 65536
        assert d["parallelism"] == 4
        assert d["key_length"] == 32

    def test_kdf_params_from_dict(self) -> None:
        data = {
            "algorithm": "argon2id",
            "time_cost": 5,
            "memory_cost": 32768,
            "parallelism": 2,
            "salt_length": 16,
            "key_length": 32,
        }
        params = KDFParams.from_dict(data)
        assert params.time_cost == 5
        assert params.memory_cost == 32768
        assert params.parallelism == 2


# ── Cipher Tests ──────────────────────────────────────────


class TestCipher:
    """Tests for AES-256-GCM encryption/decryption."""

    def test_generate_nonce_length(self) -> None:
        nonce = generate_nonce()
        assert len(nonce) == NONCE_LENGTH

    def test_encrypt_decrypt_roundtrip(self) -> None:
        key = b"\x01" * 32
        plaintext = b"Hello, world!"
        ciphertext = encrypt(key, plaintext)
        result = decrypt(key, ciphertext)
        assert result == plaintext

    def test_encrypt_decrypt_unicode(self) -> None:
        key = b"\x01" * 32
        plaintext = "你好世界 🌍".encode()
        ciphertext = encrypt(key, plaintext)
        result = decrypt(key, ciphertext)
        assert result == plaintext

    def test_encrypt_decrypt_large_data(self) -> None:
        key = b"\x01" * 32
        plaintext = b"x" * 1_000_000  # 1MB
        ciphertext = encrypt(key, plaintext)
        result = decrypt(key, ciphertext)
        assert result == plaintext

    def test_wrong_key_fails(self) -> None:
        key1 = b"\x01" * 32
        key2 = b"\x02" * 32
        ciphertext = encrypt(key1, b"secret")
        with pytest.raises(ValueError, match="authentication failed"):
            decrypt(key2, ciphertext)

    def test_wrong_key_fails_generic_message(self) -> None:
        """Verify error message does not reveal cryptographic details."""
        key1 = b"\x01" * 32
        key2 = b"\x02" * 32
        ciphertext = encrypt(key1, b"secret")
        with pytest.raises(ValueError) as exc_info:
            decrypt(key2, ciphertext)
        assert "authentication failed" in str(exc_info.value).lower()

    def test_truncated_ciphertext_fails(self) -> None:
        key = b"\x01" * 32
        ciphertext = encrypt(key, b"secret data here")
        truncated = ciphertext[:10]
        with pytest.raises(ValueError):
            decrypt(key, truncated)

    def test_empty_ciphertext_fails(self) -> None:
        key = b"\x01" * 32
        with pytest.raises(ValueError):
            decrypt(key, b"")

    def test_tampered_ciphertext_fails(self) -> None:
        key = b"\x01" * 32
        ciphertext = encrypt(key, b"authentic data")
        # Tamper with the last byte
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0xFF
        with pytest.raises(ValueError, match="authentication failed"):
            decrypt(key, bytes(tampered))

    def test_wrong_key_length_raises(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt(b"\x01" * 16, b"test")
        with pytest.raises(ValueError, match="32 bytes"):
            decrypt(b"\x01" * 16, b"\x00" * 12 + b"ciphertext")

    def test_with_associated_data(self) -> None:
        key = b"\x01" * 32
        aad = b"additional-context"
        ciphertext = encrypt(key, b"secret", associated_data=aad)
        result = decrypt(key, ciphertext, associated_data=aad)
        assert result == b"secret"

    def test_wrong_associated_data_fails(self) -> None:
        key = b"\x01" * 32
        aad1 = b"context-1"
        aad2 = b"context-2"
        ciphertext = encrypt(key, b"secret", associated_data=aad1)
        with pytest.raises(ValueError):
            decrypt(key, ciphertext, associated_data=aad2)


# ── Format Tests ──────────────────────────────────────────


class TestVaultFormat:
    """Tests for LSV1 vault format."""

    def test_create_vault_valid(self) -> None:
        vault = create_vault("password123")
        assert is_valid_vault(vault)
        assert vault[:4] == b"LSV1"

    def test_create_vault_with_data(self) -> None:
        data = {"secrets": [{"name": "test"}], "metadata": {}}
        vault = create_vault("password123", data)
        assert is_valid_vault(vault)

    def test_create_and_unlock_roundtrip(self) -> None:
        data = {"secrets": [], "metadata": {"created": True}}
        vault = create_vault("my_password", data)
        result = unlock_vault("my_password", vault)
        assert result == data

    def test_unlock_wrong_password(self) -> None:
        vault = create_vault("correct_password")
        with pytest.raises(VaultAuthError, match="authentication failed"):
            unlock_vault("wrong_password", vault)

    def test_unlock_wrong_password_no_detail(self) -> None:
        """Error message must not reveal crypto internals."""
        vault = create_vault("correct_password")
        with pytest.raises(VaultAuthError) as exc_info:
            unlock_vault("wrong_password", vault)
        msg = str(exc_info.value)
        assert "argon" not in msg.lower()
        assert "aes" not in msg.lower()
        assert "gcm" not in msg.lower()

    def test_format_invalid_magic(self) -> None:
        bad_data = b"XXXX" + b"\x00" * 100
        with pytest.raises(VaultFormatError, match="invalid magic"):
            unlock_vault("password", bad_data)

    def test_format_too_short(self) -> None:
        with pytest.raises(VaultFormatError, match="too short"):
            unlock_vault("password", b"LSV1")

    def test_format_truncated_payload(self) -> None:
        vault = create_vault("password")
        # Remove the last 10 bytes
        truncated = vault[:-10]
        with pytest.raises((VaultFormatError, VaultAuthError)):
            unlock_vault("password", truncated)

    def test_update_vault_roundtrip(self) -> None:
        data1 = {"secrets": [], "metadata": {"v": 1}}
        vault = create_vault("password", data1)
        data2 = {"secrets": [{"name": "new"}], "metadata": {"v": 2}}
        updated = update_vault("password", vault, data2)
        result = unlock_vault("password", updated)
        assert result == data2

    def test_update_vault_wrong_password(self) -> None:
        vault = create_vault("correct")
        with pytest.raises(VaultAuthError):
            update_vault("wrong", vault, {"data": 1})

    def test_is_valid_vault(self) -> None:
        vault = create_vault("password")
        assert is_valid_vault(vault)

    def test_is_valid_vault_empty(self) -> None:
        assert not is_valid_vault(b"")

    def test_is_valid_vault_random_data(self) -> None:
        assert not is_valid_vault(b"not a vault file at all")
