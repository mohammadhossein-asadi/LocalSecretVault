"""Argon2id key derivation for master password → encryption key."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw

# Argon2id parameters — balanced for desktop use
DEFAULT_TIME_COST = 3
DEFAULT_MEMORY_COST = 65536  # 64 MB
DEFAULT_PARALLELISM = 4
SALT_LENGTH = 32
KEY_LENGTH = 32  # 256 bits for AES-256


@dataclass(frozen=True)
class KDFParams:
    """Argon2id derivation parameters, stored with the vault."""

    algorithm: str = "argon2id"
    time_cost: int = DEFAULT_TIME_COST
    memory_cost: int = DEFAULT_MEMORY_COST
    parallelism: int = DEFAULT_PARALLELISM
    salt_length: int = SALT_LENGTH
    key_length: int = KEY_LENGTH

    def to_dict(self) -> dict[str, int | str]:
        """Serialize parameters to a JSON-safe dictionary."""
        return {
            "algorithm": self.algorithm,
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "salt_length": self.salt_length,
            "key_length": self.key_length,
        }

    @classmethod
    def from_dict(cls, data: dict[str, int | str]) -> KDFParams:
        """Deserialize parameters from a dictionary."""
        return cls(
            algorithm=str(data.get("algorithm", "argon2id")),
            time_cost=int(data.get("time_cost", DEFAULT_TIME_COST)),
            memory_cost=int(data.get("memory_cost", DEFAULT_MEMORY_COST)),
            parallelism=int(data.get("parallelism", DEFAULT_PARALLELISM)),
            salt_length=int(data.get("salt_length", SALT_LENGTH)),
            key_length=int(data.get("key_length", KEY_LENGTH)),
        )


def generate_salt(length: int = SALT_LENGTH) -> bytes:
    """Generate a cryptographically secure random salt."""
    return secrets.token_bytes(length)


def derive_key(password: str, salt: bytes, params: KDFParams) -> bytes:
    """Derive an encryption key from a password using Argon2id.

    The password string is encoded to UTF-8 bytes for the KDF.
    Never logs, prints, or stores the password.
    """
    if not password:
        raise ValueError("Password must not be empty")

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=params.key_length,
        type=Argon2Type.ID,
    )
