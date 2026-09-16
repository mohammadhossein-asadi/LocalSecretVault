"""Core vault manager — orchestrates encryption, storage, and secret operations."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from localsecretvault.config.settings import (
    AUTO_LOCK_MINUTES,
    get_vault_path,
)
from localsecretvault.crypto.format import (
    create_vault,
    unlock_vault,
    update_vault,
)
from localsecretvault.models.secret import Secret, SecretType, _now_iso
from localsecretvault.storage.filestore import (
    read_vault_file,
    write_vault_file,
)

class VaultLockedError(Exception):
    """Raised when a vault operation requires an unlocked vault."""

class SecretNotFoundError(Exception):
    """Raised when a secret cannot be found by name or ID."""

class DuplicateSecretError(Exception):
    """Raised when trying to create a secret with a duplicate name."""

class VaultManager:
    """Manages the lifecycle and operations of an encrypted vault."""

    def __init__(self, vault_path: Path | None = None) -> None:
        self._vault_path = vault_path or get_vault_path()
        self._password: str | None = None
        self._data: dict[str, Any] | None = None
        self._last_activity: float = 0.0
        self._auto_lock_minutes: int = AUTO_LOCK_MINUTES

    @property
    def is_unlocked(self) -> bool:
        """Whether the vault is currently decrypted in memory."""
        return self._data is not None and self._password is not None

    @property
    def vault_path(self) -> Path:
        return self._vault_path

    def _require_unlocked(self) -> dict[str, Any]:
        """Return vault data or raise if locked."""
        if not self.is_unlocked:
            raise VaultLockedError("Vault is locked. Please unlock first.")
        return self._data  # type: ignore[return-value]

    def _touch_activity(self) -> None:
        """Update the last activity timestamp for auto-lock."""
        self._last_activity = time.time()

    def check_auto_lock(self) -> bool:
        """Check if auto-lock should trigger. Returns True if auto-locked."""
        if not self.is_unlocked:
            return False
        if self._auto_lock_minutes <= 0:
            return False
        elapsed = time.time() - self._last_activity
        if elapsed > self._auto_lock_minutes * 60:
            self.lock()
            return True
        return False

    # ── Lifecycle ─────────────────────────────────────────────

    def init_vault(self, password: str) -> None:
        """Create a new vault with the given master password.

        Raises FileExistsError if a vault already exists.
        """
        if self._vault_path.exists():
            raise FileExistsError(f"A vault already exists at {self._vault_path}")

        data: dict[str, Any] = {
            "version": 1,
            "secrets": [],
            "metadata": {
                "created_at": _now_iso(),
                "updated_at": _now_iso(),
            },
        }

        vault_bytes = create_vault(password, data)
        write_vault_file(vault_bytes, self._vault_path)

        self._password = password
        self._data = data
        self._touch_activity()

    def unlock(self, password: str) -> None:
        """Unlock the vault with the master password.

        Raises VaultAuthError on wrong password.
        Raises VaultFormatError on corrupted file.
        """
        vault_bytes = read_vault_file(self._vault_path)
        data = unlock_vault(password, vault_bytes)

        self._password = password
        self._data = data
        self._touch_activity()

    def lock(self) -> None:
        """Lock the vault, clearing sensitive in-memory state."""
        self._password = None
        self._data = None

    def _save(self) -> None:
        """Re-encrypt and save the vault to disk. Must be unlocked."""
        data = self._require_unlocked()
        vault_bytes = read_vault_file(self._vault_path)
        updated_bytes = update_vault(self._password, vault_bytes, data)  # type: ignore[arg-type]
        write_vault_file(updated_bytes, self._vault_path)
        self._touch_activity()

    # ── CRUD ──────────────────────────────────────────────────

    def add_secret(self, secret: Secret) -> Secret:
        """Add a new secret to the vault."""
        data = self._require_unlocked()
        secrets = data.setdefault("secrets", [])

        # Check for duplicate names
        for existing in secrets:
            if existing.get("name", "").lower() == secret.name.lower():
                raise DuplicateSecretError(
                    f"A secret named '{secret.name}' already exists."
                )

        secrets.append(secret.to_dict())
        data["metadata"]["updated_at"] = _now_iso()
        self._save()
        return secret

    def get_secret(self, name_or_id: str) -> Secret:
        """Retrieve a secret by name or ID."""
        data = self._require_unlocked()
        secrets = data.get("secrets", [])

        # Search by ID first
        for item in secrets:
            if item.get("id") == name_or_id:
                return Secret.from_dict(item)

        # Then by name (case-insensitive)
        for item in secrets:
            if item.get("name", "").lower() == name_or_id.lower():
                return Secret.from_dict(item)

        raise SecretNotFoundError(f"Secret '{name_or_id}' not found.")

    def edit_secret(self, name_or_id: str, **kwargs: Any) -> Secret:
        """Edit a secret's fields. Pass field=value to update."""
        data = self._require_unlocked()
        secrets = data.get("secrets", [])

        for i, item in enumerate(secrets):
            match = item.get("id") == name_or_id or (
                item.get("name", "").lower() == name_or_id.lower()
            )
            if match:
                for key, value in kwargs.items():
                    if key in ("name", "type", "username", "password", "url", "notes", "tags", "custom_fields"):
                        item[key] = value
                item["updated_at"] = _now_iso()
                secrets[i] = item
                data["metadata"]["updated_at"] = _now_iso()
                self._save()
                return Secret.from_dict(item)

        raise SecretNotFoundError(f"Secret '{name_or_id}' not found.")

    def delete_secret(self, name_or_id: str) -> Secret:
        """Delete a secret by name or ID. Returns the deleted secret."""
        data = self._require_unlocked()
        secrets = data.get("secrets", [])

        for i, item in enumerate(secrets):
            match = item.get("id") == name_or_id or (
                item.get("name", "").lower() == name_or_id.lower()
            )
            if match:
                deleted = secrets.pop(i)
                data["metadata"]["updated_at"] = _now_iso()
                self._save()
                return Secret.from_dict(deleted)

        raise SecretNotFoundError(f"Secret '{name_or_id}' not found.")

    def list_secrets(
        self,
        secret_type: str | None = None,
        tag: str | None = None,
    ) -> list[Secret]:
        """List all secrets, optionally filtered by type and/or tag."""
        data = self._require_unlocked()
        secrets = data.get("secrets", [])

        result = []
        for item in secrets:
            if secret_type and item.get("type", "") != secret_type:
                continue
            if tag and tag not in item.get("tags", []):
                continue
            result.append(Secret.from_dict(item))

        return result

    def search(self, query: str) -> list[Secret]:
        """Search secrets by metadata (name, username, URL, tags, type)."""
        data = self._require_unlocked()
        secrets = data.get("secrets", [])

        return [
            Secret.from_dict(item)
            for item in secrets
            if Secret.from_dict(item).matches_search(query)
        ]

    def get_all_tags(self) -> list[str]:
        """Get all unique tags across all secrets."""
        data = self._require_unlocked()
        tags: set[str] = set()
        for item in data.get("secrets", []):
            tags.update(item.get("tags", []))
        return sorted(tags)

    def get_all_types(self) -> list[str]:
        """Get all unique secret types."""
        return [t.value for t in SecretType]
