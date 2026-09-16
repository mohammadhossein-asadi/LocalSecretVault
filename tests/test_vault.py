"""Tests for the vault manager."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from localsecretvault.models.secret import Secret, SecretType
from localsecretvault.vault.manager import (
    DuplicateSecretError,
    SecretNotFoundError,
    VaultLockedError,
    VaultManager,
)

class TestVaultLifecycle:
    """Tests for vault initialization, unlock, and lock."""

    def test_init_creates_vault(self, tmp_path: Path) -> None:
        vault_path = tmp_path / "vault.lsv"
        manager = VaultManager(vault_path)
        manager.init_vault("test123")
        assert vault_path.exists()
        assert manager.is_unlocked

    def test_unlock_after_init(self, tmp_path: Path) -> None:
        vault_path = tmp_path / "vault.lsv"
        manager = VaultManager(vault_path)
        manager.init_vault("test123")
        manager.lock()
        assert not manager.is_unlocked

        manager.unlock("test123")
        assert manager.is_unlocked

    def test_wrong_password_unlock(self, tmp_path: Path) -> None:
        vault_path = tmp_path / "vault.lsv"
        manager = VaultManager(vault_path)
        manager.init_vault("correct_password")

        manager2 = VaultManager(vault_path)
        from localsecretvault.crypto.format import VaultAuthError
        with pytest.raises(VaultAuthError):
            manager2.unlock("wrong_password")

    def test_init_existing_vault_raises(self, tmp_path: Path) -> None:
        vault_path = tmp_path / "vault.lsv"
        manager = VaultManager(vault_path)
        manager.init_vault("test123")
        with pytest.raises(FileExistsError):
            manager.init_vault("test123")

    def test_lock_clears_state(self, tmp_path: Path) -> None:
        vault_path = tmp_path / "vault.lsv"
        manager = VaultManager(vault_path)
        manager.init_vault("test123")
        manager.lock()
        assert not manager.is_unlocked
        assert manager._data is None
        assert manager._password is None

class TestVaultCRUD:
    """Tests for add, get, edit, delete operations."""

    def test_add_secret(self, initialized_vault: VaultManager) -> None:
        secret = Secret(
            type=SecretType.LOGIN.value,
            name="GitHub",
            username="user",
            password="pass",
            url="https://github.com",
            tags=["dev"],
        )
        result = initialized_vault.add_secret(secret)
        assert result.name == "GitHub"

        retrieved = initialized_vault.get_secret("GitHub")
        assert retrieved.name == "GitHub"
        assert retrieved.password == "pass"

    def test_add_duplicate_name_raises(self, initialized_vault: VaultManager) -> None:
        s1 = Secret(type=SecretType.LOGIN.value, name="GitHub", password="pw1")
        s2 = Secret(type=SecretType.LOGIN.value, name="GitHub", password="pw2")
        initialized_vault.add_secret(s1)
        with pytest.raises(DuplicateSecretError):
            initialized_vault.add_secret(s2)

    def test_add_duplicate_case_insensitive(self, initialized_vault: VaultManager) -> None:
        s1 = Secret(type=SecretType.LOGIN.value, name="github", password="pw1")
        s2 = Secret(type=SecretType.LOGIN.value, name="GitHub", password="pw2")
        initialized_vault.add_secret(s1)
        with pytest.raises(DuplicateSecretError):
            initialized_vault.add_secret(s2)

    def test_get_by_name(self, initialized_vault: VaultManager) -> None:
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="TestLogin", password="pw")
        )
        found = initialized_vault.get_secret("TestLogin")
        assert found.name == "TestLogin"

    def test_get_by_name_case_insensitive(self, initialized_vault: VaultManager) -> None:
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="MySecret", password="pw")
        )
        found = initialized_vault.get_secret("mysecret")
        assert found.name == "MySecret"

    def test_get_by_id(self, initialized_vault: VaultManager) -> None:
        s = Secret(type=SecretType.LOGIN.value, name="TestLogin", password="pw")
        initialized_vault.add_secret(s)
        found = initialized_vault.get_secret(s.id)
        assert found.name == "TestLogin"

    def test_get_not_found(self, initialized_vault: VaultManager) -> None:
        with pytest.raises(SecretNotFoundError):
            initialized_vault.get_secret("nonexistent")

    def test_edit_secret(self, initialized_vault: VaultManager) -> None:
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="GitHub", username="old_user")
        )
        initialized_vault.edit_secret("GitHub", username="new_user")
        found = initialized_vault.get_secret("GitHub")
        assert found.username == "new_user"

    def test_edit_multiple_fields(self, initialized_vault: VaultManager) -> None:
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="GitHub")
        )
        initialized_vault.edit_secret(
            "GitHub",
            username="user",
            password="pass",
            url="https://github.com",
        )
        found = initialized_vault.get_secret("GitHub")
        assert found.username == "user"
        assert found.password == "pass"
        assert found.url == "https://github.com"

    def test_edit_not_found(self, initialized_vault: VaultManager) -> None:
        with pytest.raises(SecretNotFoundError):
            initialized_vault.edit_secret("nonexistent", name="new")

    def test_delete_secret(self, initialized_vault: VaultManager) -> None:
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="ToDelete", password="pw")
        )
        deleted = initialized_vault.delete_secret("ToDelete")
        assert deleted.name == "ToDelete"

        with pytest.raises(SecretNotFoundError):
            initialized_vault.get_secret("ToDelete")

    def test_delete_not_found(self, initialized_vault: VaultManager) -> None:
        with pytest.raises(SecretNotFoundError):
            initialized_vault.delete_secret("nonexistent")

    def test_persistence_after_add(self, tmp_path: Path) -> None:
        """Secrets survive lock/unlock cycles."""
        vault_path = tmp_path / "vault.lsv"
        m1 = VaultManager(vault_path)
        m1.init_vault("pass123")
        m1.add_secret(
            Secret(type=SecretType.LOGIN.value, name="Persistent", password="secret")
        )
        m1.lock()

        m2 = VaultManager(vault_path)
        m2.unlock("pass123")
        found = m2.get_secret("Persistent")
        assert found.password == "secret"

class TestVaultSearch:
    """Tests for search and listing."""

    def test_list_all(self, initialized_vault: VaultManager) -> None:
        initialized_vault.add_secret(Secret(type=SecretType.LOGIN.value, name="A"))
        initialized_vault.add_secret(Secret(type=SecretType.API_KEY.value, name="B"))
        secrets = initialized_vault.list_secrets()
        assert len(secrets) == 2

    def test_list_filter_type(self, initialized_vault: VaultManager) -> None:
        initialized_vault.add_secret(Secret(type=SecretType.LOGIN.value, name="Login1"))
        initialized_vault.add_secret(Secret(type=SecretType.LOGIN.value, name="Login2"))
        initialized_vault.add_secret(Secret(type=SecretType.API_KEY.value, name="Key1"))
        logins = initialized_vault.list_secrets(secret_type=SecretType.LOGIN.value)
        assert len(logins) == 2

    def test_list_filter_tag(self, initialized_vault: VaultManager) -> None:
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="A", tags=["dev"])
        )
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="B", tags=["prod"])
        )
        dev = initialized_vault.list_secrets(tag="dev")
        assert len(dev) == 1
        assert dev[0].name == "A"

    def test_search_by_name(self, initialized_vault: VaultManager) -> None:
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="GitHub Account")
        )
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="AWS Console")
        )
        results = initialized_vault.search("github")
        assert len(results) == 1
        assert results[0].name == "GitHub Account"

    def test_search_by_username(self, initialized_vault: VaultManager) -> None:
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="A", username="john_doe")
        )
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="B", username="jane_smith")
        )
        results = initialized_vault.search("john")
        assert len(results) == 1

    def test_search_by_url(self, initialized_vault: VaultManager) -> None:
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="A", url="https://github.com")
        )
        results = initialized_vault.search("github.com")
        assert len(results) == 1

    def test_search_by_tag(self, initialized_vault: VaultManager) -> None:
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="A", tags=["production", "backend"])
        )
        results = initialized_vault.search("production")
        assert len(results) == 1

    def test_search_by_type(self, initialized_vault: VaultManager) -> None:
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="A")
        )
        results = initialized_vault.search("Login")
        assert len(results) == 1

    def test_search_no_results(self, initialized_vault: VaultManager) -> None:
        initialized_vault.add_secret(Secret(type=SecretType.LOGIN.value, name="A"))
        results = initialized_vault.search("nonexistent")
        assert len(results) == 0

    def test_get_all_tags(self, initialized_vault: VaultManager) -> None:
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="A", tags=["dev", "web"])
        )
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="B", tags=["dev", "api"])
        )
        tags = initialized_vault.get_all_tags()
        assert set(tags) == {"api", "dev", "web"}

class TestVaultAutoLock:
    """Tests for auto-lock functionality."""

    def test_auto_lock_triggers(self, tmp_path: Path) -> None:
        vault_path = tmp_path / "vault.lsv"
        manager = VaultManager(vault_path)
        manager.init_vault("test123")
        manager._auto_lock_minutes = 1  # 1 minute timeout
        manager._last_activity = time.time() - 120  # 2 minutes ago

        assert manager.check_auto_lock()
        assert not manager.is_unlocked

    def test_auto_lock_disabled(self, tmp_path: Path) -> None:
        vault_path = tmp_path / "vault.lsv"
        manager = VaultManager(vault_path)
        manager.init_vault("test123")
        manager._auto_lock_minutes = -1  # Disabled (negative)
        manager._last_activity = time.time() - 100

        assert not manager.check_auto_lock()
        assert manager.is_unlocked

    def test_locked_vault_operations_reject(self, tmp_path: Path) -> None:
        vault_path = tmp_path / "vault.lsv"
        manager = VaultManager(vault_path)
        manager.init_vault("test123")
        manager.lock()

        with pytest.raises(VaultLockedError):
            manager.list_secrets()
        with pytest.raises(VaultLockedError):
            manager.search("test")
        with pytest.raises(VaultLockedError):
            manager.add_secret(Secret(type="Login", name="test"))
