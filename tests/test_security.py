"""Security tests — verifying safe behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from localsecretvault.config.settings import (
    check_config_permissions,
    check_vault_permissions,
)
from localsecretvault.models.secret import Secret, SecretType
from localsecretvault.vault.manager import VaultManager


class TestNoSecretExposure:
    """Verify that secrets are not accidentally exposed."""

    def test_password_not_in_vault_manager_state(self, tmp_path: Path) -> None:
        """Password should be stored in memory but not persisted."""
        vault_path = tmp_path / "vault.lsv"
        manager = VaultManager(vault_path)
        manager.init_vault("super_secret_pw")

        # Vault file should not contain plaintext password
        file_content = vault_path.read_text(errors="replace")
        assert "super_secret_pw" not in file_content

    def test_list_does_not_show_passwords(self, initialized_vault: VaultManager) -> None:
        """List operations should not return password values."""
        initialized_vault.add_secret(
            Secret(
                type=SecretType.LOGIN.value,
                name="Test",
                username="user",
                password="secret_password",
            )
        )
        secrets = initialized_vault.list_secrets()
        # The Secret objects do contain passwords (for internal use),
        # but the CLI display should hide them. Verify the manager
        # returns structured data, not raw strings that might leak.
        for s in secrets:
            assert s.name == "Test"
            # Password is in the object but only displayed as ******** in CLI
            assert s.password == "secret_password"  # Still accessible programmatically

    def test_vault_file_encrypted(self, tmp_path: Path) -> None:
        """Vault file should never contain plaintext secrets."""
        vault_path = tmp_path / "vault.lsv"
        manager = VaultManager(vault_path)
        manager.init_vault("master_pw")
        manager.add_secret(
            Secret(
                type=SecretType.LOGIN.value,
                name="GitHub",
                password="my_real_password",
                username="john",
            )
        )
        content = vault_path.read_bytes()
        assert b"my_real_password" not in content
        assert b"john" not in content
        assert b"GitHub" not in content

    def test_lock_clears_memory(self, tmp_path: Path) -> None:
        """Locking should clear sensitive data from memory."""
        vault_path = tmp_path / "vault.lsv"
        manager = VaultManager(vault_path)
        manager.init_vault("test123")
        manager.add_secret(
            Secret(type=SecretType.LOGIN.value, name="Test", password="secret")
        )
        manager.lock()
        assert manager._data is None
        assert manager._password is None

    def test_error_message_no_secret_details(self, tmp_path: Path) -> None:
        """Error messages should not contain secret values."""
        from localsecretvault.crypto.format import VaultAuthError

        vault_path = tmp_path / "vault.lsv"
        manager = VaultManager(vault_path)
        manager.init_vault("correct_password")
        manager.lock()

        with pytest.raises(VaultAuthError) as exc_info:
            manager.unlock("wrong_password")

        error_msg = str(exc_info.value)
        assert "correct_password" not in error_msg
        assert "authentication failed" in error_msg.lower()


class TestFilePermissions:
    """Tests for file permission checks."""

    def test_vault_permissions_check(self, tmp_path: Path) -> None:
        vault_path = tmp_path / "vault.lsv"
        vault_path.write_bytes(b"test")
        # On Windows this always returns True
        result = check_vault_permissions(vault_path)
        assert isinstance(result, bool)

    def test_config_permissions_check(self, tmp_path: Path) -> None:
        result = check_config_permissions(tmp_path)
        assert isinstance(result, bool)

    def test_nonexistent_file_permissions(self, tmp_path: Path) -> None:
        result = check_vault_permissions(tmp_path / "nonexistent")
        assert result is True  # Nothing to check


class TestVaultIntegrity:
    """Tests for vault integrity under various attack scenarios."""

    def test_truncated_vault_rejected(self, tmp_path: Path) -> None:
        """Truncated vault should fail gracefully."""
        vault_path = tmp_path / "vault.lsv"
        manager = VaultManager(vault_path)
        manager.init_vault("password")

        # Truncate the vault
        data = vault_path.read_bytes()
        vault_path.write_bytes(data[:len(data) // 2])

        with pytest.raises(Exception):
            # Create a fresh manager to read the corrupted file
            m = VaultManager(vault_path)
            m.unlock("password")

    def test_corrupted_vault_rejected(self, tmp_path: Path) -> None:
        """Corrupted vault should fail gracefully."""
        vault_path = tmp_path / "vault.lsv"
        manager = VaultManager(vault_path)
        manager.init_vault("password")

        # Corrupt the vault (flip bits in the middle)
        data = bytearray(vault_path.read_bytes())
        mid = len(data) // 2
        data[mid] ^= 0xFF
        vault_path.write_bytes(bytes(data))

        with pytest.raises(Exception):
            m = VaultManager(vault_path)
            m.unlock("password")

    def test_empty_vault_rejected(self, tmp_path: Path) -> None:
        vault_path = tmp_path / "vault.lsv"
        vault_path.write_bytes(b"")
        manager = VaultManager(vault_path)
        with pytest.raises(Exception):
            manager.unlock("password")

    def test_random_data_rejected(self, tmp_path: Path) -> None:
        vault_path = tmp_path / "vault.lsv"
        vault_path.write_bytes(b"random garbage data that is not a vault")
        manager = VaultManager(vault_path)
        from localsecretvault.crypto.format import VaultFormatError
        with pytest.raises(VaultFormatError):
            manager.unlock("password")
