"""Tests for vault backup and restore."""

from __future__ import annotations

from pathlib import Path

import pytest

from localsecretvault.models.secret import Secret, SecretType
from localsecretvault.services.backup import create_backup, restore_backup
from localsecretvault.vault.manager import VaultManager


class TestBackup:
    """Tests for creating encrypted backups."""

    def test_backup_creates_file(self, initialized_vault: VaultManager, tmp_path: Path) -> None:
        backup_path = tmp_path / "backup.lsv"
        create_backup(backup_path, source_path=initialized_vault.vault_path)
        assert backup_path.exists()

    def test_backup_is_encrypted(self, initialized_vault: VaultManager, tmp_path: Path) -> None:
        backup_path = tmp_path / "backup.lsv"
        create_backup(backup_path, source_path=initialized_vault.vault_path)
        content = backup_path.read_bytes()
        assert content[:4] == b"LSV1"

    def test_backup_no_vault_raises(self, tmp_path: Path) -> None:
        backup_path = tmp_path / "backup.lsv"
        with pytest.raises(FileNotFoundError):
            create_backup(backup_path, source_path=tmp_path / "nonexistent.lsv")

    def test_backup_no_overwrite_without_flag(self, initialized_vault: VaultManager, tmp_path: Path) -> None:
        backup_path = tmp_path / "backup.lsv"
        create_backup(backup_path, source_path=initialized_vault.vault_path)
        with pytest.raises(FileExistsError):
            create_backup(backup_path, source_path=initialized_vault.vault_path, overwrite=False)

    def test_backup_overwrite_with_flag(self, initialized_vault: VaultManager, tmp_path: Path) -> None:
        backup_path = tmp_path / "backup.lsv"
        create_backup(backup_path, source_path=initialized_vault.vault_path)
        create_backup(backup_path, source_path=initialized_vault.vault_path, overwrite=True)
        assert backup_path.exists()

    def test_backup_preserves_secrets(self, initialized_vault: VaultManager, tmp_path: Path) -> None:
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="Test", password="secret123")
        )
        backup_path = tmp_path / "backup.lsv"
        create_backup(backup_path, source_path=initialized_vault.vault_path)

        # Restore to a new vault manager
        vault_path = tmp_path / "restored.lsv"
        restore_manager = VaultManager(vault_path)
        restore_backup(backup_path, dest_path=vault_path)
        restore_manager.unlock("test_password_123")
        found = restore_manager.get_secret("Test")
        assert found.password == "secret123"


class TestRestore:
    """Tests for restoring from backups."""

    def test_restore_basic(self, initialized_vault: VaultManager, tmp_path: Path) -> None:
        backup_path = tmp_path / "backup.lsv"
        vault_path = initialized_vault.vault_path
        create_backup(backup_path, source_path=vault_path)
        restore_backup(backup_path, dest_path=vault_path)
        assert vault_path.exists()

    def test_restore_creates_safety_backup(self, initialized_vault: VaultManager, tmp_path: Path) -> None:
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="Original", password="pw1")
        )
        vault_path = initialized_vault.vault_path

        # Create backup
        backup_path = tmp_path / "backup.lsv"
        create_backup(backup_path, source_path=vault_path)

        # Modify vault
        initialized_vault.add_secret(
            Secret(type=SecretType.LOGIN.value, name="Added", password="pw2")
        )

        # Restore from backup
        restore_backup(backup_path, dest_path=vault_path, create_safety_backup=True)

        # Safety backup should exist
        safety_path = vault_path.with_suffix(vault_path.suffix + ".pre-restore")
        assert safety_path.exists()

    def test_restore_invalid_file(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.lsv"
        bad_file.write_text("not a valid vault")
        with pytest.raises(ValueError, match="not a valid vault"):
            restore_backup(bad_file, dest_path=tmp_path / "vault.lsv")

    def test_restore_nonexistent_file(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            restore_backup(tmp_path / "nonexistent.lsv", dest_path=tmp_path / "vault.lsv")

    def test_restore_validates_before_replacing(self, initialized_vault: VaultManager, tmp_path: Path) -> None:
        """Corrupted backup should not modify the existing vault."""
        vault_path = initialized_vault.vault_path
        original_data = vault_path.read_bytes()

        # Try to restore from a corrupted file (not valid format)
        bad_backup = tmp_path / "bad.lsv"
        bad_backup.write_bytes(b"NOT_A_VAULT_FILE")

        with pytest.raises(ValueError):
            restore_backup(bad_backup, dest_path=vault_path)

        # Vault should be unchanged
        assert vault_path.read_bytes() == original_data
