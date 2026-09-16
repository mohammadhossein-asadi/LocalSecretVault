"""Encrypted vault backup and restore."""

from __future__ import annotations

import shutil
from pathlib import Path

from localsecretvault.config.settings import SAFETY_BACKUP_SUFFIX, get_vault_path
from localsecretvault.crypto.format import is_valid_vault
from localsecretvault.storage.filestore import read_vault_file, write_vault_file

def create_backup(
    dest_path: Path,
    *,
    overwrite: bool = False,
    source_path: Path | None = None,
) -> None:
    """Create an encrypted backup of the vault.

    The backup remains encrypted (same format as the vault file).
    """
    vault_path = source_path or get_vault_path()

    if not vault_path.exists():
        raise FileNotFoundError("No vault found to back up.")

    if dest_path.exists() and not overwrite:
        raise FileExistsError(
            f"Backup file already exists: {dest_path}\n"
            "Use --yes to overwrite."
        )

    # Read the vault (still encrypted)
    vault_data = read_vault_file(vault_path)

    # Write to destination
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    write_vault_file(vault_data, dest_path)

def restore_backup(
    backup_path: Path,
    *,
    create_safety_backup: bool = True,
    overwrite: bool = False,
    dest_path: Path | None = None,
) -> None:
    """Restore a vault from a backup file.

    The backup must be a valid encrypted vault file.
    Creates a safety backup of the current vault before restoring.
    """
    if not backup_path.exists():
        raise FileNotFoundError(f"Backup file not found: {backup_path}")

    # Validate the backup
    backup_data = backup_path.read_bytes()
    if not is_valid_vault(backup_data):
        raise ValueError(
            "Backup file is not a valid vault file.\n"
            "Restore aborted.\n"
            "The current vault was not modified."
        )

    vault_path = dest_path or get_vault_path()

    # Create safety backup of current vault
    if vault_path.exists() and create_safety_backup:
        safety_path = vault_path.with_suffix(vault_path.suffix + SAFETY_BACKUP_SUFFIX)
        shutil.copy2(str(vault_path), str(safety_path))

    # Restore
    write_vault_file(backup_data, vault_path)
