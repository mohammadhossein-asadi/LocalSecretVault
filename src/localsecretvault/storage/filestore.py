"""Atomic file storage for the encrypted vault."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from localsecretvault.config.settings import (
    ensure_config_permissions,
    ensure_vault_permissions,
    get_vault_path,
)
from localsecretvault.crypto.format import is_valid_vault


def read_vault_file(path: Path | None = None) -> bytes:
    """Read the vault file from disk.

    Returns the raw bytes of the vault file.
    Raises FileNotFoundError if vault doesn't exist.
    """
    vault_path = path or get_vault_path()
    if not vault_path.exists():
        raise FileNotFoundError(f"No vault found at {vault_path}")
    return vault_path.read_bytes()


def write_vault_file(data: bytes, path: Path | None = None) -> None:
    """Write the vault file atomically.

    Uses write-to-temp → flush → fsync → rename pattern
    to protect against data loss from interruption.
    """
    vault_path = path or get_vault_path()
    # Use the vault file's parent directory as the temp location
    config_dir = vault_path.parent
    config_dir.mkdir(parents=True, exist_ok=True)

    # Ensure config directory permissions
    ensure_config_permissions(config_dir)

    # Write to a temporary file in the same directory
    fd: int | None = None
    temp_path: Path | None = None
    try:
        fd, temp_path_str = tempfile.mkstemp(
            dir=str(config_dir),
            prefix=".vault_tmp_",
            suffix=".tmp",
        )
        temp_path = Path(temp_path_str)

        # Write the data
        os.write(fd, data)

        # Flush to disk
        os.fsync(fd)

        # Close the file descriptor before rename
        os.close(fd)
        fd = None

        # Atomic rename (same filesystem guaranteed since same directory)
        os.replace(str(temp_path), str(vault_path))

        # Set secure permissions
        ensure_vault_permissions(vault_path)

    except Exception:
        # Clean up on failure
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if temp_path is not None and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise


def vault_exists(path: Path | None = None) -> bool:
    """Check if a vault file exists and has valid format."""
    vault_path = path or get_vault_path()
    if not vault_path.exists():
        return False
    try:
        return is_valid_vault(vault_path.read_bytes())
    except Exception:
        return False


def vault_file_exists_on_disk(path: Path | None = None) -> bool:
    """Check if a vault file exists on disk (regardless of format validity)."""
    vault_path = path or get_vault_path()
    return vault_path.exists()


def validate_vault_file(path: Path | None = None) -> tuple[bool, str]:
    """Validate the vault file format without decrypting.

    Returns (is_valid, message).
    """
    vault_path = path or get_vault_path()
    if not vault_path.exists():
        return False, "Vault file does not exist."

    try:
        data = vault_path.read_bytes()
    except OSError as exc:
        return False, f"Cannot read vault file: {exc}"

    if not data:
        return False, "Vault file is empty."

    if not is_valid_vault(data):
        return False, "Vault file has invalid format."

    return True, "Vault format is valid."
