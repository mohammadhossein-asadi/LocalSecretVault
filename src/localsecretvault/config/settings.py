"""Platform-appropriate configuration for LocalSecretVault."""

from __future__ import annotations

import getpass
import stat
import sys
from pathlib import Path

from platformdirs import user_config_dir

APP_NAME = "localsecretvault"

# Directories
CONFIG_DIR_NAME = APP_NAME
VAULT_FILENAME = "vault.lsv"
SAFETY_BACKUP_SUFFIX = ".pre-restore"
CLIPBOARD_CLEAR_SECONDS = 30
AUTO_LOCK_MINUTES = 15


def get_config_dir() -> Path:
    """Return the platform-appropriate configuration directory."""
    config_dir = Path(user_config_dir(APP_NAME))
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_vault_path() -> Path:
    """Return the path to the vault file."""
    return get_config_dir() / VAULT_FILENAME


def ensure_vault_permissions(vault_path: Path) -> None:
    """Set secure file permissions on Unix systems (no-op on Windows)."""
    if sys.platform == "win32":
        return  # Windows ACLs are handled differently

    try:
        vault_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600
    except OSError:
        pass  # Best effort on permission change


def ensure_config_permissions(config_dir: Path) -> None:
    """Set secure directory permissions on Unix systems."""
    if sys.platform == "win32":
        return

    try:
        config_dir.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)  # 700
    except OSError:
        pass


def check_vault_permissions(vault_path: Path) -> bool:
    """Check if vault file has secure permissions. Returns True if OK."""
    if sys.platform == "win32":
        return True  # Cannot easily check ACLs

    if not vault_path.exists():
        return True  # Nothing to check

    try:
        mode = vault_path.stat().st_mode
        # Check that group and others have no access
        return not (mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH))
    except OSError:
        return False


def check_config_permissions(config_dir: Path) -> bool:
    """Check if config directory has secure permissions."""
    if sys.platform == "win32":
        return True

    if not config_dir.exists():
        return True

    try:
        mode = config_dir.stat().st_mode
        return not (mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH | stat.S_IXGRP | stat.S_IXOTH))
    except OSError:
        return False


def get_master_password(prompt: str = "Master password: ") -> str:
    """Read a master password from the terminal with hidden input."""
    try:
        password = getpass.getpass(prompt)
        if not password:
            raise SystemExit("Error: Master password cannot be empty.")
        return password
    except (EOFError, KeyboardInterrupt):
        print("\nOperation cancelled.", file=sys.stderr)
        raise SystemExit(1)


def get_master_password_with_confirm() -> tuple[str, str]:
    """Read and confirm a new master password."""
    pw1 = get_master_password("Create master password: ")
    pw2 = get_master_password("Confirm master password: ")
    if pw1 != pw2:
        raise SystemExit("Error: Passwords do not match.")
    return pw1, pw2
