"""Shared test fixtures for LocalSecretVault."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest

from localsecretvault.vault.manager import VaultManager

@pytest.fixture
def tmp_vault_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for vault operations."""
    return tmp_path

@pytest.fixture
def vault_manager(tmp_path: Path) -> Generator[VaultManager, None, None]:
    """Create a VaultManager with a temporary vault path."""
    vault_path = tmp_path / "test_vault.lsv"
    manager = VaultManager(vault_path)
    yield manager

@pytest.fixture
def initialized_vault(tmp_path: Path) -> Generator[VaultManager, None, None]:
    """Create and initialize a vault with a known password."""
    vault_path = tmp_path / "test_vault.lsv"
    manager = VaultManager(vault_path)
    manager.init_vault("test_password_123")
    yield manager

@pytest.fixture
def test_password() -> str:
    """A consistent test password."""
    return "test_password_123"

@pytest.fixture
def sample_secret_data() -> dict:
    """Sample secret data for testing."""
    return {
        "id": "test-id-001",
        "type": "Login",
        "name": "GitHub",
        "username": "testuser",
        "password": "super_secret_pw",
        "url": "https://github.com",
        "notes": "My GitHub account",
        "tags": ["development", "coding"],
        "custom_fields": {},
        "created_at": "2024-01-01T00:00:00+00:00",
        "updated_at": "2024-01-01T00:00:00+00:00",
    }
