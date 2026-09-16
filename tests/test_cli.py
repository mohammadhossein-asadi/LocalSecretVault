"""Tests for the CLI using Typer's test runner."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from localsecretvault.cli.app import app

runner = CliRunner()


class TestCLIBasic:
    """Tests for basic CLI commands."""

    def test_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "LocalSecretVault" in result.output

    def test_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "password" in result.output.lower() or "secrets" in result.output.lower()

    def test_init_creates_vault(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        vault_path = tmp_path / "test_vault.lsv"

        # Patch get_vault_path everywhere and getpass
        import localsecretvault.cli.app as cli_mod
        import localsecretvault.config.settings as settings_mod
        import localsecretvault.storage.filestore as fs_mod
        import localsecretvault.vault.manager as vault_mod
        monkeypatch.setattr(cli_mod, "get_vault_path", lambda: vault_path)
        monkeypatch.setattr(settings_mod, "get_vault_path", lambda: vault_path)
        monkeypatch.setattr(vault_mod, "get_vault_path", lambda: vault_path)
        monkeypatch.setattr(fs_mod, "get_vault_path", lambda: vault_path)
        monkeypatch.setattr(cli_mod, "_manager", None)
        call_count = 0
        passwords = ["test_password", "test_password"]
        def mock_getpass(prompt: str = "") -> str:
            nonlocal call_count
            pw = passwords[call_count]
            call_count += 1
            return pw
        import getpass as getpass_mod
        monkeypatch.setattr(getpass_mod, "getpass", mock_getpass)

        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "initialized" in result.output.lower()

    def test_status_shows_locked(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        vault_path = tmp_path / "vault.lsv"
        import localsecretvault.cli.app as cli_mod
        monkeypatch.setattr(cli_mod, "get_vault_path", lambda: vault_path)
        monkeypatch.setattr(cli_mod, "_manager", None)
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "Vault" in result.output

    def test_list_without_unlock_shows_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        vault_path = tmp_path / "vault.lsv"
        import localsecretvault.cli.app as cli_mod
        monkeypatch.setattr(cli_mod, "_manager", None)
        # Create a mock manager that is always locked
        class MockManager:
            is_unlocked = False
            _auto_lock_minutes = 15
            def check_auto_lock(self): return False
            def list_secrets(self, **kw): return []
            def search(self, q): return []
            def get_all_tags(self): return []
        mock = MockManager()
        mock.vault_path = vault_path
        monkeypatch.setattr(cli_mod, "_get_manager", lambda: mock)

        result = runner.invoke(app, ["list"])
        assert result.exit_code != 0 or "locked" in result.output.lower()


class TestCLIGenerate:
    """Tests for the password generator CLI command."""

    def test_generate_default(self) -> None:
        result = runner.invoke(app, ["generate"])
        assert result.exit_code == 0
        lines = result.output.strip().split("\n")
        assert len(lines[0]) == 20  # default length

    def test_generate_custom_length(self) -> None:
        result = runner.invoke(app, ["generate", "--length", "32"])
        assert result.exit_code == 0
        lines = result.output.strip().split("\n")
        assert len(lines[0]) == 32

    def test_generate_multiple(self) -> None:
        result = runner.invoke(app, ["generate", "--count", "5"])
        assert result.exit_code == 0
        lines = [l for l in result.output.strip().split("\n") if l]
        assert len(lines) == 5

    def test_generate_no_symbols(self) -> None:
        result = runner.invoke(app, ["generate", "--no-symbols", "--length", "100"])
        assert result.exit_code == 0
        pw = result.output.strip().split("\n")[0]
        symbols = set("!@#$%^&*()-_=+[]{}|;:,.<>?/")
        assert not any(c in symbols for c in pw)

    def test_generate_bad_options(self) -> None:
        result = runner.invoke(app, ["generate", "--no-upper", "--no-lower", "--no-numbers", "--no-symbols"])
        assert result.exit_code != 0
