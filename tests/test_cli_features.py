"""Tests for the new CLI commands: totp, copy, passphrase, strength, health."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from localsecretvault.cli.app import app
from localsecretvault.services.totp import totp_now

runner = CliRunner()

# Fixed TOTP secret for CLI tests (valid base32)
CLI_TOTP_SECRET = "JBSWY3DPEHPK3PXP"


@pytest.fixture
def unlocked_vault_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Set up a CLI environment with an unlocked in-memory vault."""
    vault_path = tmp_path / "cli_vault.lsv"

    import localsecretvault.cli.app as cli_mod
    from localsecretvault.models.secret import Secret
    from localsecretvault.vault.manager import VaultManager

    manager = VaultManager(vault_path)
    manager.init_vault("test_password_123")
    manager.add_secret(
        Secret(
            type="Login",
            name="GitHub",
            username="user",
            password="Str0ng!Passw0rd#2024",
            totp_secret=CLI_TOTP_SECRET,
        )
    )
    manager.add_secret(Secret(type="Login", name="Weak", password="123456"))
    manager.add_secret(Secret(type="Login", name="Reuse", password="Str0ng!Passw0rd#2024"))

    monkeypatch.setattr(cli_mod, "_get_manager", lambda: manager)
    return manager


class TestTOTPCommand:
    def test_totp_shows_code(self, unlocked_vault_cli) -> None:
        result = runner.invoke(app, ["totp", "GitHub"])
        assert result.exit_code == 0
        expected = totp_now(CLI_TOTP_SECRET)
        assert expected in result.output
        assert "remaining" in result.output

    def test_totp_no_totp_secret(self, unlocked_vault_cli) -> None:
        unlocked_vault_cli.add_secret(
            __import__("localsecretvault.models.secret", fromlist=["Secret"]).Secret(
                type="Login", name="NoTOTP"
            )
        )
        result = runner.invoke(app, ["totp", "NoTOTP"])
        assert result.exit_code == 1

    def test_totp_unknown_secret(self, unlocked_vault_cli) -> None:
        result = runner.invoke(app, ["totp", "nonexistent"])
        assert result.exit_code == 1


class TestCopyCommand:
    def test_copy_password(self, unlocked_vault_cli, monkeypatch: pytest.MonkeyPatch) -> None:
        copied: list[str] = []

        import localsecretvault.cli.app as cli_mod

        monkeypatch.setattr(cli_mod, "clipboard_available", lambda: True)
        monkeypatch.setattr(cli_mod, "copy_to_clipboard", lambda text, **kw: copied.append(text) or True)

        result = runner.invoke(app, ["copy", "GitHub"])
        assert result.exit_code == 0
        assert copied == ["Str0ng!Passw0rd#2024"]

    def test_copy_totp(self, unlocked_vault_cli, monkeypatch: pytest.MonkeyPatch) -> None:
        copied: list[str] = []

        import localsecretvault.cli.app as cli_mod

        monkeypatch.setattr(cli_mod, "clipboard_available", lambda: True)
        monkeypatch.setattr(cli_mod, "copy_to_clipboard", lambda text, **kw: copied.append(text) or True)

        result = runner.invoke(app, ["copy", "GitHub", "--field", "totp"])
        assert result.exit_code == 0
        assert copied == [totp_now(CLI_TOTP_SECRET)]

    def test_copy_custom_field(self, unlocked_vault_cli, monkeypatch: pytest.MonkeyPatch) -> None:
        copied: list[str] = []

        import localsecretvault.cli.app as cli_mod

        monkeypatch.setattr(cli_mod, "clipboard_available", lambda: True)
        monkeypatch.setattr(cli_mod, "copy_to_clipboard", lambda text, **kw: copied.append(text) or True)

        unlocked_vault_cli.edit_secret("GitHub", custom_fields={"api_key": "sk-123"})
        result = runner.invoke(app, ["copy", "GitHub", "--field", "api_key"])
        assert result.exit_code == 0
        assert copied == ["sk-123"]

    def test_copy_empty_field_fails(self, unlocked_vault_cli) -> None:
        result = runner.invoke(app, ["copy", "GitHub", "--field", "url"])
        assert result.exit_code == 1


class TestPassphraseCommand:
    def test_passphrase_default(self) -> None:
        result = runner.invoke(app, ["passphrase"])
        assert result.exit_code == 0
        assert "-" in result.output

    def test_passphrase_count(self) -> None:
        result = runner.invoke(app, ["passphrase", "--count", "3"])
        lines = [l for l in result.output.strip().split("\n") if l and "─" not in l]
        assert len(lines) == 3

    def test_passphrase_capitalize(self) -> None:
        result = runner.invoke(app, ["passphrase", "--capitalize", "--no-number"])
        phrase = result.output.strip()
        for word in phrase.split("-"):
            assert word[0].isupper()


class TestStrengthCommand:
    def test_strength_weak(self) -> None:
        result = runner.invoke(app, ["strength", "123456"])
        assert result.exit_code == 0
        assert "Very Weak" in result.output

    def test_strength_strong(self) -> None:
        result = runner.invoke(app, ["strength", "Tr0ub4dor&3xK9#mP2"])
        assert result.exit_code == 0
        assert "Strong" in result.output or "entropy" in result.output.lower()

    def test_strength_shows_entropy(self) -> None:
        result = runner.invoke(app, ["strength", "test1234"])
        assert "bits" in result.output


class TestHealthCommand:
    def test_health_reports_issues(self, unlocked_vault_cli) -> None:
        result = runner.invoke(app, ["health"])
        assert result.exit_code == 0
        assert "Weak" in result.output or "weak" in result.output.lower()
        assert "Reused" in result.output or "reused" in result.output.lower()

    def test_health_clean_vault(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import localsecretvault.cli.app as cli_mod
        from localsecretvault.models.secret import Secret
        from localsecretvault.vault.manager import VaultManager

        manager = VaultManager(tmp_path / "clean.lsv")
        manager.init_vault("test_password_123")
        manager.add_secret(Secret(type="Login", name="Only", password="xK9#mP2$vL8qZt4w"))
        monkeypatch.setattr(cli_mod, "_get_manager", lambda: manager)

        result = runner.invoke(app, ["health"])
        assert result.exit_code == 0
        assert "No weak" in result.output
        assert "No reused" in result.output

    def test_health_locked_vault_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import localsecretvault.cli.app as cli_mod
        from localsecretvault.vault.manager import VaultManager

        manager = VaultManager(tmp_path / "locked.lsv")
        manager.init_vault("test_password_123")
        manager.lock()
        monkeypatch.setattr(cli_mod, "_get_manager", lambda: manager)

        result = runner.invoke(app, ["health"])
        assert result.exit_code == 1
