"""Tests for password health analysis in the vault manager."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from localsecretvault.models.secret import Secret
from localsecretvault.vault.manager import VaultManager


def _make_manager(tmp_path: Path) -> VaultManager:
    manager = VaultManager(tmp_path / "health_vault.lsv")
    manager.init_vault("test_password_123")
    return manager


class TestPasswordHealth:
    def test_weak_passwords_detected(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        manager.add_secret(Secret(type="Login", name="Weak", password="123456"))

        report = manager.analyze_password_health()
        assert report["weak_count"] == 1
        assert report["weak"][0]["name"] == "Weak"

    def test_strong_passwords_not_flagged(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        manager.add_secret(Secret(type="Login", name="Strong", password="xK9#mP2$vL8qZt4w"))

        report = manager.analyze_password_health()
        assert report["weak_count"] == 0

    def test_reused_passwords_detected(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        manager.add_secret(Secret(type="Login", name="A", password="SamePassword123!"))
        manager.add_secret(Secret(type="Login", name="B", password="SamePassword123!"))
        manager.add_secret(Secret(type="Login", name="C", password="Different456!"))

        report = manager.analyze_password_health()
        assert report["reused_count"] == 1
        assert set(report["reused"][0]["names"]) == {"A", "B"}

    def test_unique_passwords_not_flagged(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        manager.add_secret(Secret(type="Login", name="A", password="FirstUnique123!"))
        manager.add_secret(Secret(type="Login", name="B", password="SecondUnique456!"))

        report = manager.analyze_password_health()
        assert report["reused_count"] == 0

    def test_stale_passwords_detected(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        old_date = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
        manager.add_secret(Secret(type="Login", name="Old", password="SomePassword123!"))
        manager.edit_secret("Old", password_updated_at=old_date)

        report = manager.analyze_password_health(stale_days=365)
        assert report["stale_count"] == 1
        assert report["stale"][0]["name"] == "Old"

    def test_fresh_passwords_not_stale(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        manager.add_secret(Secret(type="Login", name="Fresh", password="SomePassword123!"))

        report = manager.analyze_password_health()
        assert report["stale_count"] == 0

    def test_secrets_without_passwords_ignored(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        manager.add_secret(Secret(type="Secure Note", name="NoteOnly", notes="no password"))

        report = manager.analyze_password_health()
        assert report["total_with_passwords"] == 0
        assert report["weak_count"] == 0

    def test_report_structure(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        manager.add_secret(Secret(type="Login", name="A", password="TestPassword1!"))

        report = manager.analyze_password_health()
        for key in (
            "total_with_passwords", "total_secrets", "weak", "reused",
            "stale", "weak_count", "reused_count", "stale_count",
        ):
            assert key in report

    def test_locked_vault_raises(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        manager.lock()

        with pytest_vault_locked():
            manager.analyze_password_health()


def pytest_vault_locked():
    """Helper context: returns pytest.raises for VaultLockedError."""
    import pytest

    from localsecretvault.vault.manager import VaultLockedError
    return pytest.raises(VaultLockedError)


class TestPasswordAgeTracking:
    def test_add_sets_password_updated_at(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        manager.add_secret(Secret(type="Login", name="A", password="pw123"))

        secret = manager.get_secret("A")
        assert secret.password_updated_at != ""

    def test_edit_password_updates_timestamp(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        manager.add_secret(Secret(type="Login", name="A", password="old_password"))

        original = manager.get_secret("A").password_updated_at
        manager.edit_secret("A", password="new_password_456")
        changed = manager.get_secret("A").password_updated_at

        assert changed != original
        assert changed > original

    def test_edit_other_fields_keeps_password_timestamp(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        manager.add_secret(Secret(type="Login", name="A", password="keep_password"))

        original = manager.get_secret("A").password_updated_at
        manager.edit_secret("A", username="new_user")
        unchanged = manager.get_secret("A").password_updated_at

        assert unchanged == original

    def test_totp_secret_roundtrip(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        manager.add_secret(Secret(type="Login", name="TOTPEntry", totp_secret="JBSWY3DPEHPK3PXP"))

        found = manager.get_secret("TOTPEntry")
        assert found.totp_secret == "JBSWY3DPEHPK3PXP"

    def test_totp_persists_across_lock_unlock(self, tmp_path: Path) -> None:
        manager = _make_manager(tmp_path)
        manager.add_secret(Secret(type="Login", name="TOTPEntry", totp_secret="JBSWY3DPEHPK3PXP"))
        manager.lock()

        manager2 = VaultManager(tmp_path / "health_vault.lsv")
        manager2.unlock("test_password_123")
        found = manager2.get_secret("TOTPEntry")
        assert found.totp_secret == "JBSWY3DPEHPK3PXP"

    def test_backward_compatibility_old_vaults(self, tmp_path: Path) -> None:
        """Secrets from older versions (without new fields) load with defaults."""
        manager = _make_manager(tmp_path)
        item = {
            "id": "legacy-1", "type": "Login", "name": "Legacy",
            "username": "", "password": "pw", "url": "", "notes": "",
            "tags": [], "custom_fields": {},
        }
        manager._data["secrets"].append(item)
        manager._save()
        manager.lock()

        manager2 = VaultManager(tmp_path / "health_vault.lsv")
        manager2.unlock("test_password_123")
        found = manager2.get_secret("Legacy")
        assert found.totp_secret == ""
        assert found.password_updated_at == ""
