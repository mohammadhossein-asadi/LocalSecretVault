"""Tests for .env file import and export."""

from __future__ import annotations

from pathlib import Path

import pytest

from localsecretvault.services.env import (
    export_to_env_file,
    import_from_env_file,
    parse_env_file,
)


class TestEnvParsing:
    """Tests for .env file parsing."""

    def test_parse_simple_vars(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("KEY1=value1\nKEY2=value2\n")
        result = parse_env_file(env_file)
        assert result == {"KEY1": "value1", "KEY2": "value2"}

    def test_parse_with_comments(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(
            "# This is a comment\n"
            "KEY1=value1\n"
            "# Another comment\n"
            "KEY2=value2\n"
        )
        result = parse_env_file(env_file)
        assert result == {"KEY1": "value1", "KEY2": "value2"}

    def test_parse_empty_lines(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("\n\nKEY1=value1\n\n\nKEY2=value2\n\n")
        result = parse_env_file(env_file)
        assert result == {"KEY1": "value1", "KEY2": "value2"}

    def test_parse_double_quoted_values(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text('KEY1="hello world"\n')
        result = parse_env_file(env_file)
        assert result["KEY1"] == "hello world"

    def test_parse_single_quoted_values(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("KEY1='hello world'\n")
        result = parse_env_file(env_file)
        assert result["KEY1"] == "hello world"

    def test_parse_empty_value(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("KEY1=\n")
        result = parse_env_file(env_file)
        assert result["KEY1"] == ""

    def test_parse_whitespace_around_equals(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("KEY1 = value1\n")
        result = parse_env_file(env_file)
        assert result["KEY1"] == "value1"

    def test_parse_inline_comments(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("KEY1=value1 # inline comment\n")
        result = parse_env_file(env_file)
        assert result["KEY1"] == "value1"

    def test_parse_special_characters(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(
            'DB_URL="postgres://user:pass@localhost:5432/db"\n'
            'API_KEY="sk-1234567890abcdef"\n'
        )
        result = parse_env_file(env_file)
        assert result["DB_URL"] == "postgres://user:pass@localhost:5432/db"
        assert result["API_KEY"] == "sk-1234567890abcdef"

    def test_parse_unicode_values(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text('GREETING="こんにちは"\n', encoding="utf-8")
        result = parse_env_file(env_file)
        assert result["GREETING"] == "こんにちは"

    def test_parse_malformed_line_skipped(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(
            "GOOD=value\n"
            "bad line without equals\n"
            "ALSO_GOOD=value2\n"
        )
        result = parse_env_file(env_file)
        assert result == {"GOOD": "value", "ALSO_GOOD": "value2"}

    def test_parse_nonexistent_file(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            parse_env_file(tmp_path / "nonexistent.env")

    def test_parse_duplicate_keys(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("KEY=first\nKEY=second\n")
        result = parse_env_file(env_file)
        # Last value wins
        assert result["KEY"] == "second"


class TestEnvImport:
    """Tests for .env import into vault secrets."""

    def test_import_returns_records(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("DB_HOST=localhost\nDB_PORT=5432\n")
        records = import_from_env_file(env_file)
        assert len(records) == 2
        assert records[0]["name"] == "DB_HOST"
        assert records[0]["value"] == "localhost"

    def test_import_empty_file(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("")
        records = import_from_env_file(env_file)
        assert len(records) == 0


class TestEnvExport:
    """Tests for .env export from vault."""

    def test_export_creates_file(self, tmp_path: Path) -> None:
        env_file = tmp_path / "exported.env"
        export_to_env_file(env_file, {"KEY1": "val1", "KEY2": "val2"})
        assert env_file.exists()
        content = env_file.read_text()
        assert "KEY1=val1" in content
        assert "KEY2=val2" in content

    def test_export_quotes_special_chars(self, tmp_path: Path) -> None:
        env_file = tmp_path / "exported.env"
        export_to_env_file(env_file, {"SECRET_KEY": "my secret key"})
        content = env_file.read_text()
        assert 'SECRET_KEY="my secret key"' in content

    def test_export_no_overwrite_without_flag(self, tmp_path: Path) -> None:
        env_file = tmp_path / "exported.env"
        env_file.write_text("existing data\n")
        with pytest.raises(FileExistsError):
            export_to_env_file(env_file, {"KEY": "val"}, overwrite=False)

    def test_export_overwrite_with_flag(self, tmp_path: Path) -> None:
        env_file = tmp_path / "exported.env"
        env_file.write_text("old data\n")
        export_to_env_file(env_file, {"NEW_KEY": "new_val"}, overwrite=True)
        content = env_file.read_text()
        assert "NEW_KEY=new_val" in content
        assert "old data" not in content

    def test_export_has_warning_header(self, tmp_path: Path) -> None:
        env_file = tmp_path / "exported.env"
        export_to_env_file(env_file, {"KEY": "val"})
        content = env_file.read_text()
        assert "WARNING" in content or "secret" in content.lower()
