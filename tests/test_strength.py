"""Tests for password strength estimation."""

from __future__ import annotations

from localsecretvault.services.strength import estimate_strength


class TestWeakPasswords:
    def test_common_password(self) -> None:
        result = estimate_strength("password")
        assert result["score"] == 0
        assert result["label"] == "Very Weak"
        assert any("common" in w.lower() for w in result["warnings"])

    def test_numeric_sequence(self) -> None:
        result = estimate_strength("1234567890")
        assert result["score"] <= 1

    def test_keyboard_pattern(self) -> None:
        result = estimate_strength("qwertyuiop")
        assert result["score"] <= 1

    def test_short_password(self) -> None:
        result = estimate_strength("ab1!")
        assert result["score"] <= 1

    def test_repeated_characters(self) -> None:
        result = estimate_strength("aaaaaaaaaa")
        assert result["score"] <= 2

    def test_empty_password(self) -> None:
        result = estimate_strength("")
        assert result["score"] == 0
        assert result["entropy_bits"] == 0.0


class TestStrongPasswords:
    def test_generated_random(self) -> None:
        result = estimate_strength("xK9#mP2$vL8qZt4w")
        assert result["score"] >= 3

    def test_long_passphrase_style(self) -> None:
        result = estimate_strength("correct-horse-battery-staple-99")
        assert result["score"] >= 3

    def test_all_character_classes(self) -> None:
        result = estimate_strength("Zq9#Vm2$Kp5!Wx8")
        assert result["score"] >= 3

    def test_common_password_with_suffix_detected(self) -> None:
        result = estimate_strength("password123!")
        assert any("common" in w.lower() for w in result["warnings"])


class TestReportStructure:
    def test_fields_present(self) -> None:
        result = estimate_strength("test1234")
        for key in ("score", "label", "entropy_bits", "crack_time", "feedback", "warnings"):
            assert key in result

    def test_score_bounds(self) -> None:
        for pw in ["a", "abc12345", "Str0ng!Passw0rd#2024"]:
            result = estimate_strength(pw)
            assert 0 <= result["score"] <= 4

    def test_entropy_positive_for_valid_password(self) -> None:
        result = estimate_strength("ValidPass123!")
        assert result["entropy_bits"] > 0

    def test_crack_time_present(self) -> None:
        result = estimate_strength("ValidPass123!")
        assert isinstance(result["crack_time"], str)
        assert len(result["crack_time"]) > 0

    def test_stronger_gets_higher_score(self) -> None:
        weak = estimate_strength("letmein")["score"]
        strong = estimate_strength("Tr0ub4dor&3xK9#mP2$vL8q")["score"]
        assert strong > weak
