"""Tests for the password generator."""

from __future__ import annotations

import string

import pytest

from localsecretvault.services.generator import (
    calculate_entropy,
    generate_password,
    password_info,
)

class TestPasswordGenerator:
    """Tests for cryptographically secure password generation."""

    def test_default_length(self) -> None:
        pw = generate_password()
        assert len(pw) == 20

    def test_custom_length(self) -> None:
        for length in [1, 8, 16, 32, 64, 128]:
            pw = generate_password(length=length)
            assert len(pw) == length

    def test_minimum_length(self) -> None:
        pw = generate_password(length=1)
        assert len(pw) == 1

    def test_length_zero_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 1"):
            generate_password(length=0)

    def test_negative_length_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 1"):
            generate_password(length=-5)

    def test_contains_uppercase(self) -> None:
        # Generate many passwords and check that uppercase letters appear
        found_upper = False
        for _ in range(50):
            pw = generate_password(length=32, uppercase=True, lowercase=False, numbers=False, symbols=False)
            if any(c in string.ascii_uppercase for c in pw):
                found_upper = True
                break
        assert found_upper

    def test_contains_lowercase(self) -> None:
        found_lower = False
        for _ in range(50):
            pw = generate_password(length=32, uppercase=False, lowercase=True, numbers=False, symbols=False)
            if any(c in string.ascii_lowercase for c in pw):
                found_lower = True
                break
        assert found_lower

    def test_contains_numbers(self) -> None:
        found_digit = False
        for _ in range(50):
            pw = generate_password(length=32, uppercase=False, lowercase=False, numbers=True, symbols=False)
            if any(c in string.digits for c in pw):
                found_digit = True
                break
        assert found_digit

    def test_contains_symbols(self) -> None:
        symbols = set("!@#$%^&*()-_=+[]{}|;:,.<>?/")
        found_symbol = False
        for _ in range(100):
            pw = generate_password(length=32, uppercase=False, lowercase=False, numbers=False, symbols=True)
            if any(c in symbols for c in pw):
                found_symbol = True
                break
        assert found_symbol

    def test_no_uppercase(self) -> None:
        pw = generate_password(length=100, uppercase=False)
        assert not any(c in string.ascii_uppercase for c in pw)

    def test_no_lowercase(self) -> None:
        pw = generate_password(length=100, lowercase=False)
        assert not any(c in string.ascii_lowercase for c in pw)

    def test_no_numbers(self) -> None:
        pw = generate_password(length=100, numbers=False)
        assert not any(c in string.digits for c in pw)

    def test_no_symbols(self) -> None:
        pw = generate_password(length=100, symbols=False)
        symbols = set("!@#$%^&*()-_=+[]{}|;:,.<>?/")
        assert not any(c in symbols for c in pw)

    def test_no_classes_raises(self) -> None:
        with pytest.raises(ValueError, match="At least one character class"):
            generate_password(
                uppercase=False, lowercase=False, numbers=False, symbols=False
            )

    def test_exclude_ambiguous(self) -> None:
        ambiguous = set("0OoIl1")
        for _ in range(20):
            pw = generate_password(
                length=100,
                exclude_ambiguous=True,
                uppercase=True,
                lowercase=True,
                numbers=True,
            )
            # None of the generated chars should be ambiguous
            assert not any(c in ambiguous for c in pw)

    def test_custom_chars(self) -> None:
        pw = generate_password(length=50, custom_chars="abc")
        assert all(c in "abc" for c in pw)

    def test_custom_chars_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            generate_password(length=10, custom_chars="")

    def test_randomness(self) -> None:
        """Different calls should produce different passwords."""
        passwords = {generate_password(length=32) for _ in range(10)}
        assert len(passwords) == 10

class TestPasswordInfo:
    """Tests for password composition analysis."""

    def test_info_uppercase(self) -> None:
        info = password_info("ABCDEF")
        assert info["uppercase"] == 1
        assert info["lowercase"] == 0
        assert info["digits"] == 0
        assert info["symbols"] == 0

    def test_info_mixed(self) -> None:
        info = password_info("Abc123!")
        assert info["uppercase"] == 1
        assert info["lowercase"] == 1
        assert info["digits"] == 1
        assert info["symbols"] == 1
        assert info["length"] == 7
        assert info["charset_size"] == 95

    def test_entropy_calculation(self) -> None:
        # 20-char password with full charset → ~131 bits entropy
        pw = "aB3!" * 5  # 20 chars
        info = password_info(pw)
        assert info["entropy_bits"] > 100

class TestEntropyCalculation:
    """Tests for entropy calculation."""

    def test_entropy_positive(self) -> None:
        entropy = calculate_entropy(20, 95)
        assert entropy > 0

    def test_entropy_zero_length(self) -> None:
        assert calculate_entropy(0, 95) == 0.0

    def test_entropy_zero_charset(self) -> None:
        assert calculate_entropy(20, 0) == 0.0

    def test_entropy_single_charset(self) -> None:
        # 20 chars from 26 = ~94 bits
        entropy = calculate_entropy(20, 26)
        assert 93 < entropy < 95
