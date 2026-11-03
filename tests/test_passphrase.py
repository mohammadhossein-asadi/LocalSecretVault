"""Tests for the passphrase generator."""

from __future__ import annotations

import pytest

from localsecretvault.services.passphrase import (
    BITS_PER_WORD,
    WORD_COUNT,
    WORDS,
    generate_passphrase,
    passphrase_info,
)


class TestWordlist:
    def test_wordlist_size(self) -> None:
        assert WORD_COUNT == 1296

    def test_no_duplicates(self) -> None:
        assert len(set(WORDS)) == WORD_COUNT

    def test_words_are_lowercase_alphanumeric(self) -> None:
        for word in WORDS:
            assert word.islower() or word.isdigit(), f"Bad word: {word}"


class TestGeneratePassphrase:
    def test_default_length(self) -> None:
        phrase = generate_passphrase()
        parts = phrase.split("-")
        assert len(parts) == 6  # 5 words + appended number

    def test_word_count(self) -> None:
        phrase = generate_passphrase(num_words=7, append_number=False)
        assert len(phrase.split("-")) == 7

    def test_custom_separator(self) -> None:
        phrase = generate_passphrase(num_words=4, separator=".", append_number=False)
        assert phrase.count(".") == 3
        assert "-" not in phrase

    def test_capitalize(self) -> None:
        phrase = generate_passphrase(num_words=4, capitalize=True, append_number=False)
        for word in phrase.split("-"):
            assert word[0].isupper()

    def test_no_number(self) -> None:
        phrase = generate_passphrase(num_words=4, append_number=False)
        assert not phrase.split("-")[-1].isdigit()

    def test_appended_number_is_two_digits(self) -> None:
        phrase = generate_passphrase(num_words=4)
        tail = phrase.split("-")[-1]
        assert tail.isdigit() and 10 <= int(tail) <= 99

    def test_min_words_enforced(self) -> None:
        with pytest.raises(ValueError):
            generate_passphrase(num_words=2)

    def test_max_words_enforced(self) -> None:
        with pytest.raises(ValueError):
            generate_passphrase(num_words=25)

    def test_uniqueness(self) -> None:
        phrases = {generate_passphrase(append_number=False) for _ in range(50)}
        assert len(phrases) == 50


class TestPassphraseInfo:
    def test_info_word_count(self) -> None:
        info = passphrase_info("alpha-beta-gamma-delta-42")
        assert info["word_count"] == 4

    def test_info_entropy(self) -> None:
        info = passphrase_info("alpha-beta-gamma-delta", separator="-")
        assert info["entropy_bits"] == pytest.approx(4 * BITS_PER_WORD)

    def test_info_includes_number_entropy(self) -> None:
        with_num = passphrase_info("alpha-beta-gamma-delta-42")
        without_num = passphrase_info("alpha-beta-gamma-delta")
        assert with_num["entropy_bits"] > without_num["entropy_bits"]

    def test_info_wordlist_size(self) -> None:
        info = passphrase_info("alpha-beta")
        assert info["wordlist_size"] == 1296
