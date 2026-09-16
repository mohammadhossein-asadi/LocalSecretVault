"""Cryptographically secure password generator."""

from __future__ import annotations

import math
import secrets
import string


def calculate_entropy(length: int, charset_size: int) -> float:
    """Calculate password entropy in bits."""
    if charset_size <= 1 or length <= 0:
        return 0.0
    return length * math.log2(charset_size)


def generate_password(
    length: int = 20,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
    custom_chars: str | None = None,
) -> str:
    """Generate a cryptographically secure random password.

    Args:
        length: Desired password length (minimum 1).
        uppercase: Include uppercase letters.
        lowercase: Include lowercase letters.
        numbers: Include digits.
        symbols: Include symbols.
        exclude_ambiguous: Exclude ambiguous chars (0, O, l, 1, I, etc.).
        custom_chars: Use a custom character set (overrides all other options).

    Returns:
        The generated password string.
    """
    if length < 1:
        raise ValueError("Password length must be at least 1.")

    if custom_chars is not None:
        if not custom_chars:
            raise ValueError("Custom character set must not be empty.")
        charset = custom_chars
    else:
        chars = ""

        if uppercase:
            pool = string.ascii_uppercase
            if exclude_ambiguous:
                pool = pool.replace("O", "").replace("I", "")
            chars += pool

        if lowercase:
            pool = string.ascii_lowercase
            if exclude_ambiguous:
                pool = pool.replace("l", "").replace("o", "")
            chars += pool

        if numbers:
            pool = string.digits
            if exclude_ambiguous:
                pool = pool.replace("0", "").replace("1", "")
            chars += pool

        if symbols:
            chars += "!@#$%^&*()-_=+[]{}|;:,.<>?/"

        if not chars:
            raise ValueError(
                "At least one character class must be enabled: "
                "uppercase, lowercase, numbers, or symbols."
            )

        charset = chars

    # Generate password ensuring at least one char from each enabled class
    # (only when using default character classes, not custom)
    if custom_chars is not None:
        return "".join(secrets.choice(charset) for _ in range(length))

    # For default classes, guarantee representation
    required: list[str] = []
    if uppercase:
        pool = string.ascii_uppercase
        if exclude_ambiguous:
            pool = pool.replace("O", "").replace("I", "")
        required.append(secrets.choice(pool))
    if lowercase:
        pool = string.ascii_lowercase
        if exclude_ambiguous:
            pool = pool.replace("l", "").replace("o", "")
        required.append(secrets.choice(pool))
    if numbers:
        pool = string.digits
        if exclude_ambiguous:
            pool = pool.replace("0", "").replace("1", "")
        required.append(secrets.choice(pool))
    if symbols:
        pool = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
        required.append(secrets.choice(pool))

    # Fill remaining length
    remaining = length - len(required)
    if remaining < 0:
        # Length too short for all required classes — just generate freely
        return "".join(secrets.choice(charset) for _ in range(length))

    password_chars = required + [secrets.choice(charset) for _ in range(remaining)]

    # Shuffle to avoid predictable positions
    password_list = list(password_chars)
    # Fisher-Yates shuffle using secrets
    for i in range(len(password_list) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_list[i], password_list[j] = password_list[j], password_list[i]

    return "".join(password_list)


def password_info(password: str) -> dict[str, int | float]:
    """Return information about a password's composition."""
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    charset_size = 0
    if has_upper:
        charset_size += 26
    if has_lower:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 33  # approximate

    entropy = calculate_entropy(len(password), charset_size) if charset_size > 0 else 0.0

    return {
        "length": len(password),
        "uppercase": int(has_upper),
        "lowercase": int(has_lower),
        "digits": int(has_digit),
        "symbols": int(has_symbol),
        "charset_size": charset_size,
        "entropy_bits": round(entropy, 1),
    }
