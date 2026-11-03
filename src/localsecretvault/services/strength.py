"""Password strength estimation and breach-style analysis.

Heuristic estimator in the spirit of zxcvbn: rewards length and character
variety, penalizes common patterns (sequences, repeats, keyboard walks,
dates, common passwords). No network access — the common-password list is
a compact embedded subset of the top entries from public breach corpora.
"""

from __future__ import annotations

import re
from typing import Any

# ── Embedded common-password list (compact top-entry subset) ──
COMMON_PASSWORDS = frozenset(
    {
        "123456", "password", "123456789", "12345678", "12345", "qwerty",
        "111111", "1234567", "dragon", "123123", "abc123", "football",
        "monkey", "letmein", "696969", "shadow", "master", "666666",
        "qwertyuiop", "123321", "mustang", "1234567890", "michael",
        "superman", "trustno1", "sunshine", "iloveyou", "batman",
        "admin123", "welcome", "admin", "login", "passw0rd", "p@ssw0rd",
        "password1", "password123", "qwerty123", "1q2w3e4r", "zaq12wsx",
        "test123", "guest", "root", "toor", "changeme", "secret",
        "freedom", "whatever", "qazwsx", "starwars", "hello", "charlie",
        "donald", "princess", "solo", "lovely", "passion", "flower",
        "summer", "winter", "spring", "autumn", "january", "december",
        "asdfgh", "zxcvbn", "qwe123", "asdf1234", "1qaz2wsx", "abcd1234",
        "letmein123", "welcome1", "google", "facebook", "youtube",
        "amazon", "netflix", "spotify", "github", "linkedin", "twitter",
    }
)

COMMON_WORDS = frozenset(
    {
        "love", "money", "home", "life", "work", "game", "king", "queen",
        "rock", "star", "moon", "fire", "water", "earth", "wind", "happy",
        "lucky", "angel", "magic", "music", "house", "school", "family",
        "friend", "coffee", "guitar", "soccer", "hockey", "gamer", "player",
    }
)

KEYBOARD_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
    "!@#$%^&*()_+",
]

SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "zyxwvutsrqponmlkjihgfedcba",
    "9876543210",
]

DATE_PATTERNS = [
    re.compile(r"^(19|20)\d{2}$"),
    re.compile(r"\b(19|20)\d{2}\b"),
    re.compile(r"^\d{1,2}[/-]\d{1,2}[/-]\d{2,4}$"),
]

STRENGTH_LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]


def _contains_common_password(password: str) -> bool:
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        return True
    # Also catch common passwords with simple mutations
    stripped = re.sub(r"[0-9!@#$%^&*()_+=-]+$", "", lowered)
    return stripped in COMMON_PASSWORDS and len(stripped) >= 4


def _longest_run(password: str, alphabet: str) -> int:
    """Longest consecutive run of characters from a lowercase alphabet."""
    lowered = password.lower()
    best = 0
    current = 0
    for ch in lowered:
        if ch in alphabet:
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def _has_keyboard_walk(password: str, min_length: int = 4) -> bool:
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - min_length + 1):
            fragment = row[i : i + min_length]
            if fragment in lowered or fragment[::-1] in lowered:
                return True
    return False


def _has_sequence(password: str, min_length: int = 4) -> bool:
    lowered = password.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - min_length + 1):
            fragment = seq[i : i + min_length]
            if fragment in lowered:
                return True
    return False


def _has_repeats(password: str, min_length: int = 3) -> bool:
    return bool(re.search(r"(.)\1{" + str(min_length - 1) + ",}", password))


def _has_date(password: str) -> bool:
    return any(p.search(password) for p in DATE_PATTERNS)


def _has_common_word(password: str) -> bool:
    lowered = password.lower()
    return any(word in lowered for word in COMMON_WORDS if len(word) >= 4)


def estimate_strength(password: str) -> dict[str, Any]:
    """Estimate password strength.

    Returns a dict with:
        score: 0-4 (0 = very weak, 4 = very strong)
        label: human-readable label
        entropy_bits: estimated entropy
        feedback: list of improvement suggestions
        warnings: list of detected weaknesses
    """
    if not password:
        return {
            "score": 0,
            "label": STRENGTH_LABELS[0],
            "entropy_bits": 0.0,
            "feedback": ["Enter a password."],
            "warnings": ["Empty password"],
        }

    warnings: list[str] = []
    feedback: list[str] = []
    penalty = 0.0

    length = len(password)

    # Character-class diversity
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    classes = sum([has_lower, has_upper, has_digit, has_symbol])

    charset = 0
    if has_lower:
        charset += 26
    if has_upper:
        charset += 26
    if has_digit:
        charset += 10
    if has_symbol:
        charset += 33

    entropy = length * (charset.bit_length() and __import__("math").log2(charset)) if charset > 1 else 0.0

    # Base score from length and variety
    score = 0
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if length >= 16:
        score += 1
    if classes >= 3:
        score += 1
    if classes == 4 and length >= 14:
        score += 1
    score = min(score, 4)

    # Pattern penalties
    if _contains_common_password(password):
        penalty += 3
        warnings.append("Commonly used password")
        feedback.append("Avoid common passwords entirely.")

    if _has_sequence(password):
        penalty += 1
        warnings.append("Contains a character sequence (e.g. 'abcd', '1234')")
        feedback.append("Avoid sequences of letters or numbers.")

    if _has_keyboard_walk(password):
        penalty += 1
        warnings.append("Contains a keyboard pattern (e.g. 'qwer')")
        feedback.append("Avoid keyboard patterns.")

    if _has_repeats(password):
        penalty += 1
        warnings.append("Contains repeated characters")
        feedback.append("Avoid repeating the same character.")

    if _has_date(password):
        penalty += 0.5
        warnings.append("Contains a date or year")
        feedback.append("Dates and years are easy to guess.")

    if _has_common_word(password):
        penalty += 0.5
        warnings.append("Contains a common word")
        feedback.append("Common dictionary words weaken passwords.")

    if length < 8:
        penalty += 1
        feedback.append("Use at least 12 characters (16+ recommended).")
    elif length < 12:
        feedback.append("Longer is stronger: aim for 12+ characters.")

    if not has_symbol:
        feedback.append("Add symbols for extra strength.")
    if not has_digit:
        feedback.append("Add digits for extra strength.")

    final_score = max(0, min(4, score - int(penalty)))

    # Crack-time estimate (very rough: 1e10 guesses/sec offline attack)
    guesses = 2**entropy if entropy > 0 else 1
    seconds = guesses / 1e10 / 2  # average case
    crack_time = _humanize_seconds(seconds)

    if final_score >= 3:
        feedback.insert(0, "Good password.")
    elif not feedback:
        feedback.append("Consider using a passphrase or generated password.")

    return {
        "score": final_score,
        "label": STRENGTH_LABELS[final_score],
        "entropy_bits": round(entropy, 1),
        "crack_time": crack_time,
        "feedback": feedback,
        "warnings": warnings,
    }


def _humanize_seconds(seconds: float) -> str:
    """Format a duration in seconds as a human-readable string."""
    if seconds < 1:
        return "instantly"
    units = [
        ("second", 60),
        ("minute", 60),
        ("hour", 24),
        ("day", 365),
        ("year", 1000),
    ]
    value = seconds
    name = "second"
    for unit_name, size in units:
        if value < size:
            name = unit_name
            break
        value /= size
        name = unit_name
    else:
        # Beyond years: use scientific notation
        if value >= 1e6:
            return f"{value:.2e} years"
        name = "year"

    if value >= 1000:
        return f"{value:,.0f} {name}s"
    if value >= 2 or name == "year":
        return f"{value:,.0f} {name}s"
    return f"{value:.0f} {name}"
