"""Cross-platform clipboard operations with optional auto-clear."""

from __future__ import annotations

import threading

try:
    import pyperclip

    PYPERCLIP_AVAILABLE = True
except ImportError:
    PYPERCLIP_AVAILABLE = False

def is_available() -> bool:
    """Check if clipboard functionality is available."""
    return PYPERCLIP_AVAILABLE

def copy_to_clipboard(text: str, clear_after_seconds: int = 30) -> bool:
    """Copy text to clipboard. Optionally clear after a timeout.

    Returns True on success, False if clipboard is unavailable.
    """
    if not PYPERCLIP_AVAILABLE:
        return False

    try:
        pyperclip.copy(text)
    except Exception:
        return False

    if clear_after_seconds > 0:
        _schedule_clear(clear_after_seconds)

    return True

def _schedule_clear(seconds: int) -> None:
    """Schedule clipboard clearing after the given number of seconds."""
    timer = threading.Timer(seconds, _clear_clipboard)
    timer.daemon = True
    timer.start()

def _clear_clipboard() -> None:
    """Clear the clipboard contents."""
    if not PYPERCLIP_AVAILABLE:
        return
    try:
        # Best effort: clear clipboard
        pyperclip.copy("")
    except Exception:
        pass
