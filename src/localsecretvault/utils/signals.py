"""Signal handling and safe cleanup."""

from __future__ import annotations

import signal
import sys
from collections.abc import Callable
from typing import Any

def setup_signal_handlers(cleanup_fn: Callable[[], Any] | None = None) -> None:
    """Set up signal handlers for graceful shutdown.

    Args:
        cleanup_fn: Optional function to call before exiting.
    """

    def handler(signum: int, frame: Any) -> None:
        if cleanup_fn:
            try:
                cleanup_fn()
            except Exception:
                pass
        print("\nOperation interrupted.", file=sys.stderr)
        sys.exit(130)

    signal.signal(signal.SIGINT, handler)

    # SIGTERM on Unix (not available on Windows)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handler)
