"""Clipboard service with automatic clearing for sensitive data."""

import threading
import logging
import time

logger = logging.getLogger(__name__)

DEFAULT_CLEAR_DELAY = 30  # seconds


class ClipboardService:
    """Manages clipboard operations and schedules automatic clearing.

    Follows the Model role in MVC: encapsulates clipboard state and
    auto-clear scheduling independently from any UI widget.
    """

    def __init__(self, root, clear_delay: int = DEFAULT_CLEAR_DELAY):
        self._root = root
        self._clear_delay = clear_delay
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()

    def copy(self, text: str, auto_clear: bool = True) -> bool:
        """Copy text to system clipboard and optionally schedule auto-clear.

        Args:
            text: The string to place on the clipboard.
            auto_clear: If True, schedule clipboard clearing after delay.

        Returns:
            True if the copy succeeded, False otherwise.
        """
        try:
            self._root.clipboard_clear()
            self._root.clipboard_append(text)
            if auto_clear:
                self._schedule_clear()
            return True
        except Exception as exc:
            logger.error("Clipboard copy failed: %s", exc)
            return False

    def get(self) -> str | None:
        """Read current clipboard content.

        Returns:
            Clipboard text or None if empty / inaccessible.
        """
        try:
            return self._root.clipboard_get()
        except Exception:
            return None

    def clear(self) -> None:
        """Immediately clear the system clipboard."""
        try:
            self._root.clipboard_clear()
            self._root.clipboard_append("")
        except Exception as exc:
            logger.debug("Clipboard clear failed (non-critical): %s", exc)

    def _schedule_clear(self) -> None:
        """Cancel any pending clear timer and start a new one."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self._clear_delay, self.clear)
            self._timer.daemon = True
            self._timer.start()

    def shutdown(self) -> None:
        """Cancel pending timers and clear clipboard on app exit."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        self.clear()
