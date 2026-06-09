"""Global hotkey service for Windows using ctypes (no external dependencies).

Registers system-wide hotkeys:
    Ctrl+Shift+L  → Emergency Lock
    Ctrl+Shift+U  → Unlock (when locked)

Uses a dedicated daemon thread to listen for hotkey messages.
IMPORTANT: Hotkeys are registered from within the listener thread to ensure
WM_HOTKEY messages are delivered correctly.
"""

import ctypes
import ctypes.wintypes as wintypes
import threading
import logging
import time
from typing import Callable, Optional, List, Tuple

logger = logging.getLogger(__name__)

# Windows API constants
MOD_ALT     = 0x0001
MOD_CTRL    = 0x0002
MOD_SHIFT   = 0x0004
MOD_WIN     = 0x0008
MOD_NOREPEAT = 0x4000  # Prevent repeat-triggering on key hold
WM_HOTKEY   = 0x0312

user32 = ctypes.windll.user32


class HotkeyService:
    """Manages global hotkey registration on Windows.
    
    Hotkeys are registered from within the listener thread to ensure
    WM_HOTKEY messages are delivered to the correct message queue.
    """

    def __init__(self):
        self._hotkey_defs: List[Tuple[int, int, int, Callable]] = []  # (id, mod, vk, callback)
        self._callbacks: dict[int, Callable] = {}
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._registered_ids: list[int] = []
        self._stop_event = threading.Event()

    def register(self, hotkey_id: int, modifiers: int, vk: int,
                 callback: Callable) -> None:
        """
        Store a hotkey definition. The hotkey will be registered when start() is called.

        Parameters
        ----------
        hotkey_id : int
            Unique identifier for this hotkey (1–0xBFFF).
        modifiers : int
            Combination of MOD_ALT, MOD_CTRL, MOD_SHIFT, MOD_WIN.
        vk : int
            Virtual-key code (e.g., ord('L'), ord('U')).
        callback : callable
            Function to call when the hotkey is pressed.
        """
        # Add MOD_NOREPEAT to prevent repeated triggers on key hold
        self._hotkey_defs.append((hotkey_id, modifiers | MOD_NOREPEAT, vk, callback))
        self._callbacks[hotkey_id] = callback
        logger.info("Hotkey defined: id=%d, mod=%d, vk=%d", hotkey_id, modifiers, vk)

    def start(self) -> None:
        """Start the hotkey listener thread. Hotkeys are registered from within this thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()
        logger.info("Hotkey listener started")

    def stop(self) -> None:
        """Stop the listener and unregister hotkeys."""
        self._running = False
        self._stop_event.set()
        
        # Post a dummy message to wake up GetMessageW so the thread can exit
        if self._thread and self._thread.is_alive():
            # Post WM_NULL to the thread's message queue to wake it up
            thread_id = self._thread.ident
            if thread_id:
                user32.PostThreadMessageW(thread_id, 0, 0, 0)
            self._thread.join(timeout=3)
        
        self._hotkey_defs.clear()
        self._callbacks.clear()
        logger.info("Hotkey listener stopped")

    def _listen(self) -> None:
        """Message loop that listens for WM_HOTKEY messages.
        Hotkeys are registered from within this thread to ensure correct message delivery."""
        
        # Register all hotkeys from within this thread
        for hid, mod, vk, callback in self._hotkey_defs:
            result = user32.RegisterHotKey(None, hid, mod, vk)
            if result:
                self._registered_ids.append(hid)
                logger.info("Hotkey registered: id=%d, mod=%d, vk=%d", hid, mod, vk)
            else:
                logger.warning("Failed to register hotkey: id=%d (may already be in use)", hid)

        msg = wintypes.MSG()
        while self._running:
            # GetMessageW blocks until a message arrives
            # Use MsgWaitForMultipleObjects with timeout to allow periodic checking
            ret = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if ret == 0 or ret == -1:
                break
            if msg.message == WM_HOTKEY:
                hid = msg.wParam
                callback = self._callbacks.get(hid)
                if callback:
                    try:
                        callback()
                    except Exception:
                        logger.exception("Hotkey callback error (id=%d)", hid)

        # Unregister all hotkeys before exiting the thread
        for hid in self._registered_ids:
            user32.UnregisterHotKey(None, hid)
            logger.info("Hotkey unregistered: id=%d", hid)
        self._registered_ids.clear()


# Virtual-key codes for convenience
VK_L = 0x4C
VK_U = 0x55
