"""Lock screen overlay – covers the entire application window when locked.

Displays a dark overlay with lock icon, status text, and an unlock button.
The unlock button triggers a callback (typically showing password + TOTP dialog).
"""

import sys
import tkinter as tk
import ttkbootstrap as ttk
import logging
from views.utils import ToolTip

logger = logging.getLogger(__name__)


class LockScreen:
    """Full-window overlay that blocks interaction with the underlying app."""

    def __init__(self, root: tk.Tk, on_unlock_request, on_recovery_request=None):
        """
        Parameters
        ----------
        root : tk.Tk
            The main application root window.
        on_unlock_request : callable
            Callback invoked when the user clicks "Unlock" or presses the unlock hotkey.
        on_recovery_request : callable, optional
            Callback invoked when the user clicks "Recover with Recovery Key".
        """
        self.root = root
        self._on_unlock_request = on_unlock_request
        self._on_recovery_request = on_recovery_request
        self._overlay: tk.Frame | None = None
        self._status_var = tk.StringVar(value="🔒 LOCKED")

    @property
    def is_locked(self) -> bool:
        return self._overlay is not None

    def lock(self) -> None:
        """Show the lock overlay, blocking all interaction with the app."""
        if self._overlay is not None:
            return  # already locked

        self._overlay = tk.Frame(self.root, bg="#0d0d0d")
        self._overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._overlay.lift()
        # Make the overlay genuinely modal so clicks/keys can't reach widgets
        # behind it. The grab is released right before the unlock callback runs
        # (which itself opens a grab_set password dialog) - see _handle_unlock_request.
        try:
            self._overlay.grab_set()
        except Exception:
            logger.debug("Lock overlay grab_set failed", exc_info=True)
        # Don't use focus_force() - it can interfere with modal dialogs

        # Center content
        center = tk.Frame(self._overlay, bg="#0d0d0d")
        center.place(relx=0.5, rely=0.5, anchor="center")

        # Lock icon (large unicode padlock)
        tk.Label(
            center, text="🔒", font=("Segoe UI Emoji", 72),
            bg="#0d0d0d", fg="#ff4444"
        ).pack(pady=(0, 10))

        # Title
        tk.Label(
            center, text="ULTIMATE ENIGMA", font=("Segoe UI", 20, "bold"),
            bg="#0d0d0d", fg="#ffffff"
        ).pack()

        # Status
        tk.Label(
            center, textvariable=self._status_var,
            font=("Segoe UI", 14), bg="#0d0d0d", fg="#ff6666"
        ).pack(pady=(5, 20))

        # Info
        # Show a platform-appropriate unlock-hotkey hint on every platform so
        # non-Windows users aren't left with a button and no explanation.
        modifier = "Cmd" if sys.platform == "darwin" else "Ctrl"
        hotkey_line = f"or use the hotkey {modifier}+Shift+U to unlock.\n"
        tk.Label(
            center, text="All keys have been wiped from memory.\n"
                         "Press the button below to unlock.\n"
                         + hotkey_line,
            font=("Segoe UI", 10), bg="#0d0d0d", fg="#888888",
            justify="center"
        ).pack(pady=(0, 25))

        # Unlock button
        unlock_btn = tk.Button(
            center, text="🔓  Unlock",
            font=("Segoe UI", 14, "bold"),
            bg="#228B22", fg="white", activebackground="#2ea82e",
            activeforeground="white", bd=0, padx=30, pady=10,
            cursor="hand2", command=self._handle_unlock_request
        )
        unlock_btn.pack()
        ToolTip(unlock_btn, "Unlock the app with your master password and TOTP code")

        # Recovery button (for forgotten master password)
        if self._on_recovery_request is not None:
            recovery_btn = tk.Button(
                center, text="🔑  Recover with Recovery Key",
                font=("Segoe UI", 10),
                bg="#555555", fg="#cccccc", activebackground="#666666",
                activeforeground="#ffffff", bd=0, padx=20, pady=6,
                cursor="hand2", command=self._handle_recovery_request
            )
            recovery_btn.pack(pady=(12, 0))
            ToolTip(recovery_btn, "Recover access using your recovery key")

            # Hover effects
            def on_enter(e):
                recovery_btn.config(bg="#666666", fg="#ffffff")
            def on_leave(e):
                recovery_btn.config(bg="#555555", fg="#cccccc")
            recovery_btn.bind("<Enter>", on_enter)
            recovery_btn.bind("<Leave>", on_leave)

        # Give focus to the unlock button so Enter works immediately
        unlock_btn.focus_set()

        # Also bind Enter on both the overlay and the button for redundancy
        self._overlay.bind("<Return>", lambda e: self._handle_unlock_request())
        self._overlay.bind("<KP_Enter>", lambda e: self._handle_unlock_request())
        unlock_btn.bind("<Return>", lambda e: self._handle_unlock_request())
        unlock_btn.bind("<KP_Enter>", lambda e: self._handle_unlock_request())
        unlock_btn.bind("<space>", lambda e: self._handle_unlock_request())

        # Prevent tab focus escape
        self._overlay.bind("<Tab>", lambda e: "break")

        # Escape must never silently dismiss the lock.
        self._overlay.bind("<Escape>", lambda e: "break")

        logger.info("Lock screen activated")

    def _handle_unlock_request(self) -> None:
        """Publish unlock event and invoke the registered callback.

        The overlay grab is released first so the downstream password/TOTP dialog
        (which calls grab_set itself) isn't blocked by a conflicting grab. If the
        unlock fails, the overlay frame is still present and on top; it is fully
        re-grabbed on the next lock(). For an active-but-failed unlock we re-grab
        below so the screen stays modal.
        """
        self._release_grab()
        self._on_unlock_request()
        # If unlock didn't tear the overlay down (failed/cancelled), restore the grab.
        if self._overlay is not None:
            try:
                self._overlay.grab_set()
            except Exception:
                logger.debug("Lock overlay re-grab failed", exc_info=True)

    def _release_grab(self) -> None:
        if self._overlay is not None:
            try:
                self._overlay.grab_release()
            except Exception:
                logger.debug("Lock overlay grab_release failed", exc_info=True)

    def _handle_recovery_request(self) -> None:
        """Invoke the recovery callback if registered."""
        if self._on_recovery_request is not None:
            self._release_grab()
            self._on_recovery_request()
            if self._overlay is not None:
                try:
                    self._overlay.grab_set()
                except Exception:
                    logger.debug("Lock overlay re-grab failed", exc_info=True)

    def unlock(self) -> None:
        """Remove the lock overlay."""
        if self._overlay is not None:
            self._release_grab()
            self._overlay.destroy()
            self._overlay = None
            self.root.focus_force()
            logger.info("Lock screen deactivated")

    def set_status(self, text: str) -> None:
        """Update the status text on the lock screen."""
        self._status_var.set(text)
