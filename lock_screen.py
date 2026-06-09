"""Lock screen overlay – covers the entire application window when locked.

Displays a dark overlay with lock icon, status text, and an unlock button.
The unlock button triggers a callback (typically showing password + TOTP dialog).
"""

import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import logging

logger = logging.getLogger(__name__)


class LockScreen:
    """Full-window overlay that blocks interaction with the underlying app."""

    def __init__(self, root: tk.Tk, on_unlock_request):
        """
        Parameters
        ----------
        root : tk.Tk
            The main application root window.
        on_unlock_request : callable
            Callback invoked when the user clicks "Unlock" or presses the unlock hotkey.
        """
        self.root = root
        self._on_unlock_request = on_unlock_request
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
        tk.Label(
            center, text="All keys have been wiped from memory.\n"
                         "Press the button below or use the hotkey\n"
                         "Ctrl+Shift+U to unlock.",
            font=("Segoe UI", 10), bg="#0d0d0d", fg="#888888",
            justify="center"
        ).pack(pady=(0, 25))

        # Unlock button
        unlock_btn = tk.Button(
            center, text="🔓  Unlock",
            font=("Segoe UI", 14, "bold"),
            bg="#228B22", fg="white", activebackground="#2ea82e",
            activeforeground="white", bd=0, padx=30, pady=10,
            cursor="hand2", command=self._on_unlock_request
        )
        unlock_btn.pack()

        # Also bind Enter and the hotkey
        self._overlay.bind("<Return>", lambda e: self._on_unlock_request())
        self._overlay.bind("<KP_Enter>", lambda e: self._on_unlock_request())

        # Prevent tab focus escape
        self._overlay.bind("<Tab>", lambda e: "break")

        logger.info("Lock screen activated")

    def unlock(self) -> None:
        """Remove the lock overlay."""
        if self._overlay is not None:
            self._overlay.destroy()
            self._overlay = None
            self.root.focus_force()
            logger.info("Lock screen deactivated")

    def set_status(self, text: str) -> None:
        """Update the status text on the lock screen."""
        self._status_var.set(text)
