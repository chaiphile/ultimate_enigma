"""Unlock dialog – master password entry.

Note: TOTP verification logic has been moved to components.totp_dialogs.
This file now primarily handles the master password entry for unlocking.
"""

import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import logging

from services.totp_service import TOTPService

logger = logging.getLogger(__name__)


def unlock_dialog(parent, title: str, totp_service: TOTPService,
                  verify_password_fn, verify_totp_fn) -> bool:
    """
    Show a dialog asking for master password and TOTP code.

    Parameters
    ----------
    parent : tk widget
        Parent widget for the dialog.
    title : str
        Dialog title.
    totp_service : TOTPService
        Used to display remaining time.
    verify_password_fn : callable(str) -> bool
        Called with the entered password; returns True if correct.
    verify_totp_fn : callable(str) -> bool
        Called with the entered TOTP code; returns True if valid.

    Returns
    -------
    bool
        True if both password and TOTP were verified successfully.
    """
    dlg = tk.Toplevel(parent, bg="#1a1a1a")
    dlg.title(title)
    dlg.geometry("400x380")
    dlg.resizable(False, False)
    dlg.transient(parent)
    dlg.attributes("-topmost", True)  # Ensure above lock screen
    dlg.grab_set()

    # Title
    tk.Label(
        dlg, text="🔓 UNLOCK", font=("Segoe UI", 18, "bold"),
        bg="#1a1a1a", fg="#ffffff"
    ).pack(pady=(20, 5))

    tk.Label(
        dlg, text="Enter your master password and current TOTP code",
        font=("Segoe UI", 9), bg="#1a1a1a", fg="#888888"
    ).pack(pady=(0, 15))

    # Master password
    tk.Label(
        dlg, text="Master Password:", font=("Segoe UI", 10),
        bg="#1a1a1a", fg="#cccccc"
    ).pack(anchor="w", padx=30)
    pwd_var = tk.StringVar()
    pwd_entry = ttk.Entry(dlg, textvariable=pwd_var, show="•", width=35,
                          bootstyle="primary")
    pwd_entry.pack(pady=(5, 10), padx=30)
    pwd_entry.focus_set()

    # TOTP code
    tk.Label(
        dlg, text="TOTP Code (6 digits):", font=("Segoe UI", 10),
        bg="#1a1a1a", fg="#cccccc"
    ).pack(anchor="w", padx=30)

    totp_var = tk.StringVar()
    totp_entry = ttk.Entry(dlg, textvariable=totp_var, width=35,
                           bootstyle="warning", font=("Consolas", 16))
    totp_entry.pack(pady=(5, 5), padx=30)

    # Timer display
    timer_var = tk.StringVar()
    timer_label = tk.Label(
        dlg, textvariable=timer_var, font=("Segoe UI", 9),
        bg="#1a1a1a", fg="#ffaa00"
    )
    timer_label.pack(pady=(0, 5))

    # Update timer
    def update_timer():
        if not dlg.winfo_exists():
            return
        try:
            remaining = totp_service.time_remaining()
            timer_var.set(f"⏱ Code expires in: {remaining}s")
            if remaining <= 5:
                timer_label.config(fg="#ff4444")
            else:
                timer_label.config(fg="#ffaa00")
            dlg.after(500, update_timer)
        except Exception:
            pass

    update_timer()

    result = {"success": False}

    def attempt_unlock():
        pw = pwd_var.get()
        totp_code = totp_var.get().strip()

        if not pw:
            messagebox.showerror("Error", "Password is required.", parent=dlg)
            return
        if len(totp_code) != 6 or not totp_code.isdigit():
            messagebox.showerror("Error", "Enter a valid 6-digit TOTP code.", parent=dlg)
            return

        if not verify_password_fn(pw):
            messagebox.showerror("Failed", "Incorrect master password.", parent=dlg)
            pwd_var.set("")
            return

        if not verify_totp_fn(totp_code):
            messagebox.showerror("Failed", "Invalid TOTP code. Try again.", parent=dlg)
            totp_var.set("")
            return

        result["success"] = True
        dlg.destroy()

    def cancel():
        dlg.destroy()

    # Buttons
    btn_frame = tk.Frame(dlg, bg="#1a1a1a")
    btn_frame.pack(pady=(15, 10))
    ttk.Button(btn_frame, text="🔓 Unlock", command=attempt_unlock,
               bootstyle="success").pack(side=tk.LEFT, padx=5)
    ttk.Button(btn_frame, text="Cancel", command=cancel,
               bootstyle="secondary-outline").pack(side=tk.LEFT, padx=5)

    dlg.bind("<Return>", lambda e: attempt_unlock())
    dlg.bind("<Escape>", lambda e: cancel())

    parent.wait_window(dlg)
    return result["success"]


# Note: totp_setup_dialog has been moved to components.totp_dialogs.TOTPSetupDialog
