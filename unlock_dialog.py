"""Unlock dialog – master password + TOTP verification.

Presented when the user attempts to unlock the app after an emergency lock.
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


def totp_setup_dialog(parent, totp_service: TOTPService, provisioning_uri: str,
                      on_regenerate=None) -> bool:
    """
    Show TOTP setup dialog with the provisioning URI (for QR code generation).

    Parameters
    ----------
    parent : tk widget
        Parent widget.
    totp_service : TOTPService
        The TOTP service instance.
    provisioning_uri : str
        The otpauth:// URI for authenticator apps.
    on_regenerate : callable, optional
        Callback to regenerate the TOTP secret.

    Returns
    -------
    bool
        True if user acknowledges the setup.
    """
    dlg = tk.Toplevel(parent, bg="#1a1a1a")
    dlg.title("TOTP Setup")
    dlg.geometry("580x720")
    dlg.resizable(False, False)
    dlg.transient(parent)
    dlg.attributes("-topmost", True)
    dlg.grab_set()

    # ── BUTTON FRAME - Pack FIRST at bottom so it's always visible ──
    btn_frame = tk.Frame(dlg, bg="#1a1a1a", height=60)
    btn_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=(0, 15))
    btn_frame.pack_propagate(False)  # Prevent shrinking

    result = {"ok": False}

    def ok_close():
        result["ok"] = True
        dlg.destroy()

    def regenerate():
        if on_regenerate:
            on_regenerate()
            new_uri = totp_service.provisioning_uri()
            new_b32 = totp_service.get_b32_secret()
            uri_text.config(state="normal")
            uri_text.delete("1.0", tk.END)
            uri_text.insert("1.0", new_uri)
            uri_text.config(state="disabled")
            secret_text.config(state="normal")
            secret_text.delete("1.0", tk.END)
            secret_text.insert("1.0", new_b32)
            secret_text.config(state="disabled")
            code_var.set(totp_service.generate())
            messagebox.showinfo("Regenerated", "New TOTP secret generated.\n"
                                "Please re-scan with your authenticator app.", parent=dlg)

    # OK button - large and prominent
    ok_btn = tk.Button(
        btn_frame, text="✅  OK – I have saved the secret",
        font=("Segoe UI", 11, "bold"), bg="#28a745", fg="white",
        activebackground="#34d058", activeforeground="white",
        bd=0, padx=20, pady=10, cursor="hand2", command=ok_close
    )
    ok_btn.pack(side=tk.RIGHT, padx=5)

    # Cancel button
    cancel_btn = tk.Button(
        btn_frame, text="Cancel", font=("Segoe UI", 10),
        bg="#6c757d", fg="white", activebackground="#5a6268",
        activeforeground="white", bd=0, padx=15, pady=8,
        cursor="hand2", command=dlg.destroy
    )
    cancel_btn.pack(side=tk.RIGHT, padx=5)

    # Regenerate button
    if on_regenerate:
        regen_btn = tk.Button(
            btn_frame, text="🔄 Regenerate", font=("Segoe UI", 10),
            bg="#ffc107", fg="#212529", activebackground="#e0a800",
            activeforeground="#212529", bd=0, padx=12, pady=8,
            cursor="hand2", command=regenerate
        )
        regen_btn.pack(side=tk.LEFT, padx=5)

    # ── CONTENT - Pack AFTER buttons (fills remaining space above) ──
    content = tk.Frame(dlg, bg="#1a1a1a")
    content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(15, 5))

    # Title
    tk.Label(
        content, text="🔐 TOTP Setup", font=("Segoe UI", 16, "bold"),
        bg="#1a1a1a", fg="#ffffff"
    ).pack(pady=(5, 8))

    tk.Label(
        content, text="Scan with Google Authenticator / Authy / Microsoft Authenticator",
        font=("Segoe UI", 9), bg="#1a1a1a", fg="#888888",
        justify="center"
    ).pack(pady=(0, 10))

    # Provisioning URI
    tk.Label(
        content, text="Provisioning URI:", font=("Segoe UI", 9, "bold"),
        bg="#1a1a1a", fg="#ffaa00"
    ).pack(anchor="w")

    uri_text = tk.Text(content, height=3, width=68, bg="#2a2a2a", fg="#00ff88",
                       font=("Consolas", 9), wrap="char", relief="flat")
    uri_text.pack(pady=5, fill=tk.X)
    uri_text.insert("1.0", provisioning_uri)
    uri_text.config(state="disabled")

    def copy_uri():
        try:
            parent.clipboard_clear()
            parent.clipboard_append(provisioning_uri)
            messagebox.showinfo("Copied", "URI copied to clipboard.", parent=dlg)
        except Exception:
            pass

    ttk.Button(content, text="📋 Copy URI", command=copy_uri,
               bootstyle="info-outline").pack(pady=(0, 8))

    # Base32 secret
    b32 = totp_service.get_b32_secret()

    tk.Label(
        content, text="Secret (Base32) – Manual Entry:", font=("Segoe UI", 9, "bold"),
        bg="#1a1a1a", fg="#ffaa00"
    ).pack(anchor="w")

    secret_text = tk.Text(content, height=1, width=68, bg="#2a2a2a", fg="#00ff88",
                          font=("Consolas", 12), relief="flat")
    secret_text.pack(pady=5, fill=tk.X)
    secret_text.insert("1.0", b32)
    secret_text.config(state="disabled")

    def copy_secret():
        try:
            parent.clipboard_clear()
            parent.clipboard_append(b32)
            messagebox.showinfo("Copied", "Secret copied to clipboard.", parent=dlg)
        except Exception:
            pass

    ttk.Button(content, text="📋 Copy Secret", command=copy_secret,
               bootstyle="info-outline").pack(pady=(0, 10))

    # Live code preview
    tk.Label(
        content, text="Current Code (for verification):",
        font=("Segoe UI", 10), bg="#1a1a1a", fg="#cccccc"
    ).pack()

    code_var = tk.StringVar(value=totp_service.generate())
    code_label = tk.Label(
        content, textvariable=code_var, font=("Consolas", 28, "bold"),
        bg="#1a1a1a", fg="#00ff88"
    )
    code_label.pack(pady=5)

    timer_var = tk.StringVar()
    timer_label = tk.Label(
        content, textvariable=timer_var,
        font=("Segoe UI", 9), bg="#1a1a1a", fg="#888888"
    )
    timer_label.pack()

    def update_code_display():
        if not dlg.winfo_exists():
            return
        try:
            code_var.set(totp_service.generate())
            remaining = totp_service.time_remaining()
            timer_var.set(f"(expires in {remaining}s)")
            if remaining <= 5:
                code_label.config(fg="#ff4444")
                timer_label.config(fg="#ff4444")
            else:
                code_label.config(fg="#00ff88")
                timer_label.config(fg="#888888")
            dlg.after(500, update_code_display)
        except Exception:
            pass

    update_code_display()

    dlg.bind("<Escape>", lambda e: dlg.destroy())
    dlg.bind("<Return>", lambda e: ok_close())

    parent.wait_window(dlg)
    return result["ok"]
