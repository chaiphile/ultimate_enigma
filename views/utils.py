"""Utility functions for the app."""

import re
import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

from src.secure_string import SecureString

# Minimum requirements (military-grade)
MIN_PASSWORD_LENGTH = 16
MIN_ENTROPY_BITS = 60


def validate_password_strength(pw: str) -> tuple:
    """
    Validate password against military-grade requirements.

    Returns:
        (is_valid: bool, message: str, score: int)
        score: 0-100 (0=trivially weak, 100=excellent)
    """
    issues = []
    score = 0

    # Length check (most important factor)
    if len(pw) < MIN_PASSWORD_LENGTH:
        issues.append(f"Minimum {MIN_PASSWORD_LENGTH} characters required (have {len(pw)})")
    else:
        score += min(40, len(pw) * 2)  # Up to 40 points for length

    # Complexity checks
    if not re.search(r'[A-Z]', pw):
        issues.append("Must contain at least one uppercase letter")
    else:
        score += 15

    if not re.search(r'[a-z]', pw):
        issues.append("Must contain at least one lowercase letter")
    else:
        score += 15

    if not re.search(r'\d', pw):
        issues.append("Must contain at least one digit")
    else:
        score += 15

    if not re.search(r'[!@#$%^&*()\-_=+\[\]{}\\|;:\'",.<>/?`~]', pw):
        issues.append("Must contain at least one special character")
    else:
        score += 15

    # Common password check (top 10,000)
    common_passwords = {
        "password", "123456", "qwerty", "admin", "letmein",
        "welcome", "monkey", "master", "dragon", "login",
        "princess", "football", "shadow", "sunshine", "trustno1"
    }
    if pw.lower() in common_passwords:
        issues.append("Password is too common")
        score = 0

    # Repetitive pattern check
    if re.search(r'(.)\1{3,}', pw):
        issues.append("Contains excessive repeated characters")
        score -= 10

    # Sequential pattern check
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', pw.lower()):
        issues.append("Contains sequential patterns")
        score -= 10

    is_valid = len(issues) == 0
    message = "Strong password" if is_valid else "; ".join(issues)
    return is_valid, message, max(0, min(100, score))


def get_strength_label(score: int) -> tuple:
    """Return (label_text, color) based on password strength score."""
    if score >= 80:
        return "████████████ STRONG", "#00cc00"
    elif score >= 60:
        return "████████░░░░ GOOD", "#66cc00"
    elif score >= 40:
        return "████░░░░░░░░ FAIR", "#cccc00"
    elif score >= 20:
        return "██░░░░░░░░░░ WEAK", "#cc6600"
    else:
        return "░░░░░░░░░░░░ CRITICAL", "#cc0000"

def password_dialog(parent, title, confirm=False, topmost=False, bg=None, fg=None,
                    enforce_strength=True) -> SecureString | None:
    """
    Show a modal password entry dialog.
    
    Returns a SecureString containing the password, or None if cancelled.
    The caller is responsible for calling wipe() on the returned SecureString
    when done with the password.
    
    Args:
        parent: Parent widget
        title: Dialog title
        confirm: If True, show confirmation field
        topmost: If True, keep dialog above all windows (for lock screen)
        bg: Override background color
        fg: Override foreground color
        enforce_strength: If True, enforce password strength requirements
        
    Returns:
        SecureString containing the password, or None if cancelled/failed.
    """
    style = ttk.Style()
    dialog_bg = bg or style.colors.bg
    dialog_fg = fg or style.colors.fg
    
    dlg = tk.Toplevel(parent, bg=dialog_bg)
    dlg.title(title)
    # Dynamic sizing: base height + extra for confirm field + strength meter
    if confirm and enforce_strength:
        dlg_height = 380
    elif confirm:
        dlg_height = 310
    else:
        dlg_height = 220
    dlg.geometry(f"400x{dlg_height}")
    dlg.resizable(False, False)
    dlg.transient(parent)
    if topmost:
        dlg.attributes("-topmost", True)
    dlg.grab_set()

    ttk.Label(dlg, text="Enter password:",
              font=("Segoe UI", 10),
              bootstyle="inverse-primary",
              background=dialog_bg,
              foreground=dialog_fg).pack(pady=(15, 5))

    pwd_var = tk.StringVar()
    pwd_entry = ttk.Entry(dlg, textvariable=pwd_var, show="*", width=30,
                          bootstyle="primary")
    pwd_entry.pack(pady=5)
    pwd_entry.focus_set()

    if confirm:
        ttk.Label(dlg, text="Confirm password:",
                  font=("Segoe UI", 10),
                  bootstyle="inverse-primary",
                  background=dialog_bg,
                  foreground=dialog_fg).pack(pady=(10, 5))
        confirm_var = tk.StringVar()
        confirm_entry = ttk.Entry(dlg, textvariable=confirm_var, show="*", width=30,
                                  bootstyle="primary")
        confirm_entry.pack(pady=5)

    # Add strength meter (only when enforce_strength=True and confirm=True)
    strength_var = tk.StringVar(value="")
    strength_label = ttk.Label(dlg, textvariable=strength_var,
                                font=("Consolas", 9, "bold"),
                                background=dialog_bg)
    if enforce_strength and confirm:
        strength_label.pack(pady=(0, 5))

    def update_strength(*args):
        if not enforce_strength or not confirm:
            return
        pw = pwd_var.get()
        if not pw:
            strength_var.set("")
            return
        _, _, score = validate_password_strength(pw)
        label_text, color = get_strength_label(score)
        strength_var.set(label_text)
        strength_label.config(foreground=color)

    pwd_var.trace_add('write', update_strength)

    result = []

    def ok():
        pw = pwd_var.get()
        # Capture confirm value BEFORE clearing
        confirm_pw = confirm_var.get() if confirm else ""
        
        # Clear the Tkinter StringVars immediately to minimize memory exposure
        pwd_var.set("")
        if confirm:
            confirm_var.set("")
        
        # Validation
        if confirm:
            if pw != confirm_pw:
                messagebox.showerror("Mismatch", "Passwords do not match.", parent=dlg)
                return
            if enforce_strength:
                is_valid, msg, score = validate_password_strength(pw)
                if not is_valid:
                    messagebox.showwarning(
                        "Weak Password",
                        f"{msg}\n\nMinimum requirements:\n"
                        f"• {MIN_PASSWORD_LENGTH}+ characters\n"
                        f"• Uppercase + lowercase + digit + special character",
                        parent=dlg
                    )
                    return
        
        # Create SecureString and clear local references
        result.append(SecureString(pw))
        pw = ""
        confirm_pw = ""
        dlg.destroy()

    def cancel():
        dlg.destroy()

    btn_frame = tk.Frame(dlg, bg=dialog_bg)
    btn_frame.pack(pady=20)
    ttk.Button(btn_frame, text="OK", command=ok,
               bootstyle="success").pack(side=tk.LEFT, padx=5)
    ttk.Button(btn_frame, text="Cancel", command=cancel,
               bootstyle="secondary-outline").pack(side=tk.LEFT, padx=5)

    dlg.bind("<Return>", lambda e: ok())
    dlg.bind("<Escape>", lambda e: cancel())

    parent.wait_window(dlg)
    return result[0] if result else None