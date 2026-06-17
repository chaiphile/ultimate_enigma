"""Dialog functions for the app."""

import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk

from src.secure_string import SecureString


def password_dialog(parent, title, confirm=False, topmost=False, bg=None, fg=None,
                    enforce_strength=True, on_recover=None) -> SecureString | None:
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
        on_recover: Optional callback invoked when "Recover" button is clicked.
            The dialog closes and returns None. Caller should handle recovery.
        
    Returns:
        SecureString containing the password, or None if cancelled/failed.
    """
    from views.utils import validate_password_strength, get_strength_label, MIN_PASSWORD_LENGTH

    style = ttk.Style()
    dialog_bg = bg or style.colors.bg
    dialog_fg = fg or style.colors.fg
    
    dlg = tk.Toplevel(parent, bg=dialog_bg)
    dlg.title(title)
    # Dynamic sizing: base height + extra for confirm field + strength meter, capped at 600
    if confirm and enforce_strength:
        dlg_height = min(380, 600)
    elif confirm:
        dlg_height = min(310, 600)
    else:
        dlg_height = min(220, 600)
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

    confirm_entry = None
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
        # Tab order: password → confirm
        pwd_entry.bind("<Tab>", lambda e: (confirm_entry.focus_set(), "break"))

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

        # Validation
        if confirm:
            if pw != confirm_pw:
                messagebox.showerror("Mismatch", "Passwords do not match.", parent=dlg)
                pwd_var.set("")
                confirm_var.set("")
                pwd_entry.focus_set()
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
                    pwd_var.set("")
                    confirm_var.set("")
                    pwd_entry.focus_set()
                    return

        # Clear the Tkinter StringVars immediately to minimize memory exposure
        pwd_var.set("")
        if confirm:
            confirm_var.set("")

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

    if on_recover is not None:
        def do_recover():
            dlg.destroy()
            on_recover()
        ttk.Button(btn_frame, text="🔑 Recover", command=do_recover,
                   bootstyle="warning-outline").pack(side=tk.LEFT, padx=(15, 0))

    dlg.bind("<Return>", lambda e: ok())
    dlg.bind("<Escape>", lambda e: cancel())

    if confirm_entry:
        confirm_entry.bind("<Return>", lambda e: ok())

    parent.wait_window(dlg)
    return result[0] if result else None
