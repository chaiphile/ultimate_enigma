"""Utility functions for the app."""

import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

def password_dialog(parent, title, confirm=False, topmost=False, bg=None, fg=None):
    """
    Show a modal password entry dialog.
    
    Args:
        parent: Parent widget
        title: Dialog title
        confirm: If True, show confirmation field
        topmost: If True, keep dialog above all windows (for lock screen)
        bg: Override background color
        fg: Override foreground color
    """
    style = ttk.Style()
    dialog_bg = bg or style.colors.bg
    dialog_fg = fg or style.colors.fg
    
    dlg = tk.Toplevel(parent, bg=dialog_bg)
    dlg.title(title)
    dlg.geometry("350x200")
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

    result = []

    def ok():
        pw = pwd_var.get()
        if confirm:
            if pw != confirm_var.get():
                messagebox.showerror("Mismatch", "Passwords do not match.", parent=dlg)
                return
            if len(pw) < 4:
                messagebox.showwarning("Weak", "Password too short.", parent=dlg)
                return
        result.append(pw)
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