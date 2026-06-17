"""ECDH Key Exchange dialog – uses ECDHService for all crypto operations."""

import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk

from services.ecdh_service import ECDHService      # pure crypto service
from views.utils import init_modal, flash_widget_text


def perform_ecdh(parent, purpose="friend"):
    """
    Opens an ECDH key exchange dialog.
    Returns a tuple (derived_shared_secret, friend_x25519_pubkey_b64) or None if cancelled.
    """
    # 1. Generate ephemeral key pair using the service
    priv = ECDHService.generate_private_key()
    pub_raw = ECDHService.private_to_public_bytes(priv)
    pub_b64 = ECDHService.encode_public_key(pub_raw)
    pub_fp = ECDHService.fingerprint(pub_raw)

    # UI setup (same as before, using ttkbootstrap)
    style = ttk.Style()
    dlg = tk.Toplevel(parent, bg=style.colors.bg)
    dlg.title(f"ECDH Key Exchange ({purpose})")
    dlg.geometry("500x550")
    dlg.resizable(True, True)

    # Step 1: Show our ephemeral public key
    ttk.Label(dlg, text="1. Your ephemeral X25519 public key (send to friend):",
              font=("Segoe UI", 10, "bold"),
              bootstyle="inverse-primary").pack(pady=(15,5), anchor=tk.W, padx=10)

    ttk.Label(dlg, text="Base64:",
              bootstyle="inverse-secondary").pack(anchor=tk.W, padx=20)

    pub_entry = ttk.Entry(dlg, width=55, bootstyle="primary")
    pub_entry.insert(0, pub_b64)
    pub_entry.config(state='readonly')
    pub_entry.pack(padx=20, pady=2)

    ttk.Label(dlg, text=f"X25519 Fingerprint: {pub_fp}",
              font=("Consolas", 9),
              bootstyle="warning").pack(anchor=tk.W, padx=20)

    copy_btn = ttk.Button(dlg, text="Copy Public Key",
                          bootstyle="secondary-outline")
    copy_btn.pack(pady=5)

    def copy_pubkey():
        try:
            parent.clipboard_clear()
            parent.clipboard_append(pub_b64)
            flash_widget_text(copy_btn, "✓ Copied!", "Copy Public Key", ms=1500)
        except Exception:
            messagebox.showerror("Copy Failed", "Could not access clipboard.", parent=dlg)

    copy_btn.config(command=copy_pubkey)

    ttk.Separator(dlg, orient='horizontal', bootstyle="secondary").pack(fill=tk.X, padx=10, pady=10)

    # Step 2: Friend's public key input & fingerprint preview
    ttk.Label(dlg, text="2. Paste your friend's X25519 public key (Base64):",
              font=("Segoe UI", 10, "bold"),
              bootstyle="inverse-primary").pack(pady=(5,5), anchor=tk.W, padx=10)

    friend_pub_var = tk.StringVar()
    friend_pub_entry = ttk.Entry(dlg, textvariable=friend_pub_var, width=55,
                                 bootstyle="primary")
    friend_pub_entry.pack(padx=20, pady=2)

    friend_fp_var = tk.StringVar(value="")
    ttk.Label(dlg, text="Friend's X25519 Fingerprint:",
              bootstyle="inverse-secondary").pack(anchor=tk.W, padx=20, pady=(10,0))
    ttk.Label(dlg, textvariable=friend_fp_var,
              font=("Consolas", 9),
              bootstyle="warning").pack(anchor=tk.W, padx=20)

    def compute_fingerprint(*args):
        b64 = friend_pub_var.get().strip()
        if not b64:
            friend_fp_var.set("")
            return
        try:
            raw = ECDHService.decode_public_key(b64)   # uses service
            fp = ECDHService.fingerprint(raw)
            friend_fp_var.set(fp)
        except ValueError:
            friend_fp_var.set("Invalid key. Expected a Base64-encoded 32-byte X25519 public key.")

    friend_pub_var.trace_add('write', compute_fingerprint)

    result = {"secret": None, "friend_b64": None}

    def confirm():
        friend_b64 = friend_pub_var.get().strip()
        if not friend_b64:
            messagebox.showerror("Error", "Please enter friend's public key.", parent=dlg)
            return

        try:
            friend_raw = ECDHService.decode_public_key(friend_b64)
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid public key: {e}", parent=dlg)
            return

        # Manual fingerprint verification (use service fingerprint)
        friend_fp = ECDHService.fingerprint(friend_raw)
        if not messagebox.askyesno("Verify Fingerprint",
                                   f"Friend's X25519 key fingerprint:\n{friend_fp}\n\n"
                                   "Have you verified this fingerprint with your friend through a secure channel?",
                                   parent=dlg):
            return

        # Compute shared secret and derive final key using the service
        shared_secret = ECDHService.compute_shared_secret(priv, friend_raw)
        derived_key = ECDHService.derive_key(shared_secret)

        result["secret"] = derived_key
        result["friend_b64"] = friend_b64
        dlg.destroy()

    ttk.Button(dlg, text="Verify & Compute Shared Secret", command=confirm,
               bootstyle="success").pack(pady=15)
    ttk.Button(dlg, text="Cancel", command=dlg.destroy,
               bootstyle="secondary-outline").pack()

    init_modal(dlg, parent, focus_widget=friend_pub_entry)

    parent.wait_window(dlg)
    if result["secret"] is None:
        return None
    return result["secret"], result["friend_b64"]