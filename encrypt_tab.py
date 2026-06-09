"""Encrypt & Send tab – decoupled via dependency injection."""

import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import threading
import datetime
import logging
from services.encryption_service import EncryptionService, EncryptionError
from services.friends_service import FriendsService
from services.clipboard_service import ClipboardService

logger = logging.getLogger(__name__)


class EncryptTab:
    def __init__(self, parent, encryption_service: EncryptionService,
                 friends_service: FriendsService, clipboard_service: ClipboardService):
        """
        Args:
            parent: Notebook widget
            encryption_service: Handles crypto operations
            friends_service: Provides friend data (no direct KeyStore access)
            clipboard_service: Handles clipboard operations
        """
        self.service = encryption_service
        self.friends_service = friends_service
        self.clipboard_service = clipboard_service
        
        # Store last sent message locally instead of on app instance
        self.last_sent_b64 = ""
        
        self.frame = ttk.Frame(parent)
        self._build_ui()

    def _build_ui(self):
        # Options bar
        opts = ttk.Frame(self.frame, padding=(10, 5))
        opts.pack(fill=tk.X, padx=10, pady=(10, 0))

        self.sign_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Sign with my private key",
                        variable=self.sign_var,
                        bootstyle="round-toggle").pack(side=tk.LEFT, padx=5)

        ttk.Label(opts, text="Encrypt for:").pack(side=tk.LEFT, padx=(20, 5))
        self.friend_combo = ttk.Combobox(opts, state="readonly", width=15,
                                         bootstyle="primary")
        self.friend_combo.pack(side=tk.LEFT, padx=5)
        self.friend_combo.bind('<<ComboboxSelected>>', self._on_friend_changed)
        self._update_friend_list()

        # Encryption mode
        ttk.Label(opts, text="Mode:").pack(side=tk.LEFT, padx=(10, 5))
        self.mode_combo = ttk.Combobox(
            opts, state="readonly", width=22,
            values=["Shared Secret (time‑based)", "Public Key (RSA)"],
            bootstyle="secondary"
        )
        self.mode_combo.pack(side=tk.LEFT, padx=5)
        self.mode_combo.current(0)

        # Self-destruct controls
        self.destruct_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="⏳ Self-destruct",
                        variable=self.destruct_var,
                        bootstyle="round-toggle").pack(side=tk.LEFT, padx=(20, 5))
        self.destruct_combo = ttk.Combobox(opts,
                                           values=["5 min", "10 min", "30 min",
                                                   "1 hour", "6 hours", "24 hours"],
                                           state="readonly", width=8,
                                           bootstyle="secondary")
        self.destruct_combo.pack(side=tk.LEFT, padx=5)
        self.destruct_combo.current(0)

        # Buttons
        ttk.Button(opts, text="Clear", command=self.clear_input,
                   bootstyle="secondary-outline").pack(side=tk.RIGHT, padx=5)
        ttk.Button(opts, text="Encrypt & Send", command=self.send_message,
                   bootstyle="success").pack(side=tk.RIGHT, padx=5)

        # Message input
        msg_frame = ttk.Labelframe(self.frame, text="Write your message",
                                   bootstyle="info")
        msg_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.msg_input = ttk.ScrolledText(
            msg_frame, height=8, wrap=tk.WORD
        )
        self.msg_input.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Sent messages log
        sent_frame = ttk.Labelframe(self.frame, text="Sent messages (Base64)",
                                    bootstyle="info")
        sent_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.sent_log = ttk.ScrolledText(
            sent_frame, height=6, wrap=tk.WORD, state='normal'
        )
        self.sent_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Bottom button bar
        btn_bar = ttk.Frame(self.frame)
        btn_bar.pack(fill=tk.X, padx=10, pady=(0, 5))
        ttk.Button(btn_bar, text="Copy Last Sent", command=self.copy_last_sent,
                   bootstyle="info-outline").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_bar, text="Clear Log",
                   command=lambda: self.sent_log.delete("1.0", tk.END),
                   bootstyle="secondary-outline").pack(side=tk.LEFT, padx=5)

    def _update_friend_list(self):
        """Fetch friend names from service instead of direct model access."""
        names = ["(none)"] + self.friends_service.get_friend_names()
        self.friend_combo['values'] = names
        self.friend_combo.current(0)

    def _on_friend_changed(self, event=None):
        choice = self.friend_combo.get()
        if not choice or choice == "(none)":
            self.mode_combo.config(state="disabled")
            self.mode_combo.set("Shared Secret (time‑based)")
            return

        # Use service to check secret existence
        has_secret = self.friends_service.friend_has_secret(choice)
        if has_secret:
            self.mode_combo.config(state="readonly")
            self.mode_combo.set("Shared Secret (time‑based)")
        else:
            self.mode_combo.config(state="disabled")
            self.mode_combo.set("Public Key (RSA)")

    def clear_input(self):
        self.msg_input.delete("1.0", tk.END)

    def send_message(self):
        plaintext = self.msg_input.get("1.0", tk.END).strip()
        if not plaintext:
            messagebox.showwarning("Empty", "Please type a message.")
            return

        friend_choice = self.friend_combo.get()
        friend_name = None if friend_choice in ("(none)", "") else friend_choice

        # Parse mode from combo selection
        mode_text = self.mode_combo.get()
        if "Shared" in mode_text:
            mode = "shared"
        else:
            mode = "rsa"

        sign = self.sign_var.get()

        # Self-destruct duration
        self_destruct_seconds = None
        if self.destruct_var.get():
            mapping = {
                "5 min": 300,
                "10 min": 600,
                "30 min": 1800,
                "1 hour": 3600,
                "6 hours": 21600,
                "24 hours": 86400,
            }
            self_destruct_seconds = mapping.get(self.destruct_combo.get(), None)

        # Offload to a thread so the UI stays responsive
        def task():
            try:
                b64 = self.service.encrypt_base64(
                    plaintext=plaintext,
                    friend_name=friend_name,
                    mode=mode,
                    sign=sign,
                    self_destruct_seconds=self_destruct_seconds,
                )
                self.last_sent_b64 = b64
                # Schedule UI update on main thread
                self.frame.after(0, lambda: self._log_sent(b64))
            except EncryptionError as exc:
                logger.exception("Encryption failed")
                self.frame.after(0, lambda: messagebox.showerror(
                    "Encryption Error", str(exc)))

        threading.Thread(target=task, daemon=True).start()

    def _log_sent(self, b64_text):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.sent_log.insert(tk.END, f"[{timestamp}]\n{b64_text}\n\n")
        self.sent_log.see(tk.END)
        self.msg_input.delete("1.0", tk.END)

    def copy_last_sent(self):
        if self.last_sent_b64:
            ok = self.clipboard_service.copy(self.last_sent_b64)
            if ok:
                messagebox.showinfo(
                    "Copied",
                    "Last sent message copied to clipboard.\n"
                    "Clipboard will be cleared automatically in 30 seconds."
                )
            else:
                messagebox.showerror("Clipboard Error", "Could not access clipboard.")
        else:
            messagebox.showwarning("Nothing", "No message sent yet.")

    # ---- External notification hook ----
    def notify_friend_list_changed(self):
        """Called by app when friend list changes externally."""
        self._update_friend_list()
