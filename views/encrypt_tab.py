"""Encrypt & Send tab – decoupled via dependency injection.

Uses CryptoTaskQueue for non-blocking encryption with timeout enforcement.
"""

import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import datetime
import logging
from services.encryption_service import EncryptionService, EncryptionError
from services.friends_service import FriendsService
from services.clipboard_service import ClipboardService
from services.pqc_service import is_pqc_available
from src.exceptions import CryptoTimeoutError
from src.crypto_task_helper import submit_crypto_task

logger = logging.getLogger(__name__)

# Maximum message size (1 MB) to prevent memory issues
MAX_MESSAGE_SIZE = 1024 * 1024


class EncryptTab:
    def __init__(self, parent, encryption_service: EncryptionService,
                 friends_service: FriendsService, clipboard_service: ClipboardService,
                 crypto_queue=None):
        """
        Args:
            parent: Notebook widget
            encryption_service: Handles crypto operations
            friends_service: Provides friend data (no direct KeyStore access)
            clipboard_service: Handles clipboard operations
            crypto_queue: Optional CryptoTaskQueue for managed background execution.
                         If provided, replaces ad-hoc threading with pool-based
                         task submission and timeout enforcement.
        """
        self.service = encryption_service
        self.friends_service = friends_service
        self.clipboard_service = clipboard_service
        self.crypto_queue = crypto_queue
        
        # Store last sent message locally instead of on app instance
        self.last_sent_b64 = ""
        
        self.frame = ttk.Frame(parent)
        self._build_ui()

    def _build_ui(self):
        # Options bar – use grid to guarantee buttons stay visible
        opts = ttk.Frame(self.frame, padding=(10, 5))
        opts.pack(fill=tk.X, padx=10, pady=(10, 0))
        opts.columnconfigure(9, weight=1)  # spacer column expands

        # Row 0: main options + action buttons
        self.sign_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Sign with my private key",
                        variable=self.sign_var,
                        bootstyle="round-toggle").grid(row=0, column=0, padx=5, sticky=tk.W)

        ttk.Label(opts, text="Encrypt for:").grid(row=0, column=1, padx=(15, 5), sticky=tk.W)
        self.friend_combo = ttk.Combobox(opts, state="readonly", width=15,
                                         bootstyle="primary")
        self.friend_combo.grid(row=0, column=2, padx=5, sticky=tk.W)
        self.friend_combo.bind('<<ComboboxSelected>>', self._on_friend_changed)
        self._update_friend_list()

        # Encryption mode
        ttk.Label(opts, text="Mode:").grid(row=0, column=3, padx=(10, 5), sticky=tk.W)
        self._pqc_available = is_pqc_available()
        mode_values = ["Double Ratchet (XChaCha20)", "Shared Secret (time‑based)", "Public Key (RSA)"]
        if self._pqc_available:
            mode_values.append("Post-Quantum (Hybrid KEM)")
        self.mode_combo = ttk.Combobox(
            opts, state="readonly", width=22,
            values=mode_values,
            bootstyle="secondary"
        )
        self.mode_combo.grid(row=0, column=4, padx=5, sticky=tk.W)
        self.mode_combo.current(0)

        # Self-destruct controls
        self.destruct_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="⏳ Self-destruct",
                        variable=self.destruct_var,
                        bootstyle="round-toggle").grid(row=0, column=5, padx=(15, 5), sticky=tk.W)
        self.destruct_combo = ttk.Combobox(opts,
                                           values=["5 min", "10 min", "30 min",
                                                   "1 hour", "6 hours", "24 hours"],
                                           state="readonly", width=8,
                                           bootstyle="secondary")
        self.destruct_combo.grid(row=0, column=6, padx=5, sticky=tk.W)
        self.destruct_combo.current(0)

        # Spacer so buttons stay pinned right
        ttk.Frame(opts).grid(row=0, column=9, padx=5)

        # Buttons – always visible on the right
        ttk.Button(opts, text="Clear", command=self.clear_input,
                   bootstyle="secondary-outline").grid(row=0, column=11, padx=5, sticky=tk.E)
        ttk.Button(opts, text="Encrypt & Send", command=self.send_message,
                   bootstyle="success").grid(row=0, column=12, padx=5, sticky=tk.E)

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
            self.mode_combo.set("Double Ratchet (XChaCha20)")
            return

        # Use service to check capabilities — priority: Ratchet > PQC > Shared Secret > RSA
        has_ratchet = self.friends_service.has_active_ratchet(choice)
        has_secret = self.friends_service.friend_has_secret(choice)
        has_pqc = self.friends_service.friend_has_pqc_key(choice)

        if has_ratchet:
            # Double Ratchet active – use XChaCha20-Poly1305 forward-secret encryption
            self.mode_combo.config(state="readonly")
            self.mode_combo.set("Double Ratchet (XChaCha20)")
        elif has_pqc and self._pqc_available:
            # PQC key available – default to PQC mode
            self.mode_combo.config(state="readonly")
            self.mode_combo.set("Post-Quantum (Hybrid KEM)")
        elif has_secret:
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
        
        # Validate message size
        msg_size = len(plaintext.encode('utf-8'))
        if msg_size > MAX_MESSAGE_SIZE:
            messagebox.showwarning(
                "Message Too Large",
                f"Message size ({msg_size:,} bytes) exceeds maximum allowed "
                f"({MAX_MESSAGE_SIZE:,} bytes).\nPlease reduce the message length."
            )
            return

        friend_choice = self.friend_combo.get()
        friend_name = None if friend_choice in ("(none)", "") else friend_choice

        # Parse mode from combo selection
        mode_text = self.mode_combo.get()
        if "Double Ratchet" in mode_text:
            mode = "shared"  # Ratchet is a sub-mode of shared-secret encryption
        elif "Post-Quantum" in mode_text:
            mode = "pqc"
        elif "Shared" in mode_text:
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

        # Offload to CryptoTaskQueue (or raw thread as fallback) so the UI stays responsive
        def _do_encrypt():
            """Perform the actual encryption (runs in worker thread)."""
            return self.service.encrypt_base64(
                plaintext=plaintext,
                friend_name=friend_name,
                mode=mode,
                sign=sign,
                self_destruct_seconds=self_destruct_seconds,
            )

        def _on_success(b64):
            """Handle successful encryption (runs on main thread)."""
            self.last_sent_b64 = b64
            self._log_sent(b64)

        def _on_error(exc):
            """Handle encryption error (runs on main thread)."""
            logger.exception("Encryption failed")

        error_map = {
            CryptoTimeoutError: (
                "Timeout",
                "Encryption operation timed out. The system may be under "
                "heavy load. Please try again."
            ),
            EncryptionError: ("Encryption Error", None),
        }

        # Determine timeout based on mode
        if mode == "pqc":
            timeout = 60.0
        elif mode == "rsa":
            timeout = 30.0
        else:
            timeout = 30.0

        submit_crypto_task(
            crypto_queue=self.crypto_queue,
            do_work=_do_encrypt,
            on_success=_on_success,
            on_error=_on_error,
            frame=self.frame,
            fallback_timeout=timeout,
            error_map=error_map,
        )

    def _log_sent(self, b64_text):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        mode = getattr(self.service, 'last_encrypt_mode', None)
        if mode == "pqc":
            mode_label = "\U0001f6e1\ufe0f Post-Quantum (Hybrid KEM)"
        elif mode == "ratchet":
            mode_label = "\U0001f512 Double Ratchet (XChaCha20-Poly1305)"
        elif mode == "legacy":
            mode_label = "\U0001f511 Legacy AES-GCM"
        else:
            mode_label = "Unknown mode"
        self.sent_log.insert(
            tk.END,
            f"[{timestamp}] {mode_label}\n{b64_text}\n\n"
        )
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
