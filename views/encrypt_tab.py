"""Encrypt & Send tab – decoupled via dependency injection.

Uses CryptoTaskQueue for non-blocking encryption with timeout enforcement.
"""

import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
import datetime
import logging
from services.encryption import EncryptionService, EncryptionError
from services.friends import FriendsService
from services.clipboard_service import ClipboardService
from services.pqc_service import is_pqc_available
from services.global_secret_service import GlobalSecretService
from src.exceptions import CryptoTimeoutError
from src.crypto_task_helper import submit_crypto_task
from views.utils import friendly_error, flash_widget_text, ToolTip

logger = logging.getLogger(__name__)

# Maximum message size (1 MB) to prevent memory issues
MAX_MESSAGE_SIZE = 1024 * 1024
ENCRYPT_SEND_TEXT = "Encrypt & Send"
BUSY_STATUS_TEXT = "Encrypting…"
GLOBAL_MODE_TEXT = "Shared Secret (Time-Based)"
GLOBAL_HINT_TEXT = "Global broadcast — encrypted with your shared secret. Anyone holding the same secret can decrypt it."
NO_GLOBAL_HINT_TEXT = "Select a friend, or set a global shared secret in the Shared Secret tab to broadcast to everyone who has it."


class EncryptTab:
    def __init__(self, parent: tk.Widget, encryption_service: EncryptionService,
                 friends_service: FriendsService, clipboard_service: ClipboardService,
                 crypto_queue=None, global_secret_service: GlobalSecretService = None) -> None:
        """
        Args:
            parent: Notebook widget
            encryption_service: Handles crypto operations
            friends_service: Provides friend data (no direct KeyStore access)
            clipboard_service: Handles clipboard operations
            crypto_queue: Optional CryptoTaskQueue for managed background execution.
                         If provided, replaces ad-hoc threading with pool-based
                         task submission and timeout enforcement.
            global_secret_service: Optional GlobalSecretService used to enable
                                   friend-less "broadcast" sends via the global
                                   shared secret.
        """
        self.service = encryption_service
        self.friends_service = friends_service
        self.clipboard_service = clipboard_service
        self.crypto_queue = crypto_queue
        self.global_secret_service = global_secret_service
        
        # Store last sent message locally instead of on app instance
        self.last_sent_b64 = ""
        self._busy = False
        self._drafts = {}
        self._current_friend = "(none)"
        self._mode_overridden = False
        
        self.frame = ttk.Frame(parent)
        self._build_ui()

    def _build_ui(self) -> None:
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

        # Encryption mode
        ttk.Label(opts, text="Mode:").grid(row=0, column=3, padx=(10, 5), sticky=tk.W)
        self._pqc_available = is_pqc_available()
        mode_values = ["Double Ratchet (XChaCha20)", "Shared Secret (Time-Based)", "Public Key (RSA)"]
        if self._pqc_available:
            mode_values.append("Post-Quantum (Hybrid KEM)")
        self.mode_combo = ttk.Combobox(
            opts, state="readonly", width=22,
            values=mode_values,
            bootstyle="secondary"
        )
        self.mode_combo.grid(row=0, column=4, padx=5, sticky=tk.W)
        self.mode_combo.current(0)
        self.mode_combo.bind('<<ComboboxSelected>>', self._on_mode_changed)

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
        self.clear_btn = ttk.Button(opts, text="Clear", command=self.clear_input,
                                    bootstyle="secondary-outline")
        self.clear_btn.grid(row=0, column=11, padx=5, sticky=tk.E)
        ToolTip(self.clear_btn, "Delete message text")
        self.send_btn = ttk.Button(opts, text="Encrypt & Send", command=self.send_message,
                                   bootstyle="success")
        self.send_btn.grid(row=0, column=12, padx=5, sticky=tk.E)
        ToolTip(self.send_btn, "Encrypt and send the message to the selected friend")

        # Contextual hint (e.g. global-broadcast guidance when no friend chosen)
        self.hint_label = ttk.Label(self.frame, text="", bootstyle="warning",
                                    anchor="w", padding=(12, 0))
        self.hint_label.pack(fill=tk.X, padx=10, pady=(0, 2))

        # Message input
        msg_frame = ttk.Labelframe(self.frame, text="Write your message",
                                   bootstyle="info")
        msg_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.msg_input = ttk.ScrolledText(
            msg_frame, height=8, wrap=tk.WORD
        )
        self.msg_input.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        # Keyboard shortcuts: Ctrl+Enter / Alt+Return sends, Escape clears
        self.msg_input.bind("<Control-Return>", lambda e: (self.send_message(), "break")[1])
        self.msg_input.bind("<Alt-Return>", lambda e: (self.send_message(), "break")[1])
        self.msg_input.bind("<Escape>", lambda e: (self.clear_input(), "break")[1])

        # Sent messages log
        sent_frame = ttk.Labelframe(self.frame, text="Sent Encrypted Messages",
                                    bootstyle="info")
        sent_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        # Read-only so users can't accidentally corrupt the ciphertext history
        self.sent_log = ttk.ScrolledText(
            sent_frame, height=6, wrap=tk.WORD, state='disabled'
        )
        self.sent_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Bottom button bar
        btn_bar = ttk.Frame(self.frame)
        btn_bar.pack(fill=tk.X, padx=10, pady=(0, 5))
        self.copy_btn = ttk.Button(btn_bar, text="Copy Last Sent", command=self.copy_last_sent,
                                   bootstyle="info-outline")
        self.copy_btn.pack(side=tk.LEFT, padx=5)
        ToolTip(self.copy_btn, "Copy the last message sent to the clipboard")
        self.clear_log_btn = ttk.Button(btn_bar, text="Clear Log", command=self.clear_log,
                                        bootstyle="secondary-outline")
        self.clear_log_btn.pack(side=tk.LEFT, padx=5)
        ToolTip(self.clear_log_btn, "Clear the history of sent messages")

        self._update_friend_list()
        self.focus_compose()

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        try:
            if busy:
                self.send_btn.configure(state="disabled")
                self.mode_combo.configure(state="disabled")
                self.clear_btn.configure(state="disabled")
                self.clear_log_btn.configure(state="disabled")
                self.msg_input.configure(state="disabled")
                self.frame.winfo_toplevel().configure(cursor="watch")
                flash_widget_text(self.send_btn, BUSY_STATUS_TEXT, ENCRYPT_SEND_TEXT)
            else:
                self.send_btn.configure(text=ENCRYPT_SEND_TEXT)
                self.frame.winfo_toplevel().configure(cursor="")
                mode_state, _ = self._mode_info_for(self.friend_combo.get())
                self.mode_combo.configure(state=mode_state)
                self.clear_btn.configure(state="normal")
                self.clear_log_btn.configure(state="normal")
                self.msg_input.configure(state="normal")
                self._update_send_state()
        except Exception:
            logger.debug("set_busy failed", exc_info=True)

    def clear_log(self) -> None:
        self.sent_log.configure(state='normal')
        has_content = bool(self.sent_log.get("1.0", tk.END).strip())
        self.sent_log.configure(state='disabled')
        if not has_content:
            return
        if messagebox.askyesno(
            "Clear history",
            "Delete the entire history of sent messages? This action cannot be reversed."
        ):
            self.sent_log.configure(state='normal')
            self.sent_log.delete("1.0", tk.END)
            self.sent_log.configure(state='disabled')

    def _update_friend_list(self) -> None:
        """Fetch friend names from service instead of direct model access."""
        names = ["(none)"] + self.friends_service.get_friend_names()
        self.friend_combo['values'] = names
        self.friend_combo.current(0)
        if self._current_friend != "(none)":
            self._drafts[self._current_friend] = self.msg_input.get("1.0", tk.END)
            self._current_friend = "(none)"
            text = self._drafts.get("(none)", "")
            self.msg_input.delete("1.0", tk.END)
            if text:
                self.msg_input.insert("1.0", text)
        mode_state, recommended = self._mode_info_for("(none)")
        self.mode_combo.set(recommended)
        self.mode_combo.config(state=mode_state)
        self._mode_overridden = False
        self._update_hint()
        self._update_send_state()

    def _on_friend_changed(self, event: tk.Event = None) -> None:
        choice = self.friend_combo.get()
        if not choice:
            choice = "(none)"
        self._swap_friend(self._current_friend, choice)
        mode_state, recommended = self._mode_info_for(choice)
        # A manual mode override only makes sense while the new friend can
        # actually use it; when the friend is stuck with the fallback mode
        # (state "disabled") a stale override would be sent and fail.
        if choice == "(none)" or not self._mode_overridden or mode_state == "disabled":
            self.mode_combo.set(recommended)
        self.mode_combo.config(state=mode_state)
        self._update_hint()
        self._update_send_state()

    def _on_mode_changed(self, event: tk.Event = None) -> None:
        self._mode_overridden = True

    def _has_global_secret(self) -> bool:
        try:
            return bool(self.global_secret_service
                        and self.global_secret_service.has_secret())
        except Exception:
            logger.debug("global secret check failed", exc_info=True)
            return False

    def _update_hint(self) -> None:
        try:
            friend = self.friend_combo.get()
            if friend and friend != "(none)":
                self.hint_label.config(text="", bootstyle="warning")
                return
            if self._has_global_secret():
                self.hint_label.config(text=GLOBAL_HINT_TEXT, bootstyle="warning")
            else:
                self.hint_label.config(text=NO_GLOBAL_HINT_TEXT, bootstyle="secondary")
        except Exception:
            logger.debug("update hint failed", exc_info=True)

    def _swap_friend(self, old: str, new: str) -> None:
        self._drafts[old] = self.msg_input.get("1.0", tk.END)
        self._current_friend = new
        text = self._drafts.get(new, "")
        self.msg_input.delete("1.0", tk.END)
        if text:
            self.msg_input.insert("1.0", text)
            self.msg_input.mark_set(tk.INSERT, tk.END)
            self.msg_input.see(tk.END)

    def _mode_info_for(self, choice: str) -> tuple[str, str]:
        if not choice or choice == "(none)":
            if self._has_global_secret():
                return "readonly", GLOBAL_MODE_TEXT
            return "disabled", GLOBAL_MODE_TEXT
        has_ratchet = self.friends_service.has_active_ratchet(choice)
        has_pqc = self.friends_service.friend_has_pqc_key(choice)
        has_secret = self.friends_service.friend_has_secret(choice)
        if has_ratchet:
            return "readonly", "Double Ratchet (XChaCha20)"
        if has_pqc and self._pqc_available:
            return "readonly", "Post-Quantum (Hybrid KEM)"
        if has_secret:
            return "readonly", GLOBAL_MODE_TEXT
        return "disabled", "Public Key (RSA)"

    def _update_send_state(self) -> None:
        try:
            if not hasattr(self, "send_btn"):
                return
            friend = self.friend_combo.get()
            text = self.msg_input.get("1.0", tk.END).strip()
            has_target = (bool(friend) and friend != "(none)") or self._has_global_secret()
            valid = has_target and bool(text) and not self._busy
            self.send_btn.configure(state="normal" if valid else "disabled")
        except Exception:
            logger.debug("update_send_state failed", exc_info=True)

    def focus_compose(self) -> None:
        try:
            self.msg_input.focus_set()
            self.msg_input.mark_set(tk.INSERT, tk.END)
            self.msg_input.see(tk.END)
        except Exception:
            logger.debug("focus_compose failed", exc_info=True)

    def clear_input(self) -> None:
        self.msg_input.delete("1.0", tk.END)
        self._update_send_state()

    def send_message(self) -> None:
        plaintext = self.msg_input.get("1.0", tk.END).strip()
        if not plaintext:
            return
        
        # Validate message size
        msg_size = len(plaintext.encode('utf-8'))
        if msg_size > MAX_MESSAGE_SIZE:
            messagebox.showwarning(
                "Message Too Large",
                f"Message size ({msg_size:,} bytes) exceeds the maximum allowed "
                f"size ({MAX_MESSAGE_SIZE:,} bytes).\nPlease reduce the message length."
            )
            return

        friend_choice = self.friend_combo.get()
        friend_name = None if friend_choice in ("(none)", "") else friend_choice

        if friend_name is None and not self._has_global_secret():
            messagebox.showwarning(
                "No Recipient",
                "Choose a friend, or set a global shared secret in the "
                "Shared Secret tab to broadcast to everyone who has it."
            )
            return

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
            self._set_busy(False)
            self.last_sent_b64 = b64
            self._log_sent(b64)

        def _on_error(exc):
            """Handle encryption error (runs on main thread)."""
            self._set_busy(False)
            logger.exception("Encryption failed")
            if isinstance(exc, CryptoTimeoutError):
                messagebox.showerror(
                    "Encryption Timeout",
                    "Encryption timed out. The system may be under heavy load. "
                    "Please try again."
                )
            else:
                messagebox.showerror("Encryption Error", friendly_error(exc))

        # Determine timeout based on mode
        if mode == "pqc":
            timeout = 60.0
        elif mode == "rsa":
            timeout = 30.0
        else:
            timeout = 30.0

        self._set_busy(True)
        submit_crypto_task(
            crypto_queue=self.crypto_queue,
            do_work=_do_encrypt,
            on_success=_on_success,
            on_error=_on_error,
            frame=self.frame,
            fallback_timeout=timeout,
        )

    def _log_sent(self, b64_text: str) -> None:
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        mode = getattr(self.service, 'last_encrypt_mode', None)
        if mode == "pqc":
            mode_label = "\U0001f6e1\ufe0f Post-Quantum (Hybrid KEM)"
        elif mode == "ratchet":
            mode_label = "\U0001f512 Double Ratchet (XChaCha20-Poly1305)"
        elif mode == "legacy":
            mode_label = "\U0001f511 Legacy AES-GCM"
        else:
            mode_label = "\U0001f510 Encrypted"
        self.sent_log.configure(state='normal')
        self.sent_log.insert(
            tk.END,
            f"[{timestamp}] {mode_label}\n{b64_text}\n\n"
        )
        self.sent_log.see(tk.END)
        self.sent_log.configure(state='disabled')
        self.msg_input.delete("1.0", tk.END)
        self._update_send_state()

    def copy_last_sent(self) -> None:
        if self.last_sent_b64:
            ok = self.clipboard_service.copy(self.last_sent_b64)
            if ok:
                flash_widget_text(self.copy_btn, "Copied ✓ (clears in 30s)",
                                  "Copy Last Sent")
            else:
                messagebox.showerror("Clipboard error", "Unable to access the clipboard.")
        else:
            messagebox.showwarning("Nothing Sent", "No message has been sent yet.")

    # ---- External notification hook ----
    def notify_friend_list_changed(self) -> None:
        """Called by app when friend list changes externally."""
        self._update_friend_list()
