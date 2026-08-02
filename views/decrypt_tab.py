"""Decrypt & Receive tab with self-destruct awareness and ratchet mode indicator."""

import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
import logging
from queue import Queue
from services.encryption import DecryptionError
from src.exceptions import CryptoTimeoutError
from src.crypto_task_helper import submit_crypto_task
from views.utils import friendly_error, flash_widget_text, ToolTip

logger = logging.getLogger(__name__)

AUTO_CLEAR_INTERVALS = (10, 30, 60)
DEFAULT_AUTO_CLEAR_SECONDS = 30
AUTO_CLEAR_LABELS = tuple(f"{seconds} s" for seconds in AUTO_CLEAR_INTERVALS)
COPY_RESULT_LABEL = "Copy Result"
COPY_FLASH_BASE = "Copied ✓"

class DecryptTab:
    def __init__(self, parent: tk.Widget, encryption_service, clipboard_service, task_queue: Queue,
                 crypto_queue=None) -> None:
        """
        Args:
            parent: Notebook widget
            encryption_service: Handles decryption operations
            clipboard_service: Handles clipboard operations
            task_queue: Queue for scheduling UI updates from background threads
            crypto_queue: Optional CryptoTaskQueue for managed background execution.
                         If provided, replaces ad-hoc threading with pool-based
                         task submission and timeout enforcement.
        """
        self.service = encryption_service
        self.clipboard_service = clipboard_service
        self.task_queue = task_queue
        self.crypto_queue = crypto_queue
        self.frame = ttk.Frame(parent)
        self._autoclear_after_id: str | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        # Input area
        in_frame = ttk.Labelframe(self.frame, text="Encrypted Message Input",
                                  bootstyle="info")
        in_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))

        self.recv_input = ttk.ScrolledText(
            in_frame, height=6, wrap=tk.WORD
        )
        self.recv_input.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.recv_input.bind("<Control-Return>",
                             lambda e: (self.receive_message(), "break")[1])

        # Button bar
        btn_bar = ttk.Frame(self.frame)
        btn_bar.pack(fill=tk.X, padx=10, pady=5)

        paste_btn = ttk.Button(btn_bar, text="Paste from Clipboard",
                               command=self.paste_from_clipboard,
                               bootstyle="secondary-outline")
        paste_btn.pack(side=tk.LEFT, padx=5)
        ToolTip(paste_btn, "Paste encrypted text from clipboard")
        clip_decrypt_btn = ttk.Button(btn_bar, text="Decrypt from Clipboard",
                                      command=self.decrypt_from_clipboard,
                                      bootstyle="success-outline")
        clip_decrypt_btn.pack(side=tk.LEFT, padx=5)
        ToolTip(clip_decrypt_btn, "Paste encrypted text from clipboard and decrypt it immediately")
        clear_btn = ttk.Button(btn_bar, text="Clear",
                               command=self.clear,
                               bootstyle="secondary-outline")
        clear_btn.pack(side=tk.LEFT, padx=5)
        ToolTip(clear_btn, "Clear input and output text")
        self.copy_out_btn = ttk.Button(btn_bar, text=COPY_RESULT_LABEL,
                                       command=self.copy_decrypted,
                                       bootstyle="info-outline",
                                       state="disabled")
        self.copy_out_btn.pack(side=tk.LEFT, padx=5)
        ToolTip(self.copy_out_btn, "Copy the decrypted text to the clipboard")
        self.decrypt_btn = ttk.Button(btn_bar, text="Decrypt Message",
                                      command=self.receive_message,
                                      bootstyle="success")
        self.decrypt_btn.pack(side=tk.RIGHT, padx=5)
        ToolTip(self.decrypt_btn, "Decrypt the message")

        autoclear_bar = ttk.Frame(self.frame)
        autoclear_bar.pack(fill=tk.X, padx=10, pady=(0, 5))

        self.auto_clear_var = tk.BooleanVar(value=False)
        autoclear_chk = ttk.Checkbutton(
            autoclear_bar, text="Auto-clear after",
            variable=self.auto_clear_var, bootstyle="secondary")
        autoclear_chk.pack(side=tk.LEFT, padx=(5, 2))
        ToolTip(autoclear_chk, "Automatically clear sensitive decrypted output after a delay")

        self.auto_clear_seconds_var = tk.StringVar(
            value=f"{DEFAULT_AUTO_CLEAR_SECONDS} s")
        autoclear_cb = ttk.Combobox(
            autoclear_bar, textvariable=self.auto_clear_seconds_var,
            values=AUTO_CLEAR_LABELS, state="readonly", width=6)
        autoclear_cb.pack(side=tk.LEFT, padx=(2, 5))
        ToolTip(autoclear_cb, "Seconds to wait before auto-clearing the decrypted output")

        # Output area
        out_frame = ttk.Labelframe(self.frame, text="Decrypted Message",
                                   bootstyle="info")
        out_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Read-only so the decrypted plaintext can't be accidentally edited
        self.decrypted_display = ttk.ScrolledText(
            out_frame, height=10, wrap=tk.WORD,
            state='disabled'
        )
        self.decrypted_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Decryption mode indicator
        self.mode_label = ttk.Label(self.frame, text="", bootstyle="info")
        self.mode_label.pack(pady=(0, 2))

        # Hybrid-signature indicator (separate so it doesn't hide the mode)
        self.sig_label = ttk.Label(self.frame, text="", bootstyle="success")
        self.sig_label.pack(pady=(0, 2))

        # Static informational caption (not tied to a specific message)
        self.warning_label = ttk.Label(
            self.frame,
            text="ℹ️ Self-destruct relies on the sender's settings and the "
                 "recipient's client application. It is best-effort and not guaranteed.",
            bootstyle="secondary",
        )
        self.warning_label.pack(pady=(0, 5))

    def _set_busy(self, busy: bool) -> None:
        try:
            self.decrypt_btn.configure(state="disabled" if busy else "normal")
            self.frame.winfo_toplevel().configure(cursor="watch" if busy else "")
        except Exception:
            logger.debug("set_busy failed", exc_info=True)

    def copy_decrypted(self) -> None:
        self.decrypted_display.configure(state='normal')
        text = self.decrypted_display.get("1.0", tk.END).strip()
        self.decrypted_display.configure(state='disabled')
        if not text:
            messagebox.showwarning("Nothing to Copy", "There is no decrypted message to copy.")
            return
        if self.clipboard_service.copy(text):
            flash_text = COPY_FLASH_BASE
            if self.auto_clear_var.get():
                flash_text = f"{COPY_FLASH_BASE} (clears in {self.auto_clear_seconds_var.get()})"
            flash_widget_text(self.copy_out_btn, flash_text, COPY_RESULT_LABEL)
        else:
            messagebox.showerror("Clipboard Error", "Unable to access the clipboard.")

    def _load_from_clipboard(self) -> bool:
        text = self.clipboard_service.get()
        if text is None:
            messagebox.showwarning("Clipboard Unavailable",
                                   "Clipboard is empty or inaccessible.")
            return False
        if self.recv_input.get("1.0", tk.END).strip():
            if not messagebox.askyesno(
                "Replace input text?",
                "The input box contains text. Replace with clipboard content?"
            ):
                return False
        self.recv_input.delete("1.0", tk.END)
        self.recv_input.insert("1.0", text)
        return True

    def paste_from_clipboard(self) -> None:
        self._load_from_clipboard()

    def decrypt_from_clipboard(self) -> None:
        if self._load_from_clipboard():
            self.receive_message()

    def _cancel_autoclear(self) -> None:
        if self._autoclear_after_id is not None:
            try:
                self.frame.after_cancel(self._autoclear_after_id)
            except Exception:
                logger.debug("auto-clear cancel failed", exc_info=True)
            self._autoclear_after_id = None

    def _clear_output(self) -> None:
        self._cancel_autoclear()
        self.decrypted_display.configure(state='normal')
        self.decrypted_display.delete("1.0", tk.END)
        self.decrypted_display.configure(state='disabled')
        self.mode_label.config(text="")
        self.sig_label.config(text="")
        self._set_copy_enabled(False)

    def _set_copy_enabled(self, enabled: bool) -> None:
        try:
            self.copy_out_btn.configure(state="normal" if enabled else "disabled")
        except Exception:
            logger.debug("set copy button state failed", exc_info=True)

    def _schedule_autoclear(self) -> None:
        self._cancel_autoclear()
        if not self.auto_clear_var.get():
            return
        seconds = DEFAULT_AUTO_CLEAR_SECONDS
        for candidate in AUTO_CLEAR_INTERVALS:
            if self.auto_clear_seconds_var.get() == f"{candidate} s":
                seconds = candidate
                break
        self._autoclear_after_id = self.frame.after(
            seconds * 1000, self._clear_output)

    def clear(self) -> None:
        self.recv_input.delete("1.0", tk.END)
        self._clear_output()

    def receive_message(self) -> None:
        b64_text = self.recv_input.get("1.0", tk.END).strip()
        if not b64_text:
            messagebox.showwarning("Empty Input", "Paste an encrypted message to decrypt.")
            return

        def _do_decrypt():
            """Perform the actual decryption (runs in worker thread)."""
            return self.service.decrypt(b64_text)

        def _on_success(result):
            """Handle successful decryption (runs on main thread)."""
            self._set_busy(False)
            decrypt_mode = getattr(self.service, 'last_decrypt_mode', None)
            self._show_decrypted(result, decrypt_mode)

        def _on_error(exc):
            """Handle decryption error (runs on main thread)."""
            self._set_busy(False)
            if isinstance(exc, CryptoTimeoutError):
                messagebox.showerror(
                    "Decryption Timed Out",
                    "Decryption timed out. The message may be too large, "
                    "or the system is under heavy load. Please try again."
                )
            elif isinstance(exc, DecryptionError):
                err_msg = str(exc)
                is_ratchet_missing = (
                    "ratchet session" in err_msg.lower()
                    or "no active ratchet" in err_msg.lower()
                )
                if is_ratchet_missing:
                    messagebox.showerror(
                        "Session Not Found",
                        "No encryption session was found for this message.\n\n"
                        "To resolve this:\n"
                        "1. Go to the Friends tab\n"
                        "2. Select the sender and perform a new key exchange\n"
                        "3. Both parties must complete the handshake\n\n"
                        "The session may have been lost due to a database reset. "
                        "Reinstall the application if the issue persists."
                    )
                else:
                    messagebox.showerror(
                        "Decryption Error",
                        "This message cannot be decrypted. It may be corrupted, "
                        "was not sent to you, or has expired."
                    )
            else:
                logger.exception("Unexpected decryption error")
                messagebox.showerror("Decryption Error", friendly_error(exc))
            self.mode_label.config(text="")
            self.sig_label.config(text="")

        self._cancel_autoclear()
        self._set_busy(True)
        submit_crypto_task(
            crypto_queue=self.crypto_queue,
            do_work=_do_decrypt,
            on_success=_on_success,
            on_error=_on_error,
            task_queue=self.task_queue,
            frame=self.frame,
            fallback_timeout=30.0,
        )

    def _show_decrypted(self, text: str, decrypt_mode=None) -> None:
        # Detect hybrid signature verification in the decrypted text
        has_hybrid_sig = "Hybrid Signature Verified (Ed25519 + Dilithium3)" in text

        if decrypt_mode == "pqc":
            mode_indicator = "\U0001f6e1\ufe0f Decrypted via Post-Quantum Hybrid KEM"
            self.mode_label.config(text=mode_indicator, bootstyle="success")
        elif decrypt_mode == "ratchet":
            mode_indicator = "\U0001f512 Decrypted via Double Ratchet (XChaCha20-Poly1305)"
            self.mode_label.config(text=mode_indicator, bootstyle="success")
        elif decrypt_mode == "legacy":
            mode_indicator = "\U0001f511 Decrypted via Legacy AES-GCM"
            self.mode_label.config(text=mode_indicator, bootstyle="warning")
        else:
            self.mode_label.config(text="")

        # Show hybrid signature indicator on its own label so it doesn't hide the mode
        if has_hybrid_sig:
            self.sig_label.config(
                text="\u2705 Hybrid Signature Verified (Ed25519 + Dilithium3)",
                bootstyle="success",
            )
        else:
            self.sig_label.config(text="")

        self.decrypted_display.configure(state='normal')
        self.decrypted_display.delete("1.0", tk.END)
        self.decrypted_display.insert(tk.END, text)
        self.decrypted_display.see(tk.END)
        self.decrypted_display.configure(state='disabled')
        self._set_copy_enabled(True)
        self._schedule_autoclear()
        self.recv_input.delete("1.0", tk.END)
