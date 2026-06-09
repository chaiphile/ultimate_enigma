"""Decrypt & Receive tab with self‑destruct awareness."""

import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import threading
import logging
from services.encryption_service import DecryptionError

logger = logging.getLogger(__name__)

class DecryptTab:
    def __init__(self, parent, app):
        self.app = app
        self.service = app.encryption_service   # use the same service layer
        self.frame = ttk.Frame(parent)
        self._build_ui()

    def _build_ui(self):
        # Input area
        in_frame = ttk.Labelframe(self.frame, text="Paste received Base64 message",
                                  bootstyle="info")
        in_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))

        self.recv_input = ttk.ScrolledText(
            in_frame, height=6, wrap=tk.WORD
        )
        self.recv_input.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Button bar
        btn_bar = ttk.Frame(self.frame)
        btn_bar.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(btn_bar, text="Paste from Clipboard",
                   command=self.paste_from_clipboard,
                   bootstyle="secondary-outline").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_bar, text="Clear",
                   command=self.clear,
                   bootstyle="secondary-outline").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_bar, text="Decrypt Message",
                   command=self.receive_message,
                   bootstyle="success").pack(side=tk.RIGHT, padx=5)

        # Output area
        out_frame = ttk.Labelframe(self.frame, text="Decrypted message",
                                   bootstyle="info")
        out_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.decrypted_display = ttk.ScrolledText(
            out_frame, height=10, wrap=tk.WORD,
            state='normal'
        )
        self.decrypted_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Self-destruct warning label
        self.warning_label = ttk.Label(
            self.frame, text="",
            bootstyle="warning",
            font=("Segoe UI", 9, "italic")
        )
        self.warning_label.pack(pady=(0, 5))

    def paste_from_clipboard(self):
        try:
            text = self.app.root.clipboard_get()
        except Exception:
            messagebox.showwarning("Clipboard",
                                   "Clipboard is empty or not accessible.")
            return
        self.recv_input.delete("1.0", tk.END)
        self.recv_input.insert("1.0", text)

    def clear(self):
        self.recv_input.delete("1.0", tk.END)
        self.decrypted_display.delete("1.0", tk.END)

    def receive_message(self):
        b64_text = self.recv_input.get("1.0", tk.END).strip()
        if not b64_text:
            messagebox.showwarning("Empty", "Paste a Base64 message to decrypt.")
            return

        def task():
            try:
                # Only pass the Base64 string to the service
                result = self.service.decrypt(b64_text)
            except DecryptionError as e:
                err_msg = str(e)
                self.app.task_queue.put(
                    lambda: messagebox.showerror("Decryption Error", err_msg)
                )
                # Clean warning
                self.app.task_queue.put(lambda: self.warning_label.config(text=""))
                return
            except Exception as e:
                logger.exception("Unexpected decryption error")
                self.app.task_queue.put(
                    lambda: messagebox.showerror("Decryption Error",
                                                 "An unexpected error occurred.")
                )
                self.app.task_queue.put(lambda: self.warning_label.config(text=""))
                return

            # Success – show in the output area
            self.app.task_queue.put(
                lambda: self._show_decrypted(result)
            )

        # Show a subtle self-destruct reminder (the actual expiry is enforced
        # inside the service layer)
        self.warning_label.config(
            text="⚠️ Self-destruct depends on recipient's client. Not 100% secure."
        )
        threading.Thread(target=task, daemon=True).start()

    def _show_decrypted(self, text):
        self.decrypted_display.insert(tk.END, text + "\n" + "─" * 50 + "\n")
        self.decrypted_display.see(tk.END)
        self.recv_input.delete("1.0", tk.END)