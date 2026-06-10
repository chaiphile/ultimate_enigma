"""Reusable TOTP dialog components.

Provides a standalone verification dialog and a setup dialog that can be
used by the main application or the lock screen flow without duplicating UI logic.
"""

import time
import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import logging

try:
    import qrcode
    from PIL import ImageTk
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

from services.totp_service import TOTPService

logger = logging.getLogger(__name__)


class TOTPVerifyDialog:
    """A modal dialog for verifying a TOTP code."""

    def __init__(self, parent, totp_service: TOTPService):
        self.parent = parent
        self.totp_service = totp_service
        self.result = False

    def show(self) -> bool:
        """Display the dialog and return True if verification succeeds."""
        dlg = tk.Toplevel(self.parent, bg="#1a1a1a")
        dlg.title("TOTP Verification")
        dlg.geometry("380x300")
        dlg.resizable(False, False)
        dlg.transient(self.parent)
        dlg.attributes("-topmost", True)
        dlg.grab_set()

        tk.Label(
            dlg, text="🔐 TOTP Verification", font=("Segoe UI", 16, "bold"),
            bg="#1a1a1a", fg="#ffffff"
        ).pack(pady=(20, 10))

        tk.Label(
            dlg, text="Enter the 6-digit code from your authenticator app:",
            font=("Segoe UI", 10), bg="#1a1a1a", fg="#cccccc"
        ).pack()

        totp_var = tk.StringVar()
        totp_entry = ttk.Entry(dlg, textvariable=totp_var, width=20,
                               bootstyle="warning", font=("Consolas", 18),
                               justify="center")
        totp_entry.pack(pady=10)
        totp_entry.focus_set()

        # Timer
        timer_var = tk.StringVar()
        timer_label = tk.Label(
            dlg, textvariable=timer_var, font=("Segoe UI", 9),
            bg="#1a1a1a", fg="#ffaa00"
        )
        timer_label.pack()

        def update_timer():
            if not dlg.winfo_exists():
                return
            try:
                remaining = self.totp_service.time_remaining()
                timer_var.set(f"⏱ Expires in: {remaining}s")
                if remaining <= 5:
                    timer_label.config(fg="#ff4444")
                else:
                    timer_label.config(fg="#ffaa00")
                dlg.after(500, update_timer)
            except Exception:
                pass

        update_timer()

        def verify():
            code = totp_var.get().strip()
            if len(code) != 6 or not code.isdigit():
                messagebox.showerror("Invalid", "Enter a 6-digit code.", parent=dlg)
                return
            if self.totp_service.verify(code):
                self.result = True
                dlg.destroy()
            else:
                messagebox.showerror("Failed", "Invalid TOTP code.", parent=dlg)
                totp_var.set("")

        def cancel():
            dlg.destroy()

        btn_frame = tk.Frame(dlg, bg="#1a1a1a")
        btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="✅ Verify", command=verify,
                   bootstyle="success").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=cancel,
                   bootstyle="secondary-outline").pack(side=tk.LEFT, padx=5)

        dlg.bind("<Return>", lambda e: verify())
        dlg.bind("<Escape>", lambda e: cancel())

        self.parent.wait_window(dlg)
        return self.result


class TOTPSetupDialog:
    """A modal dialog for setting up TOTP with provisioning URI."""

    def __init__(self, parent, totp_service: TOTPService, provisioning_uri: str,
                 on_regenerate=None):
        self.parent = parent
        self.totp_service = totp_service
        self.provisioning_uri = provisioning_uri
        self.on_regenerate = on_regenerate
        self.result = False

    def show(self) -> bool:
        """Display the setup dialog and return True if acknowledged."""
        dlg = tk.Toplevel(self.parent, bg="#1a1a1a")
        dlg.title("TOTP Setup")
        dlg.geometry("580x920")
        dlg.resizable(False, False)
        dlg.transient(self.parent)
        dlg.attributes("-topmost", True)
        dlg.grab_set()

        # ── BUTTON FRAME - Pack FIRST at bottom so it's always visible ──
        btn_frame = tk.Frame(dlg, bg="#1a1a1a", height=60)
        btn_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=(0, 15))
        btn_frame.pack_propagate(False)

        def ok_close():
            self.result = True
            dlg.destroy()

        def regenerate():
            if self.on_regenerate:
                self.on_regenerate()
                new_uri = self.totp_service.provisioning_uri()
                new_b32 = self.totp_service.get_b32_secret()
                uri_text.config(state="normal")
                uri_text.delete("1.0", tk.END)
                uri_text.insert("1.0", new_uri)
                uri_text.config(state="disabled")
                secret_text.config(state="normal")
                secret_text.delete("1.0", tk.END)
                secret_text.insert("1.0", new_b32)
                secret_text.config(state="disabled")
                code_var.set(self.totp_service.generate())
                # Update QR code if available
                if qr_label is not None and HAS_QRCODE:
                    self._update_qr(qr_label, new_uri)
                messagebox.showinfo("Regenerated", "New TOTP secret generated.\n"
                                    "Please re-scan with your authenticator app.", parent=dlg)

        # OK button
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
        if self.on_regenerate:
            regen_btn = tk.Button(
                btn_frame, text="🔄 Regenerate", font=("Segoe UI", 10),
                bg="#ffc107", fg="#212529", activebackground="#e0a800",
                activeforeground="#212529", bd=0, padx=12, pady=8,
                cursor="hand2", command=regenerate
            )
            regen_btn.pack(side=tk.LEFT, padx=5)

        # ── CONTENT ──
        content = tk.Frame(dlg, bg="#1a1a1a")
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(15, 5))

        tk.Label(
            content, text="🔐 TOTP Setup", font=("Segoe UI", 16, "bold"),
            bg="#1a1a1a", fg="#ffffff"
        ).pack(pady=(5, 8))

        tk.Label(
            content, text="Scan with Google Authenticator / Authy / Microsoft Authenticator",
            font=("Segoe UI", 9), bg="#1a1a1a", fg="#888888",
            justify="center"
        ).pack(pady=(0, 10))

        # QR Code display
        self._qr_photo = None
        qr_label = None
        if HAS_QRCODE:
            try:
                qr_label = tk.Label(content, bg="#1a1a1a")
                qr_label.pack(pady=(0, 10))
                self._update_qr(qr_label, self.provisioning_uri)
            except Exception as e:
                logger.warning("Failed to generate QR code: %s", e)
                tk.Label(
                    content, text="(QR code unavailable – use URI below)",
                    font=("Segoe UI", 9, "italic"), bg="#1a1a1a", fg="#ff6666"
                ).pack(pady=(0, 10))
        else:
            tk.Label(
                content, text="(Install qrcode[pil] for QR display – use URI below)",
                font=("Segoe UI", 9, "italic"), bg="#1a1a1a", fg="#ffaa00"
            ).pack(pady=(0, 10))

        # Provisioning URI
        tk.Label(
            content, text="Provisioning URI:", font=("Segoe UI", 9, "bold"),
            bg="#1a1a1a", fg="#ffaa00"
        ).pack(anchor="w")

        uri_text = tk.Text(content, height=3, width=68, bg="#2a2a2a", fg="#00ff88",
                           font=("Consolas", 9), wrap="char", relief="flat")
        uri_text.pack(pady=5, fill=tk.X)
        uri_text.insert("1.0", self.provisioning_uri)
        uri_text.config(state="disabled")

        def copy_uri():
            try:
                self.parent.clipboard_clear()
                self.parent.clipboard_append(self.provisioning_uri)
                messagebox.showinfo("Copied", "URI copied to clipboard.", parent=dlg)
            except Exception:
                pass

        ttk.Button(content, text="📋 Copy URI", command=copy_uri,
                   bootstyle="info-outline").pack(pady=(0, 8))

        # Base32 secret
        b32 = self.totp_service.get_b32_secret()

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
                self.parent.clipboard_clear()
                self.parent.clipboard_append(b32)
                messagebox.showinfo("Copied", "Secret copied to clipboard.", parent=dlg)
            except Exception:
                pass

        ttk.Button(content, text="📋 Copy Secret", command=copy_secret,
                   bootstyle="info-outline").pack(pady=(0, 10))

        # Live code preview – shows the CURRENT code that an authenticator
        # app would generate with the same secret.  Updates every 500 ms.
        tk.Label(
            content, text="Current Code (matches your authenticator app):",
            font=("Segoe UI", 10), bg="#1a1a1a", fg="#cccccc"
        ).pack()

        code_var = tk.StringVar()
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

        # Track previous code to detect transitions
        _prev_code = [None]

        def update_code_display():
            if not dlg.winfo_exists():
                return
            try:
                new_code = self.totp_service.generate()
                remaining = self.totp_service.time_remaining()

                # Visual flash when code changes
                if _prev_code[0] is not None and new_code != _prev_code[0]:
                    code_label.config(fg="#ffffff")  # brief white flash
                    dlg.after(150, lambda: code_label.config(
                        fg="#ff4444" if remaining <= 5 else "#00ff88"))
                _prev_code[0] = new_code

                code_var.set(new_code)
                timer_var.set(f"(expires in {remaining}s)")
                if remaining <= 5:
                    code_label.config(fg="#ff4444")
                    timer_label.config(fg="#ff4444")
                else:
                    code_label.config(fg="#00ff88")
                    timer_label.config(fg="#888888")
                dlg.after(500, update_code_display)
            except Exception as e:
                logger.debug("update_code_display error: %s", e)

        # Set initial value immediately before starting the loop
        try:
            code_var.set(self.totp_service.generate())
        except Exception:
            code_var.set("------")
        update_code_display()

        dlg.bind("<Escape>", lambda e: dlg.destroy())
        dlg.bind("<Return>", lambda e: ok_close())

        self.parent.wait_window(dlg)
        return self.result

    @staticmethod
    def _update_qr(label_widget: tk.Label, uri: str) -> None:
        """Generate a QR code from *uri* and display it on *label_widget*."""
        qr = qrcode.QRCode(version=1, box_size=6, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="#ffffff", back_color="#1a1a1a")
        photo = ImageTk.PhotoImage(qr_img)
        label_widget.configure(image=photo)
        label_widget.image = photo  # prevent garbage collection
