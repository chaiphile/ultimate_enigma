"""Reusable TOTP dialog components.

Provides a standalone verification dialog and a setup dialog that can be
used by the main application or the lock screen flow without duplicating UI logic.
"""

import time
import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
import logging

try:
    import qrcode
    from PIL import ImageTk
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

from services.totp_service import TOTPService
from views.utils import init_modal, flash_widget_text, ToolTip

logger = logging.getLogger(__name__)


class TOTPVerifyDialog:
    """A modal dialog for verifying a TOTP code."""

    def __init__(self, parent, totp_service: TOTPService):
        self.parent = parent
        self.totp_service = totp_service
        self.result = False

    def show(self) -> bool:
        """Display the dialog and return True if verification succeeds."""
        dlg = tk.Toplevel(self.parent)
        dlg.title("TOTP Verification")
        dlg.geometry("380x300")
        dlg.resizable(False, False)
        dlg.transient(self.parent)
        dlg.attributes("-topmost", True)
        dlg.grab_set()

        init_modal(dlg, self.parent)

        ttk.Label(
            dlg, text="🔐 TOTP Verification", font=("Segoe UI", 16, "bold")
        ).pack(pady=(20, 10))

        ttk.Label(
            dlg, text="Enter the 6-digit code from your authenticator app:",
            font=("Segoe UI", 10)
        ).pack()

        totp_var = tk.StringVar()
        totp_entry = ttk.Entry(dlg, textvariable=totp_var, width=20,
                               bootstyle="warning", font=("Consolas", 18),
                               justify="center")
        totp_entry.pack(pady=10)
        totp_entry.focus_set()

        # Timer
        timer_var = tk.StringVar()
        timer_label = ttk.Label(
            dlg, textvariable=timer_var,
            font=("Segoe UI", 9), bootstyle="warning"
        )
        timer_label.pack()

        def update_timer():
            if not dlg.winfo_exists():
                return
            try:
                remaining = self.totp_service.time_remaining()
                timer_var.set(f"⏱ Expires in: {remaining}s")
                dlg.after(500, update_timer)
            except Exception:
                pass

        update_timer()

        def verify():
            code = totp_var.get().strip()
            if len(code) != 6 or not code.isdigit():
                messagebox.showerror("Invalid Input", "Enter a 6-digit code.", parent=dlg)
                return
            if self.totp_service.verify(code):
                self.result = True
                dlg.destroy()
            else:
                messagebox.showerror("Unsuccessful", "The TOTP code is invalid.", parent=dlg)
                totp_var.set("")

        def cancel():
            dlg.destroy()

        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(pady=15)
        verify_totp_btn = ttk.Button(btn_frame, text="✅ Verify", command=verify,
                                     bootstyle="success")
        verify_totp_btn.pack(side=tk.LEFT, padx=5)
        ToolTip(verify_totp_btn, "Verification of the entered TOTP code")
        cancel_totp_btn = ttk.Button(btn_frame, text="Cancel", command=cancel,
                                     bootstyle="secondary-outline")
        cancel_totp_btn.pack(side=tk.LEFT, padx=5)
        ToolTip(cancel_totp_btn, "Cancel TOTP verification")

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
        dlg = tk.Toplevel(self.parent)
        dlg.title("TOTP Setup")
        dlg.geometry("580x920")
        dlg.resizable(False, False)
        dlg.transient(self.parent)
        dlg.attributes("-topmost", True)
        dlg.grab_set()

        init_modal(dlg, self.parent)

        # ── BUTTON FRAME - Pack FIRST at bottom so it's always visible ──
        btn_frame = ttk.Frame(dlg, height=60)
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
                messagebox.showinfo("Secret Regenerated", "A new TOTP secret has been generated.\n"
                                    "Please scan the QR code again with your authenticator app.", parent=dlg)

        # OK button
        ok_btn = ttk.Button(
            btn_frame, text="✅  OK – I have saved the secret",
            command=ok_close, bootstyle="success"
        )
        ok_btn.pack(side=tk.RIGHT, padx=5)
        ToolTip(ok_btn, "Confirm and close — TOTP secret is saved")

        # Cancel button
        cancel_btn = ttk.Button(
            btn_frame, text="Cancel",
            command=dlg.destroy, bootstyle="secondary-outline"
        )
        cancel_btn.pack(side=tk.RIGHT, padx=5)
        ToolTip(cancel_btn, "Cancel setup")

        # Regenerate button
        if self.on_regenerate:
            regen_btn = ttk.Button(
                btn_frame, text="🔄 Regenerate",
                command=regenerate, bootstyle="warning"
            )
            regen_btn.pack(side=tk.LEFT, padx=5)
            ToolTip(regen_btn, "Generate a new TOTP secret")

        # ── CONTENT ──
        content = ttk.Frame(dlg)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(15, 5))

        ttk.Label(
            content, text="🔐 TOTP Setup", font=("Segoe UI", 16, "bold")
        ).pack(pady=(5, 8))

        ttk.Label(
            content, text="Scan with Google Authenticator / Authy / Microsoft Authenticator",
            font=("Segoe UI", 9), justify="center"
        ).pack(pady=(0, 10))

        # QR Code display
        self._qr_photo = None
        qr_label = None
        if HAS_QRCODE:
            try:
                qr_label = ttk.Label(content)
                qr_label.pack(pady=(0, 10))
                self._update_qr(qr_label, self.provisioning_uri)
            except Exception as e:
                logger.warning("Failed to generate QR code: %s", e)
                ttk.Label(
                    content, text="(QR code unavailable – use URI below)",
                    font=("Segoe UI", 9, "italic")
                ).pack(pady=(0, 10))
        else:
            ttk.Label(
                content, text="(Install qrcode[pil] for QR display – use URI below)",
                font=("Segoe UI", 9, "italic")
            ).pack(pady=(0, 10))

        # Provisioning URI
        ttk.Label(
            content, text="Provisioning URI:", font=("Segoe UI", 9, "bold")
        ).pack(anchor="w")

        uri_text = tk.Text(content, height=3, width=68,
                           font=("Consolas", 9), wrap="char", relief="flat")
        uri_text.pack(pady=5, fill=tk.X)
        uri_text.insert("1.0", self.provisioning_uri)
        uri_text.config(state="disabled")

        def copy_uri():
            try:
                self.parent.clipboard_clear()
                self.parent.clipboard_append(self.provisioning_uri)
                flash_widget_text(copy_uri_btn, "✓ Copied", "📋 Copy URI")
            except Exception:
                pass

        copy_uri_btn = ttk.Button(content, text="📋 Copy URI", command=copy_uri,
                                  bootstyle="info-outline")
        copy_uri_btn.pack(pady=(0, 8))
        ToolTip(copy_uri_btn, "Copy the URI to the clipboard")

        # Base32 secret
        b32 = self.totp_service.get_b32_secret()

        ttk.Label(
            content, text="Secret (Base32) – Manual Entry:", font=("Segoe UI", 9, "bold")
        ).pack(anchor="w")

        secret_text = tk.Text(content, height=1, width=68,
                              font=("Consolas", 12), relief="flat")
        secret_text.pack(pady=5, fill=tk.X)
        secret_text.insert("1.0", b32)
        secret_text.config(state="disabled")

        def copy_secret():
            try:
                self.parent.clipboard_clear()
                self.parent.clipboard_append(b32)
                flash_widget_text(copy_secret_btn, "✓ Copied", "📋 Copy Secret")
            except Exception:
                pass

        copy_secret_btn = ttk.Button(content, text="📋 Copy Secret", command=copy_secret,
                                     bootstyle="info-outline")
        copy_secret_btn.pack(pady=(0, 10))
        ToolTip(copy_secret_btn, "Copy the Base32 code to the clipboard")

        # Live code preview – shows the CURRENT code that an authenticator
        # app would generate with the same secret.  Updates every 500 ms.
        ttk.Label(
            content, text="Current Code (matches your authenticator app):",
            font=("Segoe UI", 10)
        ).pack()

        code_var = tk.StringVar()
        code_label = ttk.Label(
            content, textvariable=code_var, font=("Consolas", 28, "bold")
        )
        code_label.pack(pady=5)

        timer_var = tk.StringVar()
        timer_label = ttk.Label(
            content, textvariable=timer_var,
            font=("Segoe UI", 9)
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

                _prev_code[0] = new_code

                code_var.set(new_code)
                timer_var.set(f"(expires in {remaining}s)")
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
