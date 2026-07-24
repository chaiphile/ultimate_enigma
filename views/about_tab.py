"""About tab with backup export/import."""

import json
import os
import stat
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttkb

from services.backup_service import BackupService, BackupServiceError
from views.dialogs import password_dialog
from views.utils import ToolTip
from controllers.auth_controller import AuthController
from key_manager import KeyStore


class AboutTab:
    def __init__(self, parent: tk.Widget, key_store: KeyStore, auth_controller: AuthController,
                 backup_service: BackupService = None) -> None:
        """
        Args:
            parent: Notebook widget
            key_store: KeyStore instance for backup operations
            auth_controller: Handles password change and duress password operations
            backup_service: Optional shared BackupService instance. If not provided,
                           a new one is created (legacy behaviour).
        """
        self.auth_controller = auth_controller
        self.frame = ttkb.Frame(parent)
        self._backup_service = backup_service or BackupService(key_store)
        self._build_ui()

    def set_backup_service(self, backup_service: BackupService) -> None:
        """Retarget backup actions to the active backup service."""
        if backup_service is not None:
            self._backup_service = backup_service

    def _build_ui(self) -> None:
        # Main container with generous padding
        f = ttkb.Frame(self.frame, padding=30)
        f.pack(expand=True)

        # Title
        ttkb.Label(f, text="Ultimate Enigma Messenger",
                  font=("Segoe UI", 18, "bold"),
                  bootstyle="inverse-primary").pack(pady=(0, 10))

        # Version
        ttkb.Label(f, text="Version 2.0 – Chaiphile",
                  font=("Segoe UI", 10),
                  bootstyle="inverse-secondary").pack(pady=(0, 15))

        # Description
        desc = ("Hybrid Encryption (AES‑GCM + RSA‑OAEP)\n"
                "Time‑based symmetric keys • File encryption • Digital signatures")
        ttkb.Label(f, text=desc,
                  font=("Segoe UI", 9),
                  justify="center",
                  bootstyle="inverse-secondary").pack(pady=(0, 25))

        # Privacy pledge
        ttkb.Label(f, text="🔐 Your privacy is our priority.",
                  font=("Segoe UI", 10),
                  bootstyle="inverse-success").pack()

        # ── Backup section ──────────────────────────────────────
        sep = ttkb.Separator(f, orient="horizontal")
        sep.pack(fill="x", pady=(25, 15))

        ttkb.Label(f, text="Database Backup",
                  font=("Segoe UI", 12, "bold"),
                  bootstyle="inverse-primary").pack(pady=(0, 10))

        btn_frame = ttkb.Frame(f)
        btn_frame.pack()

        export_btn = ttkb.Button(btn_frame, text="📤 Export Backup",
                                 command=self._export_backup,
                                 bootstyle="warning",
                                 width=18)
        export_btn.pack(side=tk.LEFT, padx=8)
        ToolTip(export_btn, "صدور پشتیبان از همه کلیدها و تنظیمات")
        import_btn = ttkb.Button(btn_frame, text="📥 Import Backup",
                                 command=self._import_backup,
                                 bootstyle="danger",
                                 width=18)
        import_btn.pack(side=tk.LEFT, padx=8)
        ToolTip(import_btn, "وارد کردن پشتیبان و بازیابی کلیدها و تنظیمات")

        # ── Password Change section ───────────────────────────────
        sep2 = ttkb.Separator(f, orient="horizontal")
        sep2.pack(fill="x", pady=(25, 15))

        ttkb.Label(f, text="Security",
                  font=("Segoe UI", 12, "bold"),
                  bootstyle="inverse-primary").pack(pady=(0, 10))

        change_pw_btn = ttkb.Button(f, text="🔑 Change Master Password",
                                    command=self._change_password,
                                    bootstyle="info",
                                    width=24)
        change_pw_btn.pack(pady=(0, 5))
        ToolTip(change_pw_btn, "تغییر رمز عبور اصلی برنامه")
        duress_btn = ttkb.Button(f, text="🚨 Set Duress Password",
                                 command=self._set_duress_password,
                                 bootstyle="danger-outline",
                                 width=24)
        duress_btn.pack(pady=(0, 5))
        ToolTip(duress_btn, "تنظیم رمز عبور اجباری برای شرایط اضطرار")

    # ------------------------------------------------------------------
    # Change Password
    # ------------------------------------------------------------------
    def _change_password(self) -> None:
        """Delegate to the auth controller's password change handler."""
        self.auth_controller.change_password()

    # ------------------------------------------------------------------
    # Duress Password
    # ------------------------------------------------------------------
    def _set_duress_password(self) -> None:
        """Delegate to the auth controller's duress password setup handler."""
        self.auth_controller.set_duress_password()

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def _export_backup(self) -> None:
        pw = password_dialog(self.frame.winfo_toplevel(),
                             "Enter Master Password (Export)", confirm=False)
        if not pw:
            return

        try:
            data = self._backup_service.export_backup(pw)
        except BackupServiceError as exc:
            messagebox.showerror("صادرات ناموفق", str(exc))
            return

        path = filedialog.asksaveasfilename(
            title="ذخیره پشتیبان",
            defaultextension=".enigma-backup",
            filetypes=[("Enigma Backup", "*.enigma-backup"), ("All Files", "*.*")],
            initialfile="enigma_backup.enigma-backup",
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=True)
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            messagebox.showinfo("موفقیت", f"پشتیبان به مسیر زیر صادر شد:\n{path}")
        except OSError as exc:
            messagebox.showerror("صادرات ناموفق", f"نمی‌توان فایل را نوشت: {exc}")

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------
    def _import_backup(self) -> None:
        path = filedialog.askopenfilename(
            title="Open Backup",
            filetypes=[("Enigma Backup", "*.enigma-backup"), ("All Files", "*.*")],
        )
        if not path:
            return

        confirm = messagebox.askyesno(
            "تأیید واردات",
            "⚠️  این کار همه کلیدها، دوستان و تنظیمات فعلی را جایگزین خواهد کرد.\n\n"
            "این عمل قابل بازگشت نیست.\n\nادامه می‌دهید؟",
            icon="warning",
        )
        if not confirm:
            return

        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            messagebox.showerror("واردات ناموفق", f"نمی‌توان فایل پشتیبان را خواند: {exc}")
            return

        pw = password_dialog(self.frame.winfo_toplevel(),
                             "Enter Master Password (Import)", confirm=False)
        if not pw:
            return

        try:
            self._backup_service.import_backup(data, pw)
            messagebox.showinfo(
                "موفقیت",
                "پشتیبان با موفقیت وارد شد.\nکلیدها و دوستان بازیابی شدند.",
            )
        except BackupServiceError as exc:
            messagebox.showerror("واردات ناموفق", str(exc))
