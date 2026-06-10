"""About tab with backup export/import."""

import json
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttkb
from ttkbootstrap.constants import *

from services.backup_service import BackupService, BackupServiceError
from utils import password_dialog


class AboutTab:
    def __init__(self, parent, app):
        self.app = app
        self.frame = ttkb.Frame(parent)
        self._backup_service = BackupService(app.ks)
        self._build_ui()

    def _build_ui(self):
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

        ttkb.Button(btn_frame, text="📤 Export Backup",
                   command=self._export_backup,
                   bootstyle="warning",
                   width=18).pack(side=tk.LEFT, padx=8)

        ttkb.Button(btn_frame, text="📥 Import Backup",
                   command=self._import_backup,
                   bootstyle="danger",
                   width=18).pack(side=tk.LEFT, padx=8)

        # ── Password Change section ───────────────────────────────
        sep2 = ttkb.Separator(f, orient="horizontal")
        sep2.pack(fill="x", pady=(25, 15))

        ttkb.Label(f, text="Security",
                  font=("Segoe UI", 12, "bold"),
                  bootstyle="inverse-primary").pack(pady=(0, 10))

        ttkb.Button(f, text="🔑 Change Master Password",
                   command=self._change_password,
                   bootstyle="info",
                   width=24).pack(pady=(0, 5))

    # ------------------------------------------------------------------
    # Change Password
    # ------------------------------------------------------------------
    def _change_password(self):
        """Delegate to the app's password change handler."""
        self.app._change_password()

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def _export_backup(self):
        pw = password_dialog(self.frame.winfo_toplevel(),
                             "Enter Master Password (Export)", confirm=False)
        if not pw:
            return

        try:
            data = self._backup_service.export_backup(pw)
        except BackupServiceError as exc:
            messagebox.showerror("Export Failed", str(exc))
            return

        path = filedialog.asksaveasfilename(
            title="Save Backup",
            defaultextension=".enigma-backup",
            filetypes=[("Enigma Backup", "*.enigma-backup"), ("All Files", "*.*")],
            initialfile="enigma_backup.enigma-backup",
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=True)
            messagebox.showinfo("Success", f"Backup exported to:\n{path}")
        except OSError as exc:
            messagebox.showerror("Export Failed", f"Could not write file: {exc}")

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------
    def _import_backup(self):
        path = filedialog.askopenfilename(
            title="Open Backup",
            filetypes=[("Enigma Backup", "*.enigma-backup"), ("All Files", "*.*")],
        )
        if not path:
            return

        confirm = messagebox.askyesno(
            "Confirm Import",
            "⚠️  This will REPLACE all current keys, friends, and settings.\n\n"
            "This action cannot be undone.\n\nContinue?",
            icon="warning",
        )
        if not confirm:
            return

        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            messagebox.showerror("Import Failed", f"Cannot read backup file: {exc}")
            return

        pw = password_dialog(self.frame.winfo_toplevel(),
                             "Enter Master Password (Import)", confirm=False)
        if not pw:
            return

        try:
            self._backup_service.import_backup(data, pw)
            messagebox.showinfo(
                "Success",
                "Backup imported successfully.\nKeys and friends have been restored.",
            )
        except BackupServiceError as exc:
            messagebox.showerror("Import Failed", str(exc))