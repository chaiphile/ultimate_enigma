"""Shared Secret & ECDH tab – decoupled via dependency injection."""

import tkinter as tk
from tkinter import messagebox, simpledialog
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

from services.global_secret_service import GlobalSecretService, GlobalSecretServiceError
from services.clipboard_service import ClipboardService
from views.utils import password_dialog


class SecretTab:
    def __init__(self, parent, global_secret_service: GlobalSecretService,
                 clipboard_service: ClipboardService):
        """
        Args:
            parent: Notebook widget
            global_secret_service: Handles global secret operations
            clipboard_service: Handles clipboard operations
        """
        self.service = global_secret_service
        self.clipboard_service = clipboard_service
        self.frame = ttk.Frame(parent)
        self._build_ui()

    def _build_ui(self):
        f = ttk.Frame(self.frame, padding=(20, 20))
        f.pack(expand=True, fill=tk.BOTH)

        # Fingerprint display
        ttk.Label(f, text="Current Global Shared Secret Fingerprint:",
                  font=("Segoe UI", 10, "bold"),
                  bootstyle="inverse-primary").pack(anchor=tk.W, pady=(0, 5))

        self.secret_fp_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.secret_fp_var, width=50,
                  state='readonly', bootstyle="secondary").pack(anchor=tk.W, pady=(0, 15))

        # Export / Import buttons
        ttk.Button(f, text="Export Global Secret (Copy)", command=self.export_global,
                   bootstyle="secondary-outline").pack(anchor=tk.W, pady=5)
        ttk.Button(f, text="Import Global Secret", command=self.import_global,
                   bootstyle="secondary-outline").pack(anchor=tk.W, pady=5)

        # Separator
        ttk.Separator(f, orient='horizontal', bootstyle="secondary").pack(fill=tk.X, pady=15)

        # ECDH section
        ttk.Label(f, text="ECDH Key Exchange", font=("Segoe UI", 10, "bold"),
                  bootstyle="inverse-primary").pack(anchor=tk.W, pady=(0, 5))
        ttk.Button(f, text="Start ECDH for Global Secret", command=self.start_ecdh,
                   bootstyle="info").pack(anchor=tk.W, pady=5)

        self._update_display()

    def _update_display(self):
        fp = self.service.get_fingerprint()
        if fp:
            self.secret_fp_var.set(fp)
        else:
            self.secret_fp_var.set("No global secret loaded")

    def _verify_master_password(self):
        """Prompt for password and verify via service."""
        parent = self.frame.winfo_toplevel()
        pw = password_dialog(parent, "Enter master password", confirm=False)
        if not pw:
            return None
        if not self.service.verify_password(pw):
            messagebox.showerror("Wrong Password", "Master password incorrect.")
            return None
        return pw

    def export_global(self):
        if not self.service.has_secret():
            messagebox.showwarning("No Secret", "No global secret available.")
            return
        if not messagebox.askyesno("Warning", "This will expose your raw global shared secret. Continue?"):
            return
        try:
            b64 = self.service.export_secret_b64()
            ok = self.clipboard_service.copy(b64)
            if ok:
                messagebox.showinfo(
                    "Exported",
                    "Global shared secret copied to clipboard.\n"
                    "Clipboard will be cleared automatically in 30 seconds."
                )
            else:
                messagebox.showerror("Clipboard Error", "Could not access clipboard.")
        except GlobalSecretServiceError as e:
            messagebox.showerror("Error", str(e))

    def import_global(self):
        b64 = simpledialog.askstring("Import Global Secret", "Paste Base64 shared secret:")
        if not b64:
            return
        
        try:
            new_key = self.service.validate_secret_b64(b64)
        except ValueError as e:
            messagebox.showerror("Invalid", str(e))
            return
            
        from crypto import sha256_fingerprint
        fp = sha256_fingerprint(new_key)
        
        ok = messagebox.askyesno(
            "⚠️ Replace Global Secret",
            f"New secret fingerprint:\n{fp}\n\n"
            "WARNING: This will permanently replace the current global secret.\n"
            "All messages encrypted with the OLD secret will become UNREADABLE.\n"
            "Make sure you have shared the new secret with trusted contacts.\n\n"
            "Replace current global secret?"
        )
        if not ok:
            return
            
        pw = self._verify_master_password()
        if not pw:
            return
            
        try:
            self.service.update_secret(new_key, pw)
            self._update_display()
            messagebox.showinfo("Success", "Global shared secret updated.")
        except GlobalSecretServiceError as e:
            messagebox.showerror("Error", str(e))

    def start_ecdh(self):
        from views.ecdh import perform_ecdh
        parent = self.frame.winfo_toplevel()
        result = perform_ecdh(parent, purpose="global")
        if result:
            new_key = result[0]
            pw = self._verify_master_password()
            if pw:
                try:
                    self.service.update_secret(new_key, pw)
                    self._update_display()
                    messagebox.showinfo("Success", "Global secret updated via ECDH.")
                except GlobalSecretServiceError as e:
                    messagebox.showerror("Error", str(e))
