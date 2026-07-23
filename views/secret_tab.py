"""Shared Secret & ECDH tab – decoupled via dependency injection."""

import tkinter as tk
from tkinter import messagebox, simpledialog
import ttkbootstrap as ttk

from services.global_secret_service import GlobalSecretService, GlobalSecretServiceError
from services.clipboard_service import ClipboardService
from views.dialogs import password_dialog
from views.utils import init_modal


class SecretTab:
    def __init__(self, parent: tk.Widget, global_secret_service: GlobalSecretService,
                 clipboard_service: ClipboardService) -> None:
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

    def _build_ui(self) -> None:
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

    def _update_display(self) -> None:
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
        if not self.service.verify_master_password(pw):
            messagebox.showerror("رمز عبور اشتباه", "رمز عبور اصلی نادرست است.")
            return None
        return pw

    def export_global(self) -> None:
        if not self.service.has_secret():
            messagebox.showwarning("بدون رمز", "هیچ رمز سراسری در دسترس نیست.")
            return
        if not messagebox.askyesno("هشدار", "این کار رمز اشتراکی خام سراسری شما را نمایش می‌دهد. ادامه می‌دهید؟"):
            return
        try:
            b64 = self.service.export_secret_b64()
            ok = self.clipboard_service.copy(b64)
            if ok:
                messagebox.showinfo(
                    "صادر شد",
                    "رمز اشتراکی سراسری در کلیپ‌بورد کپی شد.\n"
                    "کلیپ‌بورد به‌طور خودکار در ۳۰ ثانیه پاک می‌شود."
                )
            else:
                messagebox.showerror("خطای کلیپ‌بورد", "دسترسی به کلیپ‌بورد امکان‌پذیر نیست.")
        except GlobalSecretServiceError as e:
            from views.utils import friendly_error
            messagebox.showerror("خطا", friendly_error(e))

    def import_global(self) -> None:
        from views.dialogs import password_dialog
        from views.utils import init_modal
        from crypto import sha256_fingerprint

        parent = self.frame.winfo_toplevel()
        dlg = tk.Toplevel(parent)
        dlg.title("Import Global Secret")
        dlg.geometry("450x200")
        dlg.resizable(False, False)

        ttk.Label(dlg, text="Paste the Base64 secret your friend shared:",
                  font=("Segoe UI", 10),
                  bootstyle="inverse-primary").pack(pady=(15, 5), padx=15, anchor=tk.W)

        b64_var = tk.StringVar()
        b64_entry = ttk.Entry(dlg, textvariable=b64_var, width=50)
        b64_entry.pack(padx=15, pady=5)

        result = {"secret": None}

        def submit():
            b64 = b64_var.get().strip()
            if not b64:
                messagebox.showerror("الزامی", "لطفاً رمز Base64 را جای‌گذاری کنید.", parent=dlg)
                return

            try:
                new_key = self.service.validate_secret_b64(b64)
            except ValueError as e:
                messagebox.showerror("نامعتبر", str(e), parent=dlg)
                return

            fp = sha256_fingerprint(new_key)

            ok = messagebox.askyesno(
                "⚠️ جایگزینی رمز سراسری",
                f"اثر انگشت رمز جدید:\n{fp}\n\n"
                "هشدار: این کار رمز سراسری فعلی را برای همیشه جایگزین می‌کند.\n"
                "همه پیام‌های رمزنگاری‌شده با رمز قدیمی غیرقابل خواندن خواهند شد.\n"
                "مطمئن شوید که رمز جدید را با مخاطبان مورد اعتماد به اشتراک گذاشته‌اید.\n\n"
                "رمز سراسری فعلی جایگزین شود؟",
                parent=dlg
            )
            if not ok:
                return

            pw = self._verify_master_password()
            if not pw:
                return

            try:
                self.service.update_secret(new_key, pw)
                self._update_display()
                dlg.destroy()
                messagebox.showinfo("موفقیت", "رمز اشتراکی سراسری به‌روز شد.")
            except GlobalSecretServiceError as e:
                from views.utils import friendly_error
                messagebox.showerror("خطا", friendly_error(e), parent=dlg)

        ttk.Button(dlg, text="Submit", command=submit, bootstyle="success").pack(pady=(15, 5))
        ttk.Button(dlg, text="Cancel", command=dlg.destroy, bootstyle="secondary-outline").pack(pady=5)

        init_modal(dlg, parent, focus_widget=b64_entry)
        parent.wait_window(dlg)

    def start_ecdh(self) -> None:
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
                    messagebox.showinfo("موفقیت", "رمز سراسری از طریق ECDH به‌روز شد.")
                except GlobalSecretServiceError as e:
                    messagebox.showerror("خطا", str(e))
