"""
File encryption/decryption tab.
Now delegates all cryptographic logic to `FileService`.
"""

import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import threading

from utils import password_dialog
from services.file_service import FileServiceError, SharedSecretDetected


class FileTab:
    def __init__(self, parent, app, file_service):
        self.app = app
        self.file_service = file_service
        self.frame = ttk.Frame(parent)

        # UI state
        self.method_var = tk.StringVar(value="password")
        self.friend_var = tk.StringVar()
        self.sign_var = tk.BooleanVar(value=False)

        self._build_ui()

    def _build_ui(self):
        # Encryption method selection
        opt_frame = ttk.Labelframe(self.frame, text="Encryption Method",
                                   bootstyle="info", padding=(10, 5))
        opt_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        ttk.Radiobutton(opt_frame, text="Password", variable=self.method_var,
                        value="password", command=self._on_method_change,
                        bootstyle="toolbutton").pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Radiobutton(opt_frame, text="Global Shared Secret", variable=self.method_var,
                        value="global", command=self._on_method_change,
                        bootstyle="toolbutton").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(opt_frame, text="Friend's Shared Secret", variable=self.method_var,
                        value="friend", command=self._on_method_change,
                        bootstyle="toolbutton").pack(side=tk.LEFT, padx=5)

        # Friend dropdown (active only for friend method)
        self.friend_frame = ttk.Frame(opt_frame)
        self.friend_frame.pack(side=tk.LEFT, padx=10)
        ttk.Label(self.friend_frame, text="Friend:").pack(side=tk.LEFT)
        self.friend_combo = ttk.Combobox(self.friend_frame,
                                         textvariable=self.friend_var,
                                         state="readonly", width=15,
                                         bootstyle="primary")
        self.friend_combo.pack(side=tk.LEFT, padx=5)
        self._update_friend_list()

        # Signature option
        self.sign_check = ttk.Checkbutton(opt_frame, text="Sign with my private key",
                                          variable=self.sign_var,
                                          bootstyle="round-toggle")
        self.sign_check.pack(side=tk.RIGHT, padx=10)

        self._on_method_change()

        # Big buttons
        btn_frame = ttk.Frame(self.frame, padding=(10, 20))
        btn_frame.pack(expand=True)

        ttk.Button(btn_frame, text="🔒 Encrypt a File", command=self.encrypt_file,
                   bootstyle="success", width=20).pack(pady=10, ipadx=20, ipady=10)
        ttk.Button(btn_frame, text="🔓 Decrypt a File", command=self.decrypt_file,
                   bootstyle="primary", width=20).pack(pady=10, ipadx=20, ipady=10)

    def _update_friend_list(self):
        names = [name for name, _, sec in self.app.ks.friends if sec is not None]
        self.friend_combo['values'] = names
        if names:
            self.friend_combo.current(0)

    def _on_method_change(self, *args):
        if self.method_var.get() == "friend":
            self.friend_combo.config(state="readonly")
        else:
            self.friend_combo.config(state="disabled")

    # ===================== ENCRYPT =====================
    def encrypt_file(self):
        infile = filedialog.askopenfilename(title="Select file to encrypt")
        if not infile:
            return
        outfile = filedialog.asksaveasfilename(title="Save encrypted file as",
                                               defaultextension=".enc")
        if not outfile:
            return

        method = self.method_var.get()
        sign = self.sign_var.get()

        friend_name = None
        password = None

        if method == "password":
            desc = "Password"
            pw = password_dialog(self.app.root, "File Encryption Password", confirm=False)
            if not pw:
                return
            password = pw
        elif method == "global":
            if not self.app.ks.global_secret:
                messagebox.showerror("Error", "Global shared secret is not available.")
                return
            desc = "Global Shared Secret"
        else:  # friend
            friend_name = self.friend_var.get()
            if not friend_name:
                messagebox.showwarning("No Friend", "Please select a friend.")
                return
            if not self.app.ks.get_friend_secret(friend_name):
                messagebox.showerror("Error", f"No shared secret for {friend_name}.")
                return
            desc = f"Friend's Secret ({friend_name})"

        if not messagebox.askyesno("Confirm Encryption Method",
                                   f"You are about to encrypt with:\n{desc}\n\nProceed?"):
            return

        def task():
            try:
                self.file_service.encrypt_file(
                    input_path=infile,
                    output_path=outfile,
                    method=method,
                    password=password,
                    friend_name=friend_name,
                    sign=sign,
                )
                self.app.task_queue.put(
                    lambda: messagebox.showinfo("Success", f"File encrypted:\n{outfile}")
                )
            except FileServiceError as e:
                self.app.task_queue.put(
                    lambda e=e: messagebox.showerror("Encryption Error", str(e))
                )

        threading.Thread(target=task, daemon=True).start()

    # ===================== DECRYPT =====================
    def decrypt_file(self):
        infile = filedialog.askopenfilename(title="Select encrypted file")
        if not infile:
            return
        outfile = filedialog.asksaveasfilename(title="Save decrypted file as")
        if not outfile:
            return

        def task():
            try:
                # Try decryption without password first – the service will raise if password needed
                sig_msg = self.file_service.decrypt_file(
                    input_path=infile,
                    output_path=outfile,
                    password=None,  # let the service decide
                )
                self.app.task_queue.put(lambda: self._show_result(outfile, sig_msg))
            except SharedSecretDetected as e:
                # A shared secret was detected – ask the user
                self.app.task_queue.put(lambda: self._handle_shared_detected(infile, outfile, e))
            except FileServiceError as e:
                # If the error says "Password required", we prompt the user for a password
                if "password required" in str(e).lower():
                    self.app.task_queue.put(lambda: self._prompt_password_and_decrypt(infile, outfile))
                else:
                    self.app.task_queue.put(lambda: messagebox.showerror("Decryption Error", str(e)))

        threading.Thread(target=task, daemon=True).start()

    def _handle_shared_detected(self, infile, outfile, detection: SharedSecretDetected):
        """Ask user if they want to decrypt using the detected shared secret."""
        ok = messagebox.askyesno(
            "Shared Secret Detected",
            f"This file appears to be encrypted with the shared secret of '{detection.owner}'.\n\n"
            "Do you want to decrypt it using that shared secret?"
        )
        if not ok:
            return

        def task():
            try:
                sig_msg = self.file_service.decrypt_with_shared_secret(
                    infile, outfile, detection.fingerprint
                )
                self.app.task_queue.put(lambda: self._show_result(outfile, sig_msg))
            except FileServiceError as e:
                self.app.task_queue.put(lambda: messagebox.showerror("Decryption Error", str(e)))

        threading.Thread(target=task, daemon=True).start()

    def _prompt_password_and_decrypt(self, infile, outfile):
        """Prompt for a password and attempt decryption."""
        pw = password_dialog(self.app.root, "File Decryption Password", confirm=False)
        if not pw:
            return

        def task():
            try:
                sig_msg = self.file_service.decrypt_file(
                    input_path=infile,
                    output_path=outfile,
                    password=pw,
                )
                self.app.task_queue.put(lambda: self._show_result(outfile, sig_msg))
            except FileServiceError as e:
                self.app.task_queue.put(lambda: messagebox.showerror("Decryption Error", str(e)))

        threading.Thread(target=task, daemon=True).start()

    def _show_result(self, outfile, sig_msg):
        msg = f"File decrypted:\n{outfile}"
        if sig_msg:
            msg += f"\n\n{sig_msg}"
        messagebox.showinfo("Success", msg)