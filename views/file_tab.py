"""
File encryption/decryption tab.
Now delegates all cryptographic logic to `FileService`.
"""

import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
import threading
from queue import Queue

from views.utils import password_dialog
from services.file_service import FileServiceError, SharedSecretDetected
from services.friends import FriendsService
from services.global_secret_service import GlobalSecretService
from services.crypto_task_queue import TaskPriority
from src.exceptions import CryptoTimeoutError


class FileTab:
    def __init__(self, parent: tk.Widget, file_service, friends_service: FriendsService,
                 global_secret_service: GlobalSecretService, root: tk.Tk, task_queue: Queue,
                 crypto_queue=None) -> None:
        """
        Args:
            parent: Notebook widget
            file_service: Handles file encryption/decryption
            friends_service: Provides friend data
            global_secret_service: Checks global secret availability
            root: Tkinter root for dialogs
            task_queue: Queue for scheduling UI updates from background threads
            crypto_queue: Optional CryptoTaskQueue for managed background execution.
        """
        self.file_service = file_service
        self.friends_service = friends_service
        self.global_secret_service = global_secret_service
        self.root = root
        self.task_queue = task_queue
        self.crypto_queue = crypto_queue
        self.frame = ttk.Frame(parent)

        # UI state
        self.method_var = tk.StringVar(value="password")
        self.friend_var = tk.StringVar()
        self.sign_var = tk.BooleanVar(value=False)

        self._build_ui()

    def _build_ui(self) -> None:
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

    def _update_friend_list(self) -> None:
        """Refresh the friend dropdown from the FriendsService."""
        names = self.friends_service.get_friend_names()
        self.friend_combo['values'] = names
        if names:
            self.friend_combo.current(0)
        else:
            self.friend_combo.set("")

    def refresh_list(self) -> None:
        """Called when the tab is selected to refresh the friend dropdown."""
        self._update_friend_list()

    def _on_method_change(self, *args) -> None:
        if self.method_var.get() == "friend":
            self.friend_combo.config(state="readonly")
        else:
            self.friend_combo.config(state="disabled")

    # ===================== ENCRYPT =====================
    def encrypt_file(self) -> None:
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
            pw = password_dialog(self.root, "File Encryption Password", confirm=False)
            if not pw:
                return
            password = pw
        elif method == "global":
            if not self.global_secret_service.has_secret():
                messagebox.showerror("Error", "Global shared secret is not available.")
                return
            desc = "Global Shared Secret"
        else:  # friend
            friend_name = self.friend_var.get()
            if not friend_name:
                messagebox.showwarning("No Friend", "Please select a friend.")
                return
            if not self.friends_service.friend_has_secret(friend_name):
                messagebox.showerror("Error", f"No shared secret for {friend_name}.")
                return
            desc = f"Friend's Secret ({friend_name})"

        if not messagebox.askyesno("Confirm Encryption Method",
                                   f"You are about to encrypt with:\n{desc}\n\nProceed?"):
            return

        def _do_encrypt():
            """Perform the actual file encryption (runs in worker thread)."""
            self.file_service.encrypt_file(
                input_path=infile,
                output_path=outfile,
                method=method,
                password=password,
                friend_name=friend_name,
                sign=sign,
            )
            return outfile

        def _on_success(result_path):
            """Handle successful encryption (runs on main thread)."""
            messagebox.showinfo("Success", f"File encrypted:\n{result_path}")

        def _on_error(exc):
            """Handle encryption error (runs on main thread)."""
            if isinstance(exc, CryptoTimeoutError):
                messagebox.showerror(
                    "Timeout",
                    "File encryption timed out. The file may be too large or "
                    "the system is under heavy load. Please try again."
                )
            else:
                messagebox.showerror("Encryption Error", str(exc))

        # Use CryptoTaskQueue if available, otherwise fall back to raw threading
        if self.crypto_queue is not None:
            from src.constants import CONCURRENCY_CONSTANTS
            self.crypto_queue.submit(
                _do_encrypt,
                on_success=_on_success,
                on_error=_on_error,
                priority=TaskPriority.NORMAL,
                timeout=CONCURRENCY_CONSTANTS.get("FILE_OPERATION_TIMEOUT", 300.0),
            )
        else:
            def task():
                try:
                    _do_encrypt()
                    self.task_queue.put(
                        lambda: messagebox.showinfo("Success", f"File encrypted:\n{outfile}")
                    )
                except FileServiceError as e:
                    self.task_queue.put(
                        lambda e=e: messagebox.showerror("Encryption Error", str(e))
                    )

            threading.Thread(target=task, daemon=True).start()

    # ===================== DECRYPT =====================
    def decrypt_file(self) -> None:
        infile = filedialog.askopenfilename(title="Select encrypted file")
        if not infile:
            return
        outfile = filedialog.asksaveasfilename(title="Save decrypted file as")
        if not outfile:
            return

        def _do_decrypt():
            """Attempt decryption (runs in worker thread)."""
            return self.file_service.decrypt_file(
                input_path=infile,
                output_path=outfile,
                password=None,
            )

        def _on_success(sig_msg):
            self._show_result(outfile, sig_msg)

        def _on_error(exc):
            if isinstance(exc, CryptoTimeoutError):
                messagebox.showerror(
                    "Timeout",
                    "File decryption timed out. The file may be too large or "
                    "the system is under heavy load. Please try again."
                )
            elif isinstance(exc, SharedSecretDetected):
                self._handle_shared_detected(infile, outfile, exc)
            elif isinstance(exc, FileServiceError):
                if "password required" in str(exc).lower():
                    self._prompt_password_and_decrypt(infile, outfile)
                else:
                    messagebox.showerror("Decryption Error", str(exc))
            else:
                messagebox.showerror("Decryption Error", str(exc))

        if self.crypto_queue is not None:
            from src.constants import CONCURRENCY_CONSTANTS
            self.crypto_queue.submit(
                _do_decrypt,
                on_success=_on_success,
                on_error=_on_error,
                priority=TaskPriority.NORMAL,
                timeout=CONCURRENCY_CONSTANTS.get("FILE_OPERATION_TIMEOUT", 300.0),
            )
        else:
            def task():
                try:
                    sig_msg = _do_decrypt()
                    self.task_queue.put(lambda: self._show_result(outfile, sig_msg))
                except SharedSecretDetected as e:
                    self.task_queue.put(lambda: self._handle_shared_detected(infile, outfile, e))
                except FileServiceError as e:
                    if "password required" in str(e).lower():
                        self.task_queue.put(lambda: self._prompt_password_and_decrypt(infile, outfile))
                    else:
                        self.task_queue.put(lambda: messagebox.showerror("Decryption Error", str(e)))

            threading.Thread(target=task, daemon=True).start()

    def _handle_shared_detected(self, infile: str, outfile: str, detection: SharedSecretDetected) -> None:
        """Ask user if they want to decrypt using the detected shared secret."""
        ok = messagebox.askyesno(
            "Shared Secret Detected",
            f"This file appears to be encrypted with the shared secret of '{detection.owner}'.\n\n"
            "Do you want to decrypt it using that shared secret?"
        )
        if not ok:
            return

        def _do_decrypt_shared():
            return self.file_service.decrypt_with_shared_secret(
                infile, outfile, detection.fingerprint
            )

        def _on_success(sig_msg):
            self._show_result(outfile, sig_msg)

        def _on_error(exc):
            if isinstance(exc, CryptoTimeoutError):
                messagebox.showerror("Timeout", "File decryption timed out.")
            else:
                messagebox.showerror("Decryption Error", str(exc))

        if self.crypto_queue is not None:
            from src.constants import CONCURRENCY_CONSTANTS
            self.crypto_queue.submit(
                _do_decrypt_shared,
                on_success=_on_success,
                on_error=_on_error,
                priority=TaskPriority.NORMAL,
                timeout=CONCURRENCY_CONSTANTS.get("FILE_OPERATION_TIMEOUT", 300.0),
            )
        else:
            def task():
                try:
                    sig_msg = _do_decrypt_shared()
                    self.task_queue.put(lambda: self._show_result(outfile, sig_msg))
                except FileServiceError as e:
                    self.task_queue.put(lambda: messagebox.showerror("Decryption Error", str(e)))

            threading.Thread(target=task, daemon=True).start()

    def _prompt_password_and_decrypt(self, infile: str, outfile: str) -> None:
        """Prompt for a password and attempt decryption."""
        pw = password_dialog(self.root, "File Decryption Password", confirm=False)
        if not pw:
            return

        def _do_decrypt_pw():
            return self.file_service.decrypt_file(
                input_path=infile,
                output_path=outfile,
                password=pw,
            )

        def _on_success(sig_msg):
            self._show_result(outfile, sig_msg)

        def _on_error(exc):
            if isinstance(exc, CryptoTimeoutError):
                messagebox.showerror("Timeout", "File decryption timed out.")
            else:
                messagebox.showerror("Decryption Error", str(exc))

        if self.crypto_queue is not None:
            from src.constants import CONCURRENCY_CONSTANTS
            self.crypto_queue.submit(
                _do_decrypt_pw,
                on_success=_on_success,
                on_error=_on_error,
                priority=TaskPriority.NORMAL,
                timeout=CONCURRENCY_CONSTANTS.get("FILE_OPERATION_TIMEOUT", 300.0),
            )
        else:
            def task():
                try:
                    sig_msg = _do_decrypt_pw()
                    self.task_queue.put(lambda: self._show_result(outfile, sig_msg))
                except FileServiceError as e:
                    self.task_queue.put(lambda: messagebox.showerror("Decryption Error", str(e)))

            threading.Thread(target=task, daemon=True).start()

    def _show_result(self, outfile: str, sig_msg: str) -> None:
        msg = f"File decrypted:\n{outfile}"
        if sig_msg:
            msg += f"\n\n{sig_msg}"
        messagebox.showinfo("Success", msg)