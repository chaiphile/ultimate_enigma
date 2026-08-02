"""
File encryption/decryption tab.
Now delegates all cryptographic logic to `FileService`.
"""

import logging
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
import threading
from pathlib import Path
from queue import Queue

from views.dialogs import password_dialog
from views.utils import friendly_error, ToolTip, flash_widget_text
from services.file_service import FileServiceError, SharedSecretDetected
from services.friends import FriendsService
from services.global_secret_service import GlobalSecretService
from services.crypto_task_queue import TaskPriority
from src.constants import CONCURRENCY_CONSTANTS
from src.exceptions import CryptoTimeoutError

# Drag & drop is optional: tkinterdnd2 may be missing or the root window may
# not support it. Importing it also injects the dnd methods onto
# tkinter.BaseWidget, so any existing root can be upgraded at runtime.
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except Exception:
    DND_FILES = None
    TkinterDnD = None

logger = logging.getLogger(__name__)

# Windows has a 260-char default path limit; other platforms allow much longer.
_MAX_PATH_LEN = 260 if sys.platform == "win32" else 4096


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

        self._dnd_active = False

        self._build_ui()
        self._setup_dnd()

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

        # File selection: browse, paste a path, or drag & drop
        select_frame = ttk.Labelframe(self.frame, text="Select File",
                                      bootstyle="info", padding=(10, 5))
        select_frame.pack(fill=tk.X, padx=10, pady=(5, 0))

        row = ttk.Frame(select_frame)
        row.pack(fill=tk.X)
        self.file_var = tk.StringVar()
        self.file_entry = ttk.Entry(row, textvariable=self.file_var,
                                    state="readonly")
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.browse_btn = ttk.Button(row, text="Browse...",
                                     command=self._browse_file,
                                     bootstyle="secondary-outline")
        self.browse_btn.pack(side=tk.LEFT, padx=(0, 5))
        ToolTip(self.browse_btn, "Choose a file to encrypt or decrypt")
        self.paste_btn = ttk.Button(row, text="Paste File Path",
                                    command=self._paste_file_path,
                                    bootstyle="secondary-outline")
        self.paste_btn.pack(side=tk.LEFT)
        ToolTip(self.paste_btn, "Select a file by pasting its full path")

        self.dnd_hint = ttk.Label(select_frame,
                                  text="Tip: use Browse or Paste File Path to select a file",
                                  bootstyle="secondary")
        self.dnd_hint.pack(anchor=tk.W, pady=(3, 0))

        # Big buttons
        btn_frame = ttk.Frame(self.frame, padding=(10, 20))
        btn_frame.pack(expand=True)

        self.encrypt_btn = ttk.Button(btn_frame, text="🔒 Encrypt File",
                                      command=self.encrypt_file,
                                      bootstyle="success", width=20)
        self.encrypt_btn.pack(pady=10, ipadx=20, ipady=10)
        ToolTip(self.encrypt_btn, "Encrypt a file using the selected method")
        self.decrypt_btn = ttk.Button(btn_frame, text="🔓 Decrypt File",
                                      command=self.decrypt_file,
                                      bootstyle="primary", width=20)
        self.decrypt_btn.pack(pady=10, ipadx=20, ipady=10)
        ToolTip(self.decrypt_btn, "Decrypt a previously encrypted file")

    def _set_busy(self, busy: bool) -> None:
        try:
            state = "disabled" if busy else "normal"
            self.encrypt_btn.configure(state=state)
            self.decrypt_btn.configure(state=state)
            self.browse_btn.configure(state=state)
            self.paste_btn.configure(state=state)
            self.root.configure(cursor="watch" if busy else "")
        except Exception:
            pass

    # ===================== FILE SELECTION =====================
    def _setup_dnd(self) -> None:
        """Attach OS drag & drop to the toplevel window, degrading silently."""
        if DND_FILES is None or TkinterDnD is None:
            self._dnd_active = False
            return
        try:
            toplevel = self.frame.winfo_toplevel()
            TkinterDnD._require(toplevel)
            toplevel.drop_target_register(DND_FILES)
            toplevel.dnd_bind("<<Drop>>", self._on_drop)
            self._dnd_active = True
        except Exception:
            logger.debug("Drag & drop unavailable", exc_info=True)
            self._dnd_active = False
        if self._dnd_active:
            self.dnd_hint.configure(
                text="Tip: drag & drop a file anywhere in this window to select it")
        else:
            self.dnd_hint.configure(
                text="Tip: use Browse or Paste File Path to select a file")

    def _on_drop(self, event: object) -> str:
        try:
            paths = self._parse_dnd_paths(str(getattr(event, "data", "") or ""))
        except Exception:
            logger.debug("Drop payload parse failed", exc_info=True)
            return "copy"
        if paths:
            self._select_file(paths[0])
        return "copy"

    @staticmethod
    def _parse_dnd_paths(data: str) -> list:
        """Extract file paths from a DND_FILES payload.

        Handles Windows curly-brace-wrapped paths, bare paths, and newline
        (CRLF) separated multi-file payloads.
        """
        paths = []
        buffer = ""
        i = 0
        n = len(data)
        while i < n:
            ch = data[i]
            if ch == "{":
                end = data.find("}", i)
                if end == -1:
                    break
                if buffer.strip():
                    paths.append(buffer.strip())
                buffer = ""
                paths.append(data[i + 1:end].replace("\\{", "{").replace("\\}", "}"))
                i = end + 1
            else:
                buffer += ch
                i += 1
        if buffer.strip():
            paths.append(buffer.strip())
        result = []
        for path in paths:
            for part in path.replace("\r\n", "\n").split("\n"):
                part = part.strip()
                if part:
                    result.append(part)
        return result

    def _browse_file(self) -> None:
        path = filedialog.askopenfilename(title="Select File")
        if not path:
            return
        self._select_file(path)

    def _paste_file_path(self) -> None:
        try:
            raw = self.root.clipboard_get()
        except Exception:
            messagebox.showerror("Clipboard Error", "Unable to read the clipboard.")
            return
        path = raw.strip().strip('"').strip("'")
        if not path:
            messagebox.showwarning("Empty Clipboard",
                                   "The clipboard does not contain a file path.")
            return
        if not os.path.exists(path):
            messagebox.showwarning("File Not Found",
                                   f"No file exists at:\n{path}")
            return
        self._select_file(path)

    def _select_file(self, filepath: str) -> None:
        cleaned = filepath.strip().strip('"').strip("'")
        if not cleaned:
            return
        try:
            path = Path(cleaned).resolve()
        except Exception:
            return
        if path.is_dir():
            messagebox.showwarning("Folder Selected",
                                   "Please select a file, not a folder.")
            return
        self.file_var.set(str(path))

    def _file_dialog_kwargs(self, title: str) -> dict:
        kwargs = {"title": title}
        selected = self.file_var.get().strip()
        if selected and os.path.isfile(selected):
            kwargs["initialdir"] = os.path.dirname(selected)
            kwargs["initialfile"] = os.path.basename(selected)
        return kwargs

    def _submit_file_task(self, do_work, on_success, on_error) -> None:
        """Run a file crypto op off-thread via the queue or a thread fallback.

        The fallback catches *all* exceptions (not just FileServiceError) so no
        failure dies silently in a daemon thread.
        """
        if self.crypto_queue is not None:
            self.crypto_queue.submit(
                do_work,
                on_success=on_success,
                on_error=on_error,
                priority=TaskPriority.NORMAL,
                timeout=CONCURRENCY_CONSTANTS.get("FILE_OPERATION_TIMEOUT", 300.0),
            )
        else:
            def task():
                try:
                    result = do_work()
                    self.task_queue.put(lambda r=result: on_success(r))
                except Exception as exc:  # noqa: BLE001 - surfaced to the user
                    self.task_queue.put(lambda e=exc: on_error(e))

            threading.Thread(target=task, daemon=True).start()

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

    # ===================== PATH VALIDATION =====================
    @staticmethod
    def _validate_path(filepath: str) -> Path:
        p = Path(filepath).resolve()
        if len(str(p)) > _MAX_PATH_LEN:
            raise ValueError(
                "The selected location's path is too long. "
                "Please choose a shorter path or folder name."
            )
        return p

    # ===================== ENCRYPT =====================
    def encrypt_file(self) -> None:
        infile = filedialog.askopenfilename(
            **self._file_dialog_kwargs("Select File to Encrypt"))
        if not infile:
            return
        try:
            self._validate_path(infile)
        except ValueError as e:
            messagebox.showerror("Invalid path", str(e))
            return
        outfile = filedialog.asksaveasfilename(title="Save Encrypted File As",
                                               defaultextension=".enc")
        if not outfile:
            return
        try:
            self._validate_path(outfile)
        except ValueError as e:
            messagebox.showerror("Invalid path", str(e))
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
                messagebox.showerror("Encryption Error", "Global shared secret is not configured.")
                return
            desc = "Global Shared Secret"
        else:  # friend
            friend_name = self.friend_var.get()
            if not friend_name:
                messagebox.showwarning("No Friend Selected", "Please select a friend.")
                return
            if not self.friends_service.friend_has_secret(friend_name):
                messagebox.showerror("Shared Secret Not Found", f"No shared secret is available for {friend_name}.")
                return
            desc = f"Friend's Secret ({friend_name})"

        if not messagebox.askyesno("Confirm Encryption",
                                   f"Encrypt using:\n{desc}\n\nProceed?"):
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

        def _on_success(result_path: str):
            """Handle successful encryption (runs on main thread)."""
            self._set_busy(False)
            flash_widget_text(self.encrypt_btn, "Encrypted ✓", "🔒 Encrypt File")
            self.refresh_list()
            messagebox.showinfo(
                "Encryption Successful",
                f"File encrypted successfully.\nYour original file was not modified.\n\nSaved to:\n{result_path}"
            )

        def _on_error(exc):
            """Handle encryption error (runs on main thread)."""
            self._set_busy(False)
            if isinstance(exc, CryptoTimeoutError):
                messagebox.showerror(
                    "Encryption Timed Out",
                    "File encryption timed out. The file may be too large or the system may be under heavy load.\n\nPlease try again."
                )
            else:
                messagebox.showerror("Encryption Error", friendly_error(exc))

        self._set_busy(True)
        self._submit_file_task(_do_encrypt, _on_success, _on_error)

    # ===================== DECRYPT =====================
    def decrypt_file(self) -> None:
        infile = filedialog.askopenfilename(
            **self._file_dialog_kwargs("Select Encrypted File"))
        if not infile:
            return
        try:
            self._validate_path(infile)
        except ValueError as e:
            messagebox.showerror("Invalid path", str(e))
            return
        # Suggest a sensible output name (strip a trailing .enc)
        suggested = os.path.basename(infile)
        if suggested.lower().endswith(".enc"):
            suggested = suggested[:-4]
        outfile = filedialog.asksaveasfilename(title="Save Decrypted File As",
                                               initialfile=suggested)
        if not outfile:
            return
        try:
            self._validate_path(outfile)
        except ValueError as e:
            messagebox.showerror("Invalid path", str(e))
            return

        def _do_decrypt():
            """Attempt decryption (runs in worker thread)."""
            return self.file_service.decrypt_file(
                input_path=infile,
                output_path=outfile,
                password=None,
            )

        def _on_success(sig_msg):
            self._set_busy(False)
            self._show_result(outfile, sig_msg)

        def _on_error(exc):
            self._set_busy(False)
            if isinstance(exc, CryptoTimeoutError):
                messagebox.showerror(
                    "Decryption Timed Out",
                    "File decryption timed out. The file may be too large or the system may be under heavy load.\n\nPlease try again."
                )
            elif isinstance(exc, SharedSecretDetected):
                self._handle_shared_detected(infile, outfile, exc)
            elif isinstance(exc, FileServiceError):
                if "password required" in str(exc).lower():
                    self._prompt_password_and_decrypt(infile, outfile)
                else:
                    messagebox.showerror("Decryption Error", friendly_error(exc))
            else:
                messagebox.showerror("Decryption Error", friendly_error(exc))

        self._set_busy(True)
        self._submit_file_task(_do_decrypt, _on_success, _on_error)

    def _handle_shared_detected(self, infile: str, outfile: str, detection: SharedSecretDetected) -> None:
        """Ask user if they want to decrypt using the detected shared secret."""
        ok = messagebox.askyesno(
            "Shared Secret Detected",
            f"This file appears to be encrypted with the shared secret for '{detection.owner}'.\n\n"
            "Decrypt using this shared secret?"
        )
        if not ok:
            return

        def _do_decrypt_shared():
            return self.file_service.decrypt_with_shared_secret(
                infile, outfile, detection.fingerprint
            )

        def _on_success(sig_msg):
            self._set_busy(False)
            self._show_result(outfile, sig_msg)

        def _on_error(exc):
            self._set_busy(False)
            if isinstance(exc, CryptoTimeoutError):
                messagebox.showerror("Decryption Timed Out", "File decryption timed out.")
            else:
                messagebox.showerror("Decryption Error", friendly_error(exc))

        self._set_busy(True)
        self._submit_file_task(_do_decrypt_shared, _on_success, _on_error)

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
            self._set_busy(False)
            self._show_result(outfile, sig_msg)

        def _on_error(exc):
            self._set_busy(False)
            if isinstance(exc, CryptoTimeoutError):
                messagebox.showerror("Decryption Timed Out", "File decryption timed out.")
            else:
                messagebox.showerror("Decryption Error", friendly_error(exc))

        self._set_busy(True)
        self._submit_file_task(_do_decrypt_pw, _on_success, _on_error)

    def _show_result(self, outfile: str, sig_msg: str) -> None:
        flash_widget_text(self.decrypt_btn, "Decrypted ✓", "🔓 Decrypt File")
        self.refresh_list()
        msg = f"File decrypted:\n{outfile}"
        if sig_msg:
            msg += f"\n\n{sig_msg}"
        messagebox.showinfo("Decryption Successful", msg)