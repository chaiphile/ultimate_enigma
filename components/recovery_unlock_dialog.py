"""Recovery unlock dialog – reconstruct recovery key and set new password.

This dialog operates WITHOUT requiring the current master password.
It is launched from the lock screen or startup login when the user
has forgotten their password and wants to recover using Shamir shares.
"""

import base64
import json
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk

from services.shamir_service import ShamirService
from views.dialogs import password_dialog

_SHARE_FILE_EXT = ".enigma-share"
_SHARE_FILE_TYPE = [("Enigma Share", "*.enigma-share"), ("All files", "*.*")]


class RecoveryUnlockDialog:
    """Modal dialog for recovery key reconstruction and password reset.

    Args:
        parent: Parent Tk window.
        on_recovered: Callback(new_password: SecureString) invoked after
            successful reconstruction and password set. The caller should
            use the password to reset the KeyStore.
    """

    def __init__(self, parent, on_recovered):
        self.parent = parent
        self.on_recovered = on_recovered
        self.shamir_service = ShamirService()

    def show(self):
        dlg = tk.Toplevel(self.parent)
        dlg.title("🔑 Recovery Key Unlock")
        dlg.geometry("700x600")
        dlg.resizable(True, True)
        dlg.minsize(600, 500)
        dlg.transient(self.parent)
        dlg.grab_set()

        notebook = ttk.Notebook(dlg, bootstyle="warning")
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))

        tab_reconstruct = ttk.Frame(notebook, padding=15)
        notebook.add(tab_reconstruct, text="  Reconstruct Key  ")

        tab_set_password = ttk.Frame(notebook, padding=15)
        notebook.add(tab_set_password, text="  Set New Password  ")

        self._build_reconstruct_tab(tab_reconstruct, dlg)
        self._build_set_password_tab(tab_set_password, dlg)

        ttk.Button(dlg, text="Cancel", command=dlg.destroy,
                   bootstyle="secondary-outline").pack(pady=(0, 10))

        self.parent.wait_window(dlg)

    def _build_reconstruct_tab(self, parent, dlg):
        ttk.Label(
            parent,
            text="Import share files or paste share values to reconstruct your recovery key",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            parent,
            text="You need K of N shares. Each .enigma-share file is RSA-encrypted to your key.",
            font=("Segoe UI", 9),
            bootstyle="secondary",
        ).pack(anchor="w", pady=(0, 10))

        params_frame = ttk.Frame(parent)
        params_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(params_frame, text="Expected threshold (K):",
                  font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 5))
        self._expected_k_var = tk.IntVar(value=2)
        ttk.Spinbox(params_frame, from_=2, to=10, textvariable=self._expected_k_var,
                    width=5, bootstyle="warning").pack(side=tk.LEFT, padx=(0, 15))

        ttk.Label(params_frame, text="Expected total shares (N):",
                  font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 5))
        self._expected_n_var = tk.IntVar(value=3)
        ttk.Spinbox(params_frame, from_=2, to=10, textvariable=self._expected_n_var,
                    width=5, bootstyle="warning").pack(side=tk.LEFT)

        ttk.Label(parent, text="Shares (Base64):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))

        share_entries_frame = ttk.Frame(parent)
        share_entries_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        self._share_entries_frame = share_entries_frame
        self._share_entries = []

        def add_share_entry(idx_val=None, b64_val=""):
            row_frame = ttk.Frame(share_entries_frame)
            row_frame.pack(fill=tk.X, pady=2)
            idx_var = tk.IntVar(value=idx_val if idx_val is not None else len(self._share_entries) + 1)
            ttk.Label(row_frame, text="Share #", font=("Segoe UI", 9),
                      width=6).pack(side=tk.LEFT)
            idx_spin = ttk.Spinbox(row_frame, from_=1, to=20, textvariable=idx_var,
                                   width=4, bootstyle="warning")
            idx_spin.pack(side=tk.LEFT, padx=(0, 5))
            entry = ttk.Entry(row_frame, font=("Consolas", 9), width=52)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            if b64_val:
                entry.insert(0, b64_val)
            self._share_entries.append((idx_var, entry))

        self._add_share_entry = add_share_entry
        add_share_entry()
        add_share_entry()
        add_share_entry()

        btn_row = ttk.Frame(parent)
        btn_row.pack(fill=tk.X, pady=(0, 5))

        def remove_last():
            if self._share_entries:
                _, entry = self._share_entries.pop()
                entry.master.destroy()

        ttk.Button(btn_row, text="Add Share", command=lambda: add_share_entry(),
                   bootstyle="success-outline").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_row, text="Remove Last", command=remove_last,
                   bootstyle="danger-outline").pack(side=tk.LEFT, padx=(0, 12))

        def import_share_file():
            path = filedialog.askopenfilename(
                parent=dlg,
                title="Import .enigma-share file",
                filetypes=_SHARE_FILE_TYPE,
            )
            if not path:
                return
            try:
                with open(path, "r", encoding="utf-8") as f:
                    payload = json.load(f)
                enc_b64 = payload.get("encrypted_share_b64", "")
                share_index = payload.get("share_index", len(self._share_entries) + 1)
                if not enc_b64:
                    messagebox.showerror("Invalid File",
                                         "No encrypted share found in file.",
                                         parent=dlg)
                    return
                # For recovery, the share may not be RSA-encrypted to us
                # (we may not have keys loaded). Try to use the raw value.
                try:
                    enc_bytes = base64.b64decode(enc_b64)
                    # Try RSA decryption (will fail if keys not loaded)
                    from key_manager import KeyStore
                    ks = KeyStore()
                    plain_bytes = ks.decrypt_share(enc_bytes) if hasattr(ks, 'decrypt_share') else enc_bytes
                except Exception:
                    # If decryption fails, use the raw base64 value
                    plain_bytes = base64.b64decode(enc_b64)
                plain_b64 = base64.b64encode(plain_bytes).decode("ascii")
                add_share_entry(idx_val=share_index, b64_val=plain_b64)
                messagebox.showinfo(
                    "Share Imported",
                    f"Share #{share_index} added.\n"
                    f"Owner: {payload.get('owner_name', 'unknown')}",
                    parent=dlg,
                )
            except Exception as e:
                messagebox.showerror("Import Failed",
                                     f"Failed to import share file:\n{e}", parent=dlg)

        ttk.Button(btn_row, text="Import .enigma-share File",
                   command=import_share_file,
                   bootstyle="info-outline").pack(side=tk.LEFT)

        self._result_var = tk.StringVar(value="")
        self._result_display = ttk.ScrolledText(parent, height=3, wrap=tk.WORD,
                                                font=("Consolas", 10), state="disabled")
        self._result_display.pack(fill=tk.X, pady=(0, 5))

        self._reconstructed_state = {"key_bytes": None}

        def do_reconstruct():
            raw_shares = []
            for idx_var, entry in self._share_entries:
                val = entry.get().strip()
                if val:
                    raw_shares.append((idx_var.get(), val))

            if len(raw_shares) < 2:
                messagebox.showwarning("Insufficient Shares",
                                       "Provide at least 2 shares.", parent=dlg)
                return

            try:
                parsed = []
                for share_idx, b64_str in raw_shares:
                    share_bytes = base64.b64decode(b64_str)
                    parsed.append((share_idx, share_bytes))

                if len(set(len(s[1]) for s in parsed)) != 1:
                    messagebox.showerror("Invalid Shares",
                                         "All shares must have the same length.",
                                         parent=dlg)
                    return

                expected_len = len(parsed[0][1])
                reconstructed = self.shamir_service.reconstruct_secret(parsed, expected_len)

                full_b64 = base64.b64encode(reconstructed).decode("ascii")
                masked = full_b64[:8] + "●" * (len(full_b64) - 8)

                self._result_display.config(state="normal")
                self._result_display.delete("1.0", tk.END)
                self._result_display.insert("1.0", masked)
                self._result_display.config(state="disabled")
                self._result_var.set("✅ Key reconstructed successfully")

                self._reconstructed_state["key_bytes"] = reconstructed

                # Enable the "Set New Password" tab
                notebook = dlg.winfo_children()[0]
                if isinstance(notebook, ttk.Notebook):
                    # Auto-switch to password tab
                    for tab in notebook.tabs():
                        if notebook.tab(tab, "text").strip() == "Set New Password":
                            notebook.select(tab)
                            break

            except Exception as e:
                messagebox.showerror("Reconstruction Failed",
                                     f"Failed to reconstruct key:\n{e}", parent=dlg)

        ttk.Label(parent, textvariable=self._result_var,
                  font=("Segoe UI", 9), bootstyle="success").pack(anchor="w", pady=(0, 8))
        ttk.Button(parent, text="Reconstruct Key", command=do_reconstruct,
                   bootstyle="warning").pack(anchor="w")

    def _build_set_password_tab(self, parent, dlg):
        ttk.Label(
            parent,
            text="Set a new master password for the application",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            parent,
            text="Your old password cannot be recovered. This will reset all "
                 "cryptographic keys. Friend public keys and certificates are preserved.",
            font=("Segoe UI", 9),
            bootstyle="secondary",
            wraplength=580,
            justify="left",
        ).pack(anchor="w", pady=(0, 10))

        warning_frame = ttk.Frame(parent)
        warning_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(
            warning_frame,
            text="⚠️  Warning: Private keys (RSA, PQC, signing) will be regenerated.\n"
                 "You will need to re-exchange keys with friends.",
            font=("Segoe UI", 9),
            bootstyle="danger",
            wraplength=580,
            justify="left",
        ).pack(anchor="w")

        ttk.Label(parent, text="New master password:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        self._new_pw_var = tk.StringVar()
        new_pw_entry = ttk.Entry(parent, textvariable=self._new_pw_var, show="*", width=35,
                                 bootstyle="warning")
        new_pw_entry.pack(anchor="w", pady=(0, 8))

        ttk.Label(parent, text="Confirm new password:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        self._confirm_pw_var = tk.StringVar()
        confirm_pw_entry = ttk.Entry(parent, textvariable=self._confirm_pw_var, show="*", width=35,
                                     bootstyle="warning")
        confirm_pw_entry.pack(anchor="w", pady=(0, 15))

        def apply_recovery():
            if self._reconstructed_state["key_bytes"] is None:
                messagebox.showwarning("No Key",
                                       "Reconstruct the recovery key first.",
                                       parent=dlg)
                return

            new_pw = self._new_pw_var.get()
            confirm_pw = self._confirm_pw_var.get()

            if not new_pw:
                messagebox.showwarning("Empty Password",
                                       "Enter a new master password.",
                                       parent=dlg)
                return

            if new_pw != confirm_pw:
                messagebox.showerror("Mismatch", "Passwords do not match.",
                                     parent=dlg)
                return

            if len(new_pw) < 8:
                messagebox.showwarning("Weak Password",
                                       "Password must be at least 8 characters.",
                                       parent=dlg)
                return

            confirm = messagebox.askyesno(
                "Confirm Recovery",
                "This will:\n"
                "• Replace your master password\n"
                "• Regenerate RSA, PQC, and signing keys\n"
                "• Clear friend shared secrets\n"
                "• Preserve friend public keys and certificates\n\n"
                "Continue?",
                icon="warning",
                parent=dlg,
            )
            if not confirm:
                return

            try:
                dlg.destroy()
                self.on_recovered(new_pw)
            except Exception as e:
                messagebox.showerror("Recovery Failed",
                                     f"Failed to complete recovery:\n{e}",
                                     parent=self.parent)

        ttk.Button(parent, text="Apply Recovery & Set New Password",
                   command=apply_recovery, bootstyle="danger").pack(anchor="w")
