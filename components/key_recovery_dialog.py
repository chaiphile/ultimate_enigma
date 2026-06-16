import base64
import json
import time
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

import database
from services.event_bus import event_bus, Events
from services.shamir_service import ShamirService, generate_recovery_key
from views.dialogs import password_dialog

_SHARE_FILE_EXT = ".enigma-share"
_SHARE_FILE_TYPE = [("Enigma Share", "*.enigma-share"), ("All files", "*.*")]


class KeyRecoveryDialog:
    def __init__(self, parent, trust_chain_service, friends_service, bg: str,
                 mode: str = None, global_secret_service=None):
        self.parent = parent
        self.trust_chain_service = trust_chain_service
        self.friends_service = friends_service
        self.bg = bg
        self.mode = mode
        self.global_secret_service = global_secret_service
        self.shamir_service = ShamirService()

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def show(self):
        master_pw = password_dialog(
            self.parent,
            "🔑 Key Recovery – Master Password Required",
            confirm=False,
        )
        if not master_pw:
            return
        if not self.friends_service.verify_password(master_pw):
            messagebox.showerror(
                "Access Denied",
                "Incorrect master password.\n"
                "Key recovery requires authentication.",
                parent=self.parent,
            )
            return

        dlg = tk.Toplevel(self.parent)
        dlg.title("🔑 Key Recovery (Shamir's Secret Sharing)")
        dlg.geometry("740x640")
        dlg.resizable(True, True)
        dlg.minsize(640, 540)
        dlg.transient(self.parent)
        dlg.grab_set()
        dlg.configure(bg=self.bg)

        notebook = ttk.Notebook(dlg, bootstyle="warning")
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))

        tab_split = ttk.Frame(notebook, padding=15)
        notebook.add(tab_split, text="  Split Recovery Key  ")

        tab_recover = ttk.Frame(notebook, padding=15)
        notebook.add(tab_recover, text="  Recover Key  ")

        tab_held = ttk.Frame(notebook, padding=15)
        notebook.add(tab_held, text="  Held Shares  ")

        tab_status = ttk.Frame(notebook, padding=15)
        notebook.add(tab_status, text="  Share Status  ")

        self._build_split_tab(tab_split, master_pw, dlg)
        self._build_recover_tab(tab_recover, dlg)
        self._build_held_shares_tab(tab_held, dlg)
        self._build_status_tab(tab_status)

        if self.mode == "split":
            notebook.select(tab_split)
        elif self.mode == "recover":
            notebook.select(tab_recover)
        elif self.mode == "held":
            notebook.select(tab_held)

        ttk.Button(dlg, text="Close", command=dlg.destroy,
                   bootstyle="secondary-outline").pack(pady=(0, 10))

    # ------------------------------------------------------------------
    # Split tab
    # ------------------------------------------------------------------

    def _build_split_tab(self, parent, master_pw, dlg):
        ttk.Label(
            parent,
            text="Split your master recovery key into shares distributed among trusted friends",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            parent,
            text="Each share is RSA-encrypted to the recipient's public key — only they can read it",
            font=("Segoe UI", 9),
            bootstyle="secondary",
        ).pack(anchor="w", pady=(0, 10))

        params_frame = ttk.Frame(parent)
        params_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(params_frame, text="Total shares (N):",
                  font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 5))
        n_var = tk.IntVar(value=3)
        n_spin = ttk.Spinbox(params_frame, from_=2, to=10, textvariable=n_var,
                             width=5, bootstyle="warning")
        n_spin.pack(side=tk.LEFT, padx=(0, 15))

        ttk.Label(params_frame, text="Threshold (K):",
                  font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 5))
        k_var = tk.IntVar(value=2)
        k_spin = ttk.Spinbox(params_frame, from_=2, to=10, textvariable=k_var,
                             width=5, bootstyle="warning")
        k_spin.pack(side=tk.LEFT)

        def on_n_change(*args):
            n = n_var.get()
            k = k_var.get()
            if k > n:
                k_var.set(n)
            k_spin.config(to=n)

        n_var.trace_add("write", on_n_change)

        ttk.Label(
            parent,
            text="You need K of N shares to recover your key",
            font=("Segoe UI", 9, "italic"),
            bootstyle="info",
        ).pack(anchor="w", pady=(0, 8))

        ttk.Label(parent, text="Select friends to hold shares:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        friend_listbox = tk.Listbox(parent, height=5, font=("Segoe UI", 9),
                                    selectmode=tk.MULTIPLE, relief="solid", bd=1)
        friend_listbox.pack(fill=tk.X, pady=(0, 10))
        friend_names = self.friends_service.get_friend_names()
        for name in friend_names:
            friend_listbox.insert(tk.END, name)

        shares_display = ttk.ScrolledText(parent, height=7, wrap=tk.WORD,
                                          font=("Consolas", 9), state="disabled")
        shares_display.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        # Per-share export buttons (populated after splitting)
        export_frame = ttk.Frame(parent)
        export_frame.pack(fill=tk.X, pady=(0, 4))

        status_var = tk.StringVar(value="")
        ttk.Label(parent, textvariable=status_var,
                  font=("Segoe UI", 9), bootstyle="success").pack(anchor="w", pady=(0, 8))

        # Holds {holder_name: share_json_dict} after a successful split
        _split_result: dict = {}

        def do_split():
            for widget in export_frame.winfo_children():
                widget.destroy()
            _split_result.clear()

            selected_indices = friend_listbox.curselection()
            if not selected_indices:
                messagebox.showwarning("No Friends Selected",
                                       "Select at least one friend to hold shares.",
                                       parent=dlg)
                return
            n = n_var.get()
            k = k_var.get()
            if k > n:
                messagebox.showwarning("Invalid Parameters",
                                       "Threshold K cannot exceed total shares N.",
                                       parent=dlg)
                return
            if len(selected_indices) < n:
                messagebox.showwarning(
                    "Not Enough Friends",
                    f"You selected {len(selected_indices)} friend(s) but need "
                    f"{n} share holders.\nSelect more friends or reduce N.",
                    parent=dlg,
                )
                return

            pw = password_dialog(parent, "Enter Master Password to generate recovery key",
                                 confirm=False)
            if not pw:
                return
            if not self.friends_service.verify_password(pw):
                messagebox.showerror("Wrong Password",
                                     "Master password incorrect.", parent=dlg)
                return

            selected_names = [friend_names[i] for i in selected_indices]

            # Check that all selected friends have RSA public keys loaded
            missing = [n for n in selected_names
                       if self.friends_service.get_friend_rsa_pub(n) is None]
            if missing:
                messagebox.showerror(
                    "Missing Public Keys",
                    "These friends have no RSA public key loaded and cannot "
                    f"receive an encrypted share:\n\n{', '.join(missing)}\n\n"
                    "Re-add them so their public key is available.",
                    parent=dlg,
                )
                return

            try:
                recovery_key = generate_recovery_key(32)
                shares = self.shamir_service.split_secret(recovery_key, n, k)

                shares_display.config(state="normal")
                shares_display.delete("1.0", tk.END)

                now = time.time()
                for idx, (share_index, share_bytes) in enumerate(shares):
                    holder = (selected_names[idx]
                              if idx < len(selected_names) else f"Share {share_index}")
                    friend_pub = self.friends_service.get_friend_rsa_pub(holder)
                    encrypted_bytes = self.friends_service.encrypt_share(share_bytes, friend_pub)
                    encrypted_b64 = base64.b64encode(encrypted_bytes).decode("ascii")

                    share_id = f"{int(now * 1000)}-{share_index}"
                    share_dict = {
                        "share_id": share_id,
                        "owner_name": self.friends_service.get_my_name() or "owner",
                        "holder_name": holder,
                        "share_index": share_index,
                        "total_shares": n,
                        "threshold": k,
                        "encrypted_share_b64": encrypted_b64,
                        "holder_pub_b64": "",
                        "created_at": now,
                    }
                    database.save_recovery_share(share_dict)
                    _split_result[holder] = share_dict

                    shares_display.insert(
                        tk.END,
                        f"Share #{share_index} → {holder}  "
                        f"[RSA-encrypted, {len(encrypted_bytes)} bytes]\n"
                        f"{encrypted_b64[:48]}…\n\n",
                    )

                shares_display.config(state="disabled")

                # Build per-friend export buttons
                ttk.Label(export_frame, text="Export share files:",
                          font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
                btn_row = ttk.Frame(export_frame)
                btn_row.pack(fill=tk.X)
                for holder_name, sd in _split_result.items():
                    def _make_export(sd=sd, holder_name=holder_name):
                        def _export():
                            path = filedialog.asksaveasfilename(
                                parent=dlg,
                                title=f"Save share file for {holder_name}",
                                initialfile=f"share_for_{holder_name}{_SHARE_FILE_EXT}",
                                filetypes=_SHARE_FILE_TYPE,
                                defaultextension=_SHARE_FILE_EXT,
                            )
                            if not path:
                                return
                            payload = {k: v for k, v in sd.items()
                                       if k != "holder_pub_b64"}
                            payload["type"] = "enigma_recovery_share"
                            payload["version"] = 1
                            with open(path, "w", encoding="utf-8") as f:
                                json.dump(payload, f, indent=2)
                            messagebox.showinfo(
                                "Exported",
                                f"Share file saved.\nSend it securely to {holder_name}.",
                                parent=dlg,
                            )
                        return _export
                    ttk.Button(btn_row, text=f"Export for {holder_name}",
                               command=_make_export(),
                               bootstyle="warning-outline").pack(side=tk.LEFT, padx=(0, 6))

                status_var.set(
                    f"✅ {n} encrypted shares created (threshold: {k}), "
                    f"for: {', '.join(selected_names)}"
                )
                event_bus.publish(Events.RECOVERY_SHARE_CREATED, n=n, k=k,
                                  holders=selected_names)
                messagebox.showinfo(
                    "Shares Created",
                    f"Recovery key split into {n} shares (K={k}).\n\n"
                    "Each share is RSA-encrypted to the recipient's public key.\n"
                    "Use the export buttons to save a file for each friend.\n"
                    "Friends can import their file in the 'Held Shares' tab.",
                    parent=dlg,
                )
            except Exception as e:
                messagebox.showerror("Error", f"Failed to split key:\n{e}", parent=dlg)

        ttk.Button(parent, text="Generate & Distribute Shares",
                   command=do_split, bootstyle="warning").pack(anchor="w")

    # ------------------------------------------------------------------
    # Recover tab
    # ------------------------------------------------------------------

    def _build_recover_tab(self, parent, dlg):
        ttk.Label(
            parent,
            text="Collect shares from trusted friends to reconstruct your recovery key",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            parent,
            text="Paste plaintext share values, or import .enigma-share files (auto-decrypted with your RSA key)",
            font=("Segoe UI", 9),
            bootstyle="secondary",
        ).pack(anchor="w", pady=(0, 10))

        params_frame = ttk.Frame(parent)
        params_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(params_frame, text="Expected threshold (K):",
                  font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 5))
        expected_k_var = tk.IntVar(value=2)
        ttk.Spinbox(params_frame, from_=2, to=10, textvariable=expected_k_var,
                    width=5, bootstyle="warning").pack(side=tk.LEFT, padx=(0, 15))

        ttk.Label(params_frame, text="Expected total shares (N):",
                  font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 5))
        expected_n_var = tk.IntVar(value=3)
        ttk.Spinbox(params_frame, from_=2, to=10, textvariable=expected_n_var,
                    width=5, bootstyle="warning").pack(side=tk.LEFT)

        ttk.Label(parent, text="Paste shares (Base64) or import files below:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))

        share_entries_frame = ttk.Frame(parent)
        share_entries_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        share_entries = []

        def add_share_entry(idx_val=None, b64_val=""):
            row_frame = ttk.Frame(share_entries_frame)
            row_frame.pack(fill=tk.X, pady=2)
            idx_var = tk.IntVar(value=idx_val if idx_val is not None else len(share_entries) + 1)
            ttk.Label(row_frame, text="Share #", font=("Segoe UI", 9),
                      width=6).pack(side=tk.LEFT)
            idx_spin = ttk.Spinbox(row_frame, from_=1, to=20, textvariable=idx_var,
                                   width=4, bootstyle="warning")
            idx_spin.pack(side=tk.LEFT, padx=(0, 5))
            entry = ttk.Entry(row_frame, font=("Consolas", 9), width=52)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            if b64_val:
                entry.insert(0, b64_val)
            share_entries.append((idx_var, entry))

        add_share_entry()
        add_share_entry()
        add_share_entry()

        btn_row = ttk.Frame(parent)
        btn_row.pack(fill=tk.X, pady=(0, 5))

        def remove_last():
            if share_entries:
                _, entry = share_entries.pop()
                entry.master.destroy()

        ttk.Button(btn_row, text="Add Share", command=add_share_entry,
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
                share_index = payload.get("share_index", len(share_entries) + 1)
                if not enc_b64:
                    messagebox.showerror("Invalid File",
                                         "No encrypted share found in file.",
                                         parent=dlg)
                    return
                enc_bytes = base64.b64decode(enc_b64)
                try:
                    plain_bytes = self.friends_service.decrypt_share(enc_bytes)
                except Exception as dec_err:
                    messagebox.showerror(
                        "Decryption Failed",
                        f"Could not decrypt the share with your RSA private key:\n{dec_err}\n\n"
                        "Make sure this share file was created for you.",
                        parent=dlg,
                    )
                    return
                plain_b64 = base64.b64encode(plain_bytes).decode("ascii")
                add_share_entry(idx_val=share_index, b64_val=plain_b64)
                messagebox.showinfo(
                    "Share Imported",
                    f"Share #{share_index} decrypted and added.\n"
                    f"Owner: {payload.get('owner_name', 'unknown')}",
                    parent=dlg,
                )
            except Exception as e:
                messagebox.showerror("Import Failed",
                                     f"Failed to import share file:\n{e}", parent=dlg)

        ttk.Button(btn_row, text="Import .enigma-share File",
                   command=import_share_file,
                   bootstyle="info-outline").pack(side=tk.LEFT)

        result_var = tk.StringVar(value="")
        result_display = ttk.ScrolledText(parent, height=3, wrap=tk.WORD,
                                          font=("Consolas", 10), state="disabled")
        result_display.pack(fill=tk.X, pady=(0, 5))

        _reconstructed_state = {"key_bytes": None, "key_b64": None, "action_frame": None}

        def do_reconstruct():
            raw_shares = []
            for idx_var, entry in share_entries:
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

                result_display.config(state="normal")
                result_display.delete("1.0", tk.END)
                result_display.insert("1.0", masked)
                result_display.config(state="disabled")
                result_var.set("✅ Key reconstructed successfully")

                _reconstructed_state["key_bytes"] = reconstructed
                _reconstructed_state["key_b64"] = full_b64
                event_bus.publish(
                    Events.RECOVERY_KEY_RECONSTRUCTED,
                    num_shares=len(raw_shares),
                    recovered_key_b64=full_b64,
                )

            except Exception as e:
                messagebox.showerror("Reconstruction Failed",
                                     f"Failed to reconstruct key:\n{e}", parent=dlg)
                return

            if _reconstructed_state["action_frame"] is not None:
                _reconstructed_state["action_frame"].destroy()

            action_frame = ttk.Frame(parent)
            action_frame.pack(fill=tk.X, pady=(0, 5))
            _reconstructed_state["action_frame"] = action_frame

            def copy_key():
                self.parent.clipboard_clear()
                self.parent.clipboard_append(_reconstructed_state["key_b64"])
                messagebox.showinfo("Copied",
                                    "Recovery key copied to clipboard.\n"
                                    "Use it immediately and clear clipboard.",
                                    parent=dlg)

            ttk.Button(action_frame, text="Copy to Clipboard",
                       command=copy_key, bootstyle="warning").pack(side=tk.LEFT, padx=(0, 8))

            if self.global_secret_service is not None:
                def apply_as_master_key():
                    key_bytes = _reconstructed_state["key_bytes"]
                    if key_bytes is None:
                        return
                    if len(key_bytes) != 32:
                        messagebox.showerror(
                            "Invalid Key Length",
                            f"Reconstructed key is {len(key_bytes)} bytes; "
                            "exactly 32 bytes required to set as master key.",
                            parent=dlg,
                        )
                        return
                    confirmed = messagebox.askyesno(
                        "Replace Master Key",
                        "This will replace your current master key with the reconstructed key.\n\n"
                        "Any data encrypted with the old key will need to be re-encrypted manually.\n\n"
                        "Continue?",
                        icon="warning",
                        parent=dlg,
                    )
                    if not confirmed:
                        return
                    master_pw = password_dialog(
                        dlg,
                        "Enter Master Password to Apply Recovered Key",
                        confirm=False,
                    )
                    if not master_pw:
                        return
                    try:
                        self.global_secret_service.update_secret(key_bytes, master_pw)
                        messagebox.showinfo(
                            "Key Applied",
                            "Master key has been replaced with the reconstructed recovery key.\n"
                            "Your session is now using the recovered key.",
                            parent=dlg,
                        )
                    except Exception as exc:
                        messagebox.showerror("Apply Failed",
                                             f"Failed to apply recovered key:\n{exc}",
                                             parent=dlg)

                ttk.Button(action_frame, text="Apply as Master Key",
                           command=apply_as_master_key,
                           bootstyle="danger").pack(side=tk.LEFT)

        ttk.Label(parent, textvariable=result_var,
                  font=("Segoe UI", 9), bootstyle="success").pack(anchor="w", pady=(0, 8))
        ttk.Button(parent, text="Reconstruct Key", command=do_reconstruct,
                   bootstyle="warning").pack(anchor="w")

    # ------------------------------------------------------------------
    # Held Shares tab  (shares this user is holding for others)
    # ------------------------------------------------------------------

    def _build_held_shares_tab(self, parent, dlg):
        ttk.Label(
            parent,
            text="Shares you are holding on behalf of others",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            parent,
            text="Import a .enigma-share file a friend sent you. "
                 "It will be decrypted with your RSA key and stored here. "
                 "When they ask, export it back.",
            font=("Segoe UI", 9),
            bootstyle="secondary",
            wraplength=640,
        ).pack(anchor="w", pady=(0, 10))

        columns = ("owner", "share_index", "threshold", "created")
        tree = ttk.Treeview(parent, columns=columns, show="headings", height=8,
                            bootstyle="warning")
        tree.heading("owner", text="Owner")
        tree.heading("share_index", text="Share #")
        tree.heading("threshold", text="Threshold")
        tree.heading("created", text="Imported")
        tree.column("owner", width=180)
        tree.column("share_index", width=70, anchor="center")
        tree.column("threshold", width=90, anchor="center")
        tree.column("created", width=160)

        sb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        _held: list = []

        def load_held():
            tree.delete(*tree.get_children())
            _held.clear()
            for row in database.get_all_held_shares():
                _held.append(row)
                created_str = time.strftime(
                    "%Y-%m-%d %H:%M",
                    time.localtime(row.get("created_at", 0)),
                )
                tree.insert("", tk.END, iid=row["share_id"], values=(
                    row.get("owner_name", ""),
                    row.get("share_index", ""),
                    f"{row.get('threshold', '')}/{row.get('total_shares', '')}",
                    created_str,
                ))

        load_held()

        btn_row = ttk.Frame(parent)
        btn_row.pack(fill=tk.X)

        def import_held_share():
            path = filedialog.askopenfilename(
                parent=dlg,
                title="Import .enigma-share file a friend sent you",
                filetypes=_SHARE_FILE_TYPE,
            )
            if not path:
                return
            try:
                with open(path, "r", encoding="utf-8") as f:
                    payload = json.load(f)

                enc_b64 = payload.get("encrypted_share_b64", "")
                if not enc_b64:
                    messagebox.showerror("Invalid File",
                                         "No encrypted share data found in file.",
                                         parent=dlg)
                    return
                enc_bytes = base64.b64decode(enc_b64)
                try:
                    plain_bytes = self.friends_service.decrypt_share(enc_bytes)
                except Exception as dec_err:
                    messagebox.showerror(
                        "Decryption Failed",
                        f"Could not decrypt the share:\n{dec_err}\n\n"
                        "This file may not have been encrypted for you, "
                        "or your RSA key does not match.",
                        parent=dlg,
                    )
                    return

                plain_b64 = base64.b64encode(plain_bytes).decode("ascii")
                share_id = payload.get("share_id",
                                       f"held-{int(time.time() * 1000)}")
                held_dict = {
                    "share_id": share_id,
                    "owner_name": payload.get("owner_name", "unknown"),
                    "holder_name": payload.get("holder_name",
                                               self.friends_service.get_my_name() or "me"),
                    "share_index": payload.get("share_index", 0),
                    "total_shares": payload.get("total_shares", 0),
                    "threshold": payload.get("threshold", 0),
                    "plaintext_share_b64": plain_b64,
                    "created_at": time.time(),
                }
                database.save_held_share(held_dict)
                load_held()
                messagebox.showinfo(
                    "Share Stored",
                    f"Share #{payload.get('share_index', '?')} from "
                    f"{payload.get('owner_name', 'unknown')} has been decrypted and stored.\n\n"
                    "When they need to recover, use 'Export Back to Owner' to send it to them.",
                    parent=dlg,
                )
            except Exception as e:
                messagebox.showerror("Import Failed",
                                     f"Failed to import share:\n{e}", parent=dlg)

        def export_back():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Nothing Selected",
                                       "Select a held share to export.", parent=dlg)
                return
            share_id = sel[0]
            row = next((r for r in _held if r["share_id"] == share_id), None)
            if row is None:
                return
            owner = row.get("owner_name", "owner")
            path = filedialog.asksaveasfilename(
                parent=dlg,
                title=f"Export held share back to {owner}",
                initialfile=f"share_back_to_{owner}{_SHARE_FILE_EXT}",
                filetypes=_SHARE_FILE_TYPE,
                defaultextension=_SHARE_FILE_EXT,
            )
            if not path:
                return
            # Encrypt the plaintext share to the owner's RSA public key so
            # only the owner can use it during reconstruction.
            plain_bytes = base64.b64decode(row["plaintext_share_b64"])
            owner_pub = self.friends_service.get_friend_rsa_pub(owner)
            if owner_pub is not None:
                enc_bytes = self.friends_service.encrypt_share(plain_bytes, owner_pub)
                enc_b64 = base64.b64encode(enc_bytes).decode("ascii")
                note = "RSA-encrypted to owner"
            else:
                # Owner not in friend list — export as plaintext with warning
                enc_b64 = row["plaintext_share_b64"]
                note = "plaintext (owner not in friend list)"
                messagebox.showwarning(
                    "Owner Not Found",
                    f"'{owner}' is not in your friend list.\n"
                    "The share will be exported as plaintext.\n"
                    "Send the file only through a secure channel.",
                    parent=dlg,
                )
            export_payload = {
                "type": "enigma_recovery_share",
                "version": 1,
                "share_id": row["share_id"],
                "owner_name": owner,
                "holder_name": row.get("holder_name", ""),
                "share_index": row.get("share_index", 0),
                "total_shares": row.get("total_shares", 0),
                "threshold": row.get("threshold", 0),
                "encrypted_share_b64": enc_b64,
                "note": note,
                "created_at": row.get("created_at", 0),
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(export_payload, f, indent=2)
            messagebox.showinfo(
                "Exported",
                f"Share file saved ({note}).\nSend it securely to {owner}.",
                parent=dlg,
            )

        def delete_selected():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Nothing Selected",
                                       "Select a share to delete.", parent=dlg)
                return
            confirmed = messagebox.askyesno(
                "Delete Held Share",
                "Delete this held share from your local storage?\n\n"
                "The owner will no longer be able to request it from you.",
                icon="warning",
                parent=dlg,
            )
            if not confirmed:
                return
            for share_id in sel:
                database.delete_held_share(share_id)
            load_held()

        ttk.Button(btn_row, text="Import Share File",
                   command=import_held_share,
                   bootstyle="warning").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="Export Back to Owner",
                   command=export_back,
                   bootstyle="success").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="Delete Selected",
                   command=delete_selected,
                   bootstyle="danger-outline").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="🔄 Refresh",
                   command=load_held,
                   bootstyle="secondary-outline").pack(side=tk.RIGHT)

    # ------------------------------------------------------------------
    # Status tab
    # ------------------------------------------------------------------

    def _build_status_tab(self, parent):
        ttk.Label(
            parent,
            text="Recovery Share Distribution Status",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(0, 10))

        columns = ("owner", "holder", "share_index", "threshold", "created", "status")
        tree = ttk.Treeview(parent, columns=columns, show="headings", height=12,
                            bootstyle="warning")
        tree.heading("owner", text="Owner")
        tree.heading("holder", text="Holder")
        tree.heading("share_index", text="Share #")
        tree.heading("threshold", text="Threshold")
        tree.heading("created", text="Created")
        tree.heading("status", text="Status")
        tree.column("owner", width=120)
        tree.column("holder", width=120)
        tree.column("share_index", width=70, anchor="center")
        tree.column("threshold", width=80, anchor="center")
        tree.column("created", width=140)
        tree.column("status", width=100)

        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        def load_status():
            for item in tree.get_children():
                tree.delete(item)
            friend_names = self.friends_service.get_friend_names()
            for name in friend_names:
                try:
                    shares = database.get_recovery_shares_for(name)
                    for share in shares:
                        created_str = time.strftime(
                            "%Y-%m-%d %H:%M",
                            time.localtime(share.get("created_at", 0)),
                        )
                        tree.insert("", tk.END, values=(
                            share.get("owner_name", ""),
                            share.get("holder_name", ""),
                            share.get("share_index", ""),
                            f"{share.get('threshold', '')}/{share.get('total_shares', '')}",
                            created_str,
                            "Encrypted ✓",
                        ))
                except Exception:
                    pass

        load_status()

        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="🔄 Refresh", command=load_status,
                   bootstyle="warning-outline").pack(side=tk.RIGHT)
