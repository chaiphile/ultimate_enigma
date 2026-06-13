import base64
import time
import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

import database
from services.shamir_service import ShamirService, generate_recovery_key
from views.utils import password_dialog


class KeyRecoveryDialog:
    def __init__(self, parent, trust_chain_service, friends_service, bg: str,
                 mode: str = None):
        self.parent = parent
        self.trust_chain_service = trust_chain_service
        self.friends_service = friends_service
        self.bg = bg
        self.mode = mode
        self.shamir_service = ShamirService()

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
        dlg.geometry("700x600")
        dlg.resizable(True, True)
        dlg.minsize(600, 500)
        dlg.transient(self.parent)
        dlg.grab_set()
        dlg.configure(bg=self.bg)

        notebook = ttk.Notebook(dlg, bootstyle="warning")
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))

        tab_split = ttk.Frame(notebook, padding=15)
        notebook.add(tab_split, text="  Split Recovery Key  ")

        tab_recover = ttk.Frame(notebook, padding=15)
        notebook.add(tab_recover, text="  Recover Key  ")

        tab_status = ttk.Frame(notebook, padding=15)
        notebook.add(tab_status, text="  Share Status  ")

        self._build_split_tab(tab_split, master_pw)
        self._build_recover_tab(tab_recover)
        self._build_status_tab(tab_status)

        ttk.Button(dlg, text="Close", command=dlg.destroy,
                   bootstyle="secondary-outline").pack(pady=(0, 10))

    def _build_split_tab(self, parent, master_pw):
        ttk.Label(
            parent,
            text="Split your master recovery key into shares distributed among trusted friends",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            parent,
            text="This allows key recovery if you lose access",
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

        ttk.Label(parent, text="Available friends:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        friend_listbox = tk.Listbox(parent, height=6, font=("Segoe UI", 9),
                                    selectmode=tk.MULTIPLE, relief="solid", bd=1)
        friend_listbox.pack(fill=tk.X, pady=(0, 10))
        friend_names = self.friends_service.get_friend_names()
        for name in friend_names:
            friend_listbox.insert(tk.END, name)

        shares_display = ttk.ScrolledText(parent, height=10, wrap=tk.WORD,
                                          font=("Consolas", 9), state="disabled")
        shares_display.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        status_var = tk.StringVar(value="")
        ttk.Label(parent, textvariable=status_var,
                  font=("Segoe UI", 9), bootstyle="success").pack(anchor="w", pady=(0, 8))

        def do_split():
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

            pw = password_dialog(
                parent,
                "Enter Master Password to generate recovery key",
                confirm=False,
            )
            if not pw:
                return
            if not self.friends_service.verify_password(pw):
                messagebox.showerror("Wrong Password",
                                     "Master password incorrect.", parent=dlg)
                return

            try:
                recovery_key = generate_recovery_key(32)
                shares = self.shamir_service.split_secret(recovery_key, n, k)
                selected_names = [friend_names[i] for i in selected_indices]

                shares_display.config(state="normal")
                shares_display.delete("1.0", tk.END)

                for idx, (share_index, share_bytes) in enumerate(shares):
                    holder = selected_names[idx] if idx < len(selected_names) else f"Share {share_index}"
                    b64_share = base64.b64encode(share_bytes).decode("ascii")
                    shares_display.insert(
                        tk.END,
                        f"Share #{share_index} → {holder}\n{b64_share}\n\n",
                    )

                    share_dict = {
                        "share_id": f"{int(time.time()*1000)}-{share_index}",
                        "owner_name": self.friends_service.get_friend_names()[0]
                        if self.friends_service.get_friend_names() else "owner",
                        "share_index": share_index,
                        "total_shares": n,
                        "threshold": k,
                        "encrypted_share_b64": b64_share,
                        "holder_name": holder,
                        "holder_pub_b64": "",
                        "created_at": time.time(),
                    }
                    database.save_recovery_share(share_dict)

                shares_display.config(state="disabled")
                status_var.set(f"✅ {n} shares created (threshold: {k}), distributed to {len(selected_names)} friends")
                messagebox.showinfo(
                    "Shares Created",
                    f"Recovery key split into {n} shares (K={k}).\n\n"
                    "Each selected friend should receive their share.\n"
                    "Store them securely — you'll need K shares to recover.",
                    parent=dlg,
                )
            except Exception as e:
                messagebox.showerror("Error", f"Failed to split key:\n{e}", parent=dlg)

        dlg = parent.winfo_toplevel()
        ttk.Button(parent, text="Generate & Distribute Shares",
                   command=do_split, bootstyle="warning").pack(anchor="w")

    def _build_recover_tab(self, parent):
        ttk.Label(
            parent,
            text="Collect shares from trusted friends to reconstruct your recovery key",
            font=("Segoe UI", 10, "bold"),
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

        ttk.Label(parent, text="Paste shares (Base64) below:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))

        share_entries_frame = ttk.Frame(parent)
        share_entries_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        share_entries = []

        def add_share_entry():
            row_frame = ttk.Frame(share_entries_frame)
            row_frame.pack(fill=tk.X, pady=2)
            idx_var = tk.IntVar(value=len(share_entries) + 1)
            ttk.Label(row_frame, text="Share #", font=("Segoe UI", 9),
                      width=6).pack(side=tk.LEFT)
            idx_spin = ttk.Spinbox(row_frame, from_=1, to=20, textvariable=idx_var,
                                   width=4, bootstyle="warning")
            idx_spin.pack(side=tk.LEFT, padx=(0, 5))
            entry = ttk.Entry(row_frame, font=("Consolas", 9), width=55)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            share_entries.append((idx_var, entry))

        add_share_entry()
        add_share_entry()
        add_share_entry()

        btn_row = ttk.Frame(parent)
        btn_row.pack(fill=tk.X, pady=(0, 5))

        ttk.Button(btn_row, text="Add Share", command=add_share_entry,
                   bootstyle="success-outline").pack(side=tk.LEFT, padx=(0, 5))

        def remove_last():
            if share_entries:
                _, entry = share_entries.pop()
                entry.master.destroy()

        ttk.Button(btn_row, text="Remove Last Share", command=remove_last,
                   bootstyle="danger-outline").pack(side=tk.LEFT)

        result_var = tk.StringVar(value="")
        result_display = ttk.ScrolledText(parent, height=3, wrap=tk.WORD,
                                          font=("Consolas", 10), state="disabled")
        result_display.pack(fill=tk.X, pady=(0, 5))

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
                reconstructed = self.shamir_service.reconstruct_secret(
                    parsed, expected_len
                )

                full_b64 = base64.b64encode(reconstructed).decode("ascii")
                masked = full_b64[:8] + "●" * (len(full_b64) - 8)

                result_display.config(state="normal")
                result_display.delete("1.0", tk.END)
                result_display.insert("1.0", masked)
                result_display.config(state="disabled")
                result_var.set("✅ Key reconstructed successfully")

            except Exception as e:
                messagebox.showerror("Reconstruction Failed",
                                     f"Failed to reconstruct key:\n{e}", parent=dlg)
                return

            def copy_key():
                self.parent.clipboard_clear()
                self.parent.clipboard_append(full_b64)
                messagebox.showinfo("Copied",
                                    "Recovery key copied to clipboard.\n"
                                    "Use it immediately and clear clipboard.",
                                    parent=dlg)

            copy_frame = ttk.Frame(parent)
            copy_frame.pack(fill=tk.X, pady=(0, 5))
            ttk.Button(copy_frame, text="Copy to Clipboard",
                       command=copy_key, bootstyle="warning").pack(side=tk.LEFT)

        ttk.Label(parent, textvariable=result_var,
                  font=("Segoe UI", 9), bootstyle="success").pack(anchor="w", pady=(0, 8))

        dlg = parent.winfo_toplevel()
        ttk.Button(parent, text="Reconstruct Key", command=do_reconstruct,
                   bootstyle="warning").pack(anchor="w")

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
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

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
                            "Active",
                        ))
                except Exception:
                    pass

        load_status()

        ttk.Button(parent, text="Refresh", command=load_status,
                   bootstyle="warning-outline").pack(anchor="e", pady=(5, 0))
