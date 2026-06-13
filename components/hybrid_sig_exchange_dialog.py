import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

from services.friends_service import FriendsService, FriendsServiceError
from views.utils import password_dialog


class HybridSigExchangeDialog:
    def __init__(self, parent, friends_service: FriendsService, bg: str, refresh_list, trust_chain_service=None):
        self.parent = parent
        self.friends_service = friends_service
        self.bg = bg
        self.refresh_list = refresh_list
        self.trust_chain_service = trust_chain_service

    def show(self):
        pqc_pw = password_dialog(
            self.parent,
            "✍️ Hybrid Signature Key Exchange – Master Password Required",
            confirm=False,
        )
        if not pqc_pw:
            return
        if not self.friends_service.verify_password(pqc_pw):
            messagebox.showerror(
                "Access Denied",
                "Incorrect master password.\n"
                "Hybrid signature key exchange requires authentication.",
                parent=self.parent,
            )
            return

        dlg = tk.Toplevel(self.parent)
        dlg.title("✍️ Hybrid Signature Key Exchange (Ed25519 + Dilithium3)")
        dlg.geometry("680x680")
        dlg.resizable(True, True)
        dlg.minsize(580, 580)
        dlg.transient(self.parent)
        dlg.grab_set()
        dlg.configure(bg=self.bg)

        notebook = ttk.Notebook(dlg, bootstyle="success")
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))

        tab_keys = ttk.Frame(notebook, padding=15)
        notebook.add(tab_keys, text="  My Signing Keys  ")

        my_pub_text = ttk.ScrolledText(tab_keys, height=4, wrap=tk.WORD,
                                       font=("Consolas", 9), state='disabled')
        my_status_var = tk.StringVar(value="Checking...")
        my_fp_var = tk.StringVar(value="")

        def load_my_hybrid_sig():
            pub_b64 = self.friends_service.get_my_hybrid_sig_combined_pub()
            my_pub_text.config(state='normal')
            my_pub_text.delete('1.0', tk.END)
            if pub_b64:
                my_pub_text.insert('1.0', pub_b64)
                my_status_var.set(f"✅ Hybrid signing keys loaded ({len(pub_b64)} chars Base64)")
                fp = self.friends_service.get_hybrid_sig_key_fingerprint(pub_b64)
                my_fp_var.set(f"Fingerprint: {fp}" if fp else "Fingerprint: error")
            else:
                my_pub_text.insert('1.0', "(No hybrid signing keys generated yet)")
                my_status_var.set("⚠ No hybrid signing keys. Click 'Generate' to create.")
                my_fp_var.set("")
            my_pub_text.config(state='disabled')

        load_my_hybrid_sig()

        ttk.Label(tab_keys,
                  text="Hybrid Signing Combined Public Key (Ed25519 + Dilithium3/ML-DSA-65):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        my_pub_text.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(tab_keys, textvariable=my_status_var,
                  font=("Segoe UI", 9), bootstyle="secondary").pack(anchor="w", pady=(0, 4))
        ttk.Label(tab_keys, textvariable=my_fp_var,
                  font=("Consolas", 9), bootstyle="warning").pack(anchor="w", pady=(0, 8))

        ttk.Label(tab_keys,
                  text="Hybrid signatures combine classical Ed25519 with post-quantum\n"
                       "Dilithium3 (ML-DSA-65). BOTH must verify for authenticity.\n"
                       "Share your combined public key with friends so they can verify your messages.",
                  font=("Segoe UI", 9), bootstyle="info", wraplength=600).pack(anchor="w", pady=(0, 8))

        btn_row_keys = ttk.Frame(tab_keys)
        btn_row_keys.pack(fill=tk.X)

        def copy_my_hybrid_sig():
            content = my_pub_text.get('1.0', tk.END).strip()
            if content and not content.startswith("("):
                self.parent.clipboard_clear()
                self.parent.clipboard_append(content)
                messagebox.showinfo("Copied",
                                    "Hybrid signing combined public key copied to clipboard.",
                                    parent=dlg)

        def generate_hybrid_sig():
            pw = password_dialog(dlg,
                                 "Enter Master Password to generate hybrid signing keys",
                                 confirm=False)
            if not pw:
                return
            if not self.friends_service.verify_password(pw):
                messagebox.showerror("Wrong Password", "Master password incorrect.",
                                     parent=dlg)
                return
            try:
                pub_b64 = self.friends_service.generate_hybrid_sig_keys(pw)
                load_my_hybrid_sig()
                messagebox.showinfo(
                    "Success",
                    "Hybrid signing keys generated successfully!\n\n"
                    "Share your combined public key with friends so they can\n"
                    "verify your post-quantum secure signatures.",
                    parent=dlg
                )
            except FriendsServiceError as e:
                messagebox.showerror("Error", str(e), parent=dlg)

        def export_certs_with_key():
            """Copy public key AND pending certificates to clipboard."""
            content = my_pub_text.get('1.0', tk.END).strip()
            if not content or content.startswith("("):
                messagebox.showwarning("No Key", "Generate signing keys first.", parent=dlg)
                return
            if self.trust_chain_service is None:
                messagebox.showinfo("No Certificates", "Trust chain service not available.", parent=dlg)
                return
            pending = self.trust_chain_service.get_pending_certs_for_exchange()
            if not pending:
                # Just copy the key
                parent.clipboard_clear()
                parent.clipboard_append(content)
                messagebox.showinfo("Copied", "No pending certificates. Public key copied.", parent=dlg)
                return
            import json
            bundle = {
                "public_key": content,
                "certificates": [c for c in pending]
            }
            bundle_b64 = __import__('base64').b64encode(json.dumps(bundle).encode()).decode()
            parent.clipboard_clear()
            parent.clipboard_append(bundle_b64)
            messagebox.showinfo("Copied",
                f"Public key + {len(pending)} certificate(s) copied to clipboard.\n\n"
                "Share this with friends to propagate trust.",
                parent=dlg)

        ttk.Button(btn_row_keys, text="📋 Copy Public Key", command=copy_my_hybrid_sig,
                   bootstyle="success-outline").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_row_keys, text="📋 Export Key + Certificates", command=export_certs_with_key,
                   bootstyle="info-outline").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_row_keys, text="🔑 Generate New Signing Keys",
                   command=generate_hybrid_sig,
                   bootstyle="success").pack(side=tk.LEFT)

        tab_import = ttk.Frame(notebook, padding=15)
        notebook.add(tab_import, text="  Import Friend Key  ")

        ttk.Label(tab_import,
                  text="Import a friend's hybrid signing combined public key to verify\n"
                       "their messages with both Ed25519 and Dilithium3.",
                  font=("Segoe UI", 9), wraplength=600).pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_import, text="Friend:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        all_friend_names = self.friends_service.get_friend_names()
        import_friend_var = tk.StringVar()
        import_combo = ttk.Combobox(tab_import, textvariable=import_friend_var,
                                    values=all_friend_names, state="readonly",
                                    width=40, bootstyle="success")
        import_combo.pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_import, text="Friend's Hybrid Signing Combined Public Key (Base64):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        import_key_text = ttk.ScrolledText(tab_import, height=4, wrap=tk.WORD,
                                           font=("Consolas", 9))
        import_key_text.pack(fill=tk.X, pady=(0, 4))

        import_fp_var = tk.StringVar(value="")
        ttk.Label(tab_import, textvariable=import_fp_var,
                  font=("Consolas", 9), bootstyle="warning").pack(anchor="w", pady=(0, 10))

        def update_import_fp(*args):
            content = import_key_text.get('1.0', tk.END).strip()
            if not content:
                import_fp_var.set("")
                return
            fp = self.friends_service.get_hybrid_sig_key_fingerprint(content)
            import_fp_var.set(f"Fingerprint: {fp}" if fp else "⚠ Invalid Base64")

        import_key_text.bind('<KeyRelease>', lambda e: update_import_fp())

        import_status_var = tk.StringVar(value="")
        ttk.Label(tab_import, textvariable=import_status_var,
                  font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 8))

        ttk.Separator(tab_import, orient='horizontal').pack(fill=tk.X, pady=8)

        ttk.Label(tab_import, text="Or paste a key bundle (public key + certificates):",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        bundle_text = ttk.ScrolledText(tab_import, height=3, wrap=tk.WORD,
                                        font=("Consolas", 9))
        bundle_text.pack(fill=tk.X, pady=(0, 4))

        bundle_status_var = tk.StringVar(value="")
        ttk.Label(tab_import, textvariable=bundle_status_var,
                  font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 4))

        def do_import_hybrid_sig_key():
            fname = import_friend_var.get()
            key_b64 = import_key_text.get('1.0', tk.END).strip()
            bundle_content = bundle_text.get('1.0', tk.END).strip()

            # Try bundle import first if key field is empty
            if not key_b64 and bundle_content:
                try:
                    import json
                    import base64 as b64mod
                    bundle_data = json.loads(b64mod.b64decode(bundle_content).decode())
                    key_b64 = bundle_data.get("public_key", "")
                    # Import certificates if present
                    if self.trust_chain_service and bundle_data.get("certificates"):
                        count = self.trust_chain_service.import_received_certs(bundle_data["certificates"])
                        bundle_status_var.set(f"✅ Imported {count} certificate(s)")
                except Exception as e:
                    messagebox.showerror("Invalid Bundle", f"Could not parse key bundle: {e}", parent=dlg)
                    return

            if not fname:
                messagebox.showwarning("No Selection", "Please select a friend.",
                                       parent=dlg)
                return
            if not key_b64:
                messagebox.showwarning("Empty Key",
                                       "Please paste the hybrid signing combined public key.",
                                       parent=dlg)
                return
            # ... rest of existing import logic stays the same
            pw = ""
            secret = self.friends_service.get_friend_secret(fname)
            if secret:
                pw = password_dialog(
                    dlg,
                    "Enter Master Password to encrypt shared secret",
                    confirm=False,
                )
                if not pw:
                    return
                if not self.friends_service.verify_password(pw):
                    messagebox.showerror("Wrong Password",
                                         "Master password incorrect.",
                                         parent=dlg)
                    return
            try:
                self.friends_service.import_friend_hybrid_sig_pub(
                    friend_name=fname,
                    combined_pub_b64=key_b64,
                    master_password=pw,
                )
                self.refresh_list()
                import_status_var.set(f"✅ Hybrid signing key imported for '{fname}'")
                messagebox.showinfo("Success",
                                    f"Hybrid signing combined public key saved for '{fname}'.\n\n"
                                    "Messages from this friend will now be verified with\n"
                                    "both Ed25519 and Dilithium3.",
                                    parent=dlg)
            except FriendsServiceError as e:
                messagebox.showerror("Import Failed", str(e), parent=dlg)

        ttk.Button(tab_import, text="💾 Import & Save Signing Key",
                   command=do_import_hybrid_sig_key, bootstyle="success").pack(anchor="w")

        tab_status = ttk.Frame(notebook, padding=15)
        notebook.add(tab_status, text="  Status  ")

        ttk.Label(tab_status,
                  text="Hybrid Signing Key Status Overview",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 10))

        my_pub = self.friends_service.get_my_hybrid_sig_combined_pub()
        my_key_status = "✅ Generated" if my_pub else "❌ Not generated"
        ttk.Label(tab_status, text=f"My Hybrid Signing Keys: {my_key_status}",
                  font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 4))

        if my_pub:
            fp = self.friends_service.get_hybrid_sig_key_fingerprint(my_pub)
            ttk.Label(tab_status, text=f"  Fingerprint: {fp}",
                      font=("Consolas", 9), bootstyle="warning").pack(anchor="w", pady=(0, 8))

        ttk.Separator(tab_status, orient='horizontal').pack(fill=tk.X, pady=8)

        ttk.Label(tab_status, text="Friends with Hybrid Signing Keys:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))

        friends_frame = ttk.Frame(tab_status)
        friends_frame.pack(fill=tk.X)

        friends_with_hybrid = [
            f for f in self.friends_service.get_all_friends()
            if f.get("has_hybrid_sig_key")
        ]
        if friends_with_hybrid:
            for f in friends_with_hybrid:
                ttk.Label(friends_frame,
                          text=f"  ✍️ {f['name']}",
                          font=("Segoe UI", 10), bootstyle="success").pack(anchor="w")
        else:
            ttk.Label(friends_frame,
                      text="  (No friends have hybrid signing keys configured yet)",
                      font=("Segoe UI", 9), bootstyle="secondary").pack(anchor="w")

        ttk.Separator(tab_status, orient='horizontal').pack(fill=tk.X, pady=8)

        total_friends = len(self.friends_service.get_all_friends())
        hybrid_sig_friends = len(friends_with_hybrid)
        ttk.Label(tab_status,
                  text=f"Summary: {hybrid_sig_friends}/{total_friends} friends with hybrid signing keys",
                  font=("Segoe UI", 9)).pack(anchor="w")

        ttk.Button(dlg, text="Close", command=dlg.destroy,
                   bootstyle="secondary-outline").pack(pady=(0, 10))
