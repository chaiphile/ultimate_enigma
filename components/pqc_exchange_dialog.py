import tkinter as tk
from tkinter import messagebox, simpledialog
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import base64

from services.friends_service import FriendsService, FriendsServiceError
from views.utils import password_dialog


class PqcExchangeDialog:
    def __init__(self, parent, friends_service: FriendsService, bg: str, refresh_list):
        self.parent = parent
        self.friends_service = friends_service
        self.bg = bg
        self.refresh_list = refresh_list

    def show(self):
        pqc_pw = password_dialog(
            self.parent,
            "🛡 PQC Key Exchange – Master Password Required",
            confirm=False,
        )
        if not pqc_pw:
            return
        if not self.friends_service.verify_password(pqc_pw):
            messagebox.showerror(
                "Access Denied",
                "Incorrect master password.\n"
                "PQC key exchange requires authentication.",
                parent=self.parent,
            )
            return

        dlg = tk.Toplevel(self.parent)
        dlg.title("🛡 Post-Quantum Hybrid Key Exchange")
        dlg.geometry("680x720")
        dlg.resizable(True, True)
        dlg.minsize(580, 600)
        dlg.transient(self.parent)
        dlg.grab_set()
        dlg.configure(bg=self.bg)

        notebook = ttk.Notebook(dlg, bootstyle="primary")
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))

        tab_keys = ttk.Frame(notebook, padding=15)
        notebook.add(tab_keys, text="  My PQC Keys  ")

        my_pub_text = ttk.ScrolledText(tab_keys, height=4, wrap=tk.WORD,
                                       font=("Consolas", 9), state='disabled')
        my_status_var = tk.StringVar(value="Checking...")

        def load_my_pqc():
            pub_b64 = self.friends_service.get_my_pqc_combined_pub()
            my_pub_text.config(state='normal')
            my_pub_text.delete('1.0', tk.END)
            if pub_b64:
                my_pub_text.insert('1.0', pub_b64)
                my_status_var.set(f"✅ PQC keys loaded ({len(pub_b64)} chars Base64)")
            else:
                my_pub_text.insert('1.0', "(No PQC keys generated yet)")
                my_status_var.set("⚠ No PQC keys. Click 'Generate' to create.")
            my_pub_text.config(state='disabled')

        load_my_pqc()

        ttk.Label(tab_keys, text="My PQC Combined Public Key (X25519 + Kyber768):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        my_pub_text.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(tab_keys, textvariable=my_status_var,
                  font=("Segoe UI", 9), bootstyle="secondary").pack(anchor="w", pady=(0, 8))

        btn_row_keys = ttk.Frame(tab_keys)
        btn_row_keys.pack(fill=tk.X)

        def copy_my_pqc():
            content = my_pub_text.get('1.0', tk.END).strip()
            if content and not content.startswith("("):
                self.parent.clipboard_clear()
                self.parent.clipboard_append(content)
                messagebox.showinfo("Copied", "PQC combined public key copied to clipboard.",
                                    parent=dlg)

        def generate_pqc():
            pw = password_dialog(dlg, "Enter Master Password to generate PQC keys",
                                 confirm=False)
            if not pw:
                return
            if not self.friends_service.verify_password(pw):
                messagebox.showerror("Wrong Password", "Master password incorrect.",
                                     parent=dlg)
                return
            try:
                pub_b64 = self.friends_service.generate_pqc_keys(pw)
                load_my_pqc()
                messagebox.showinfo(
                    "Success",
                    "PQC hybrid keys generated successfully!\n\n"
                    "Share your combined public key with friends to enable\n"
                    "quantum-resistant key exchange.",
                    parent=dlg
                )
            except FriendsServiceError as e:
                messagebox.showerror("Error", str(e), parent=dlg)

        ttk.Button(btn_row_keys, text="📋 Copy Public Key", command=copy_my_pqc,
                   bootstyle="info-outline").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_row_keys, text="🔑 Generate New PQC Keys", command=generate_pqc,
                   bootstyle="info").pack(side=tk.LEFT)

        tab_encap = ttk.Frame(notebook, padding=15)
        notebook.add(tab_encap, text="  Encapsulate (Send)  ")

        ttk.Label(tab_encap,
                  text="Select a friend with a stored PQC public key to derive a shared secret.",
                  font=("Segoe UI", 9), wraplength=600).pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_encap, text="Friend:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        friend_names = [f["name"] for f in self.friends_service.get_all_friends()
                        if f.get("has_pqc_key")]
        encap_friend_var = tk.StringVar()
        encap_combo = ttk.Combobox(tab_encap, textvariable=encap_friend_var,
                                   values=friend_names, state="readonly",
                                   width=40, bootstyle="primary")
        encap_combo.pack(anchor="w", pady=(0, 10))

        encap_result_text = ttk.ScrolledText(tab_encap, height=5, wrap=tk.WORD,
                                             font=("Consolas", 9), state='disabled')
        encap_result_text.pack(fill=tk.X, pady=(0, 4))
        encap_status_var = tk.StringVar(value="")
        ttk.Label(tab_encap, textvariable=encap_status_var,
                  font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 8))

        def do_encapsulate():
            fname = encap_friend_var.get()
            if not fname:
                messagebox.showwarning("No Selection", "Please select a friend.",
                                       parent=dlg)
                return
            try:
                ct_b64, shared_secret = self.friends_service.pqc_encapsulate(fname, "")
                encap_result_text.config(state='normal')
                encap_result_text.delete('1.0', tk.END)
                encap_result_text.insert('1.0',
                    f"=== CIPHERTEXT TO SEND TO {fname} ===\n{ct_b64}\n\n"
                    f"=== DERIVED SHARED SECRET (Base64) ===\n"
                    f"{base64.b64encode(shared_secret).decode()}\n\n"
                    f"Secret fingerprint: {base64.b64encode(shared_secret[:8]).decode()}")
                encap_result_text.config(state='disabled')
                encap_status_var.set(
                    f"✅ Shared secret derived! Send the ciphertext above to {fname}."
                )
                save_pw = password_dialog(
                    dlg,
                    "Enter Master Password to save the derived shared secret",
                    confirm=False
                )
                if save_pw and self.friends_service.verify_password(save_pw):
                    self.friends_service.update_shared_secret(
                        name=fname,
                        new_secret=shared_secret,
                        master_password=save_pw,
                    )
                    self.refresh_list()
                    encap_status_var.set(
                        f"✅ Shared secret saved for '{fname}' AND ciphertext ready to send."
                    )
            except FriendsServiceError as e:
                messagebox.showerror("Encapsulation Failed", str(e), parent=dlg)

        def copy_encap_result():
            content = encap_result_text.get('1.0', tk.END).strip()
            if content:
                lines = content.split('\n')
                ct_line = ""
                in_ct = False
                for line in lines:
                    if "CIPHERTEXT" in line:
                        in_ct = True
                        continue
                    if in_ct and line.strip() and not line.startswith("="):
                        ct_line = line.strip()
                        break
                if ct_line:
                    self.parent.clipboard_clear()
                    self.parent.clipboard_append(ct_line)
                    messagebox.showinfo("Copied", "Ciphertext copied to clipboard.",
                                        parent=dlg)

        encap_btn_row = ttk.Frame(tab_encap)
        encap_btn_row.pack(fill=tk.X)
        ttk.Button(encap_btn_row, text="🔒 Encapsulate & Derive Secret",
                   command=do_encapsulate, bootstyle="info").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(encap_btn_row, text="📋 Copy Ciphertext",
                   command=copy_encap_result, bootstyle="info-outline").pack(side=tk.LEFT)

        tab_decap = ttk.Frame(notebook, padding=15)
        notebook.add(tab_decap, text="  Decapsulate (Receive)  ")

        ttk.Label(tab_decap,
                  text="Paste the ciphertext received from a friend to recover the shared secret.",
                  font=("Segoe UI", 9), wraplength=600).pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_decap, text="Received Ciphertext (Base64):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        decap_input = ttk.ScrolledText(tab_decap, height=4, wrap=tk.WORD,
                                       font=("Consolas", 9))
        decap_input.pack(fill=tk.X, pady=(0, 10))

        decap_result_var = tk.StringVar(value="")
        ttk.Label(tab_decap, textvariable=decap_result_var,
                  font=("Consolas", 9), wraplength=600).pack(anchor="w", pady=(0, 8))

        def do_decapsulate():
            ct_b64 = decap_input.get('1.0', tk.END).strip()
            if not ct_b64:
                messagebox.showwarning("Empty Input",
                                       "Please paste a ciphertext first.", parent=dlg)
                return
            pw = password_dialog(dlg, "Enter Master Password for PQC decapsulation",
                                 confirm=False)
            if not pw:
                return
            if not self.friends_service.verify_password(pw):
                messagebox.showerror("Wrong Password", "Master password incorrect.",
                                     parent=dlg)
                return
            try:
                shared_secret = self.friends_service.pqc_decapsulate(ct_b64, pw)
                ss_b64 = base64.b64encode(shared_secret).decode()
                fp = base64.b64encode(shared_secret[:8]).decode()
                decap_result_var.set(
                    f"✅ Shared secret recovered!\n"
                    f"Secret (Base64): {ss_b64}\n"
                    f"Fingerprint: {fp}\n\n"
                    f"You can now use this secret for encrypted communication."
                )
                all_names = self.friends_service.get_friend_names()
                if all_names:
                    save_for = simpledialog.askstring(
                        "Save Shared Secret",
                        "Optionally save this secret for a friend:\n"
                        f"{', '.join(all_names)}\n\n"
                        "(Leave empty to skip saving)",
                        parent=dlg
                    )
                    if save_for and save_for in all_names:
                        self.friends_service.update_shared_secret(
                            name=save_for,
                            new_secret=shared_secret,
                            master_password=pw,
                        )
                        self.refresh_list()
                        decap_result_var.set(
                            f"✅ Shared secret recovered AND saved for '{save_for}'!\n"
                            f"Fingerprint: {fp}"
                        )
            except FriendsServiceError as e:
                messagebox.showerror("Decapsulation Failed", str(e), parent=dlg)

        ttk.Button(tab_decap, text="🔓 Decapsulate & Recover Secret",
                   command=do_decapsulate, bootstyle="info").pack(anchor="w")

        tab_import = ttk.Frame(notebook, padding=15)
        notebook.add(tab_import, text="  Import Friend Key  ")

        ttk.Label(tab_import,
                  text="Import a friend's PQC combined public key for future encapsulation.",
                  font=("Segoe UI", 9), wraplength=600).pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_import, text="Friend:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        all_friend_names = self.friends_service.get_friend_names()
        import_friend_var = tk.StringVar()
        import_combo = ttk.Combobox(tab_import, textvariable=import_friend_var,
                                    values=all_friend_names, state="readonly",
                                    width=40, bootstyle="primary")
        import_combo.pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_import, text="Friend's PQC Combined Public Key (Base64):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        import_key_text = ttk.ScrolledText(tab_import, height=4, wrap=tk.WORD,
                                           font=("Consolas", 9))
        import_key_text.pack(fill=tk.X, pady=(0, 10))

        import_status_var = tk.StringVar(value="")
        ttk.Label(tab_import, textvariable=import_status_var,
                  font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 8))

        def do_import_pqc_key():
            fname = import_friend_var.get()
            key_b64 = import_key_text.get('1.0', tk.END).strip()
            if not fname:
                messagebox.showwarning("No Selection", "Please select a friend.",
                                       parent=dlg)
                return
            if not key_b64:
                messagebox.showwarning("Empty Key",
                                       "Please paste the PQC combined public key.",
                                       parent=dlg)
                return
            try:
                raw = base64.b64decode(key_b64)
                if len(raw) < 36:
                    raise ValueError("Too short")
            except Exception as e:
                messagebox.showerror("Invalid Key",
                                     f"Invalid PQC combined public key: {e}",
                                     parent=dlg)
                return
            details = self.friends_service.get_friend_details(fname)
            if not details:
                messagebox.showerror("Error", f"Friend '{fname}' not found.",
                                     parent=dlg)
                return
            try:
                secret = self.friends_service.get_friend_secret(fname)
                x_b64 = self.friends_service.get_friend_x25519_key(fname)
                caps = self.friends_service.get_friend_capabilities(fname)

                pw = ""
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

                self.friends_service.add_friend(
                    name=fname,
                    public_key_pem=details["public_key_pem"],
                    shared_secret=secret,
                    master_password=pw,
                    x25519_pub_b64=x_b64,
                    capabilities=caps if caps else None,
                    pqc_combined_pub_b64=key_b64,
                )
                self.refresh_list()
                import_status_var.set(f"✅ PQC key imported for '{fname}'")
                messagebox.showinfo("Success",
                                    f"PQC combined public key saved for '{fname}'.",
                                    parent=dlg)
            except FriendsServiceError as e:
                messagebox.showerror("Import Failed", str(e), parent=dlg)

        ttk.Button(tab_import, text="💾 Import & Save PQC Key",
                   command=do_import_pqc_key, bootstyle="info").pack(anchor="w")

        ttk.Button(dlg, text="Close", command=dlg.destroy,
                   bootstyle="secondary-outline").pack(pady=(0, 10))
