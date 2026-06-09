"""Friends management tab – using FriendsService for all friend operations."""

import tkinter as tk
from tkinter import messagebox, simpledialog
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import base64

# Import the service
from services.friends_service import FriendsService, FriendsServiceError
from utils import password_dialog


class FriendsTab:
    def __init__(self, parent, app):
        self.app = app
        self.frame = ttk.Frame(parent)
        self.all_friend_names = []
        self._build_ui()

    # ---- UI construction (unchanged) ----
    def _build_ui(self):
        # Top button bar
        top_bar = ttk.Frame(self.frame, padding=(10, 5))
        top_bar.pack(fill=tk.X)

        ttk.Button(top_bar, text="➕ Add Friend",
                   command=self.add_friend_dialog,
                   bootstyle="success").pack(side=tk.LEFT, padx=5)
        ttk.Button(top_bar, text="➖ Remove Friend",
                   command=self.remove_friend_dialog,
                   bootstyle="danger-outline").pack(side=tk.LEFT, padx=5)
        ttk.Button(top_bar, text="🔑 My Public Key",
                   command=self.show_my_pubkey,
                   bootstyle="info-outline").pack(side=tk.LEFT, padx=5)
        ttk.Button(top_bar, text="🔁 ECDH with Selected",
                   command=self.ecdh_with_selected,
                   bootstyle="secondary-outline").pack(side=tk.LEFT, padx=5)

        # Search
        search_frame = ttk.Frame(self.frame, padding=(10, 0))
        search_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame,
                                      textvariable=self.search_var,
                                      width=30,
                                      bootstyle="primary")
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_var.trace_add('write', lambda *a: self.filter_list())

        # Treeview
        list_frame = ttk.Labelframe(self.frame, text="Your Friends (name – fingerprint)",
                                    bootstyle="info")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = ("status", "name", "fingerprint")
        self.tree = ttk.Treeview(list_frame, columns=columns,
                                 show="headings",
                                 bootstyle="primary")
        self.tree.heading("status", text="🔑")
        self.tree.heading("name", text="Name")
        self.tree.heading("fingerprint", text="Fingerprint")
        self.tree.column("status", width=40, anchor="center")
        self.tree.column("name", width=120)
        self.tree.column("fingerprint", width=200)

        vsb = ttk.Scrollbar(list_frame, orient="vertical",
                            command=self.tree.yview,
                            bootstyle="round")
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        self.tree.bind('<<TreeviewSelect>>', self.on_select)

        # Detail view
        detail_frame = ttk.Labelframe(self.frame, text="Friend Details",
                                      bootstyle="info")
        detail_frame.pack(fill=tk.BOTH, padx=10, pady=5, ipady=5)
        self.detail_text = ttk.ScrolledText(detail_frame, height=5,
                                            wrap=tk.WORD,
                                            state='disabled')
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.refresh_list()

    # ---- Data refresh ----
    def refresh_list(self):
        # Use the service to get names
        self.all_friend_names = [
            friend["name"] for friend in self.app.friends_service.get_all_friends()
        ]
        self.filter_list()

    def filter_list(self):
        query = self.search_var.get().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Iterate over service data – every dict already has rsa_fingerprint
        for friend in self.app.friends_service.get_all_friends():
            name = friend["name"]
            if query in name.lower():
                status = "🔑" if friend["has_shared_secret"] else "   "
                self.tree.insert(
                    "", tk.END,
                    values=(status, name, friend["rsa_fingerprint"])
                )

    # ---- Event handlers ----
    def on_select(self, event=None):
        selected = self.tree.selection()
        if not selected:
            return
        item = self.tree.item(selected[0])
        name = item['values'][1]

        # Fetch details directly from service
        details = self.app.friends_service.get_friend_details(name)
        if not details:
            return

        info = (
            f"Name: {details['name']}\n"
            f"RSA Fingerprint: {details['rsa_fingerprint']}\n"
            f"Has shared secret: {'Yes' if details['has_shared_secret'] else 'No'}\n"
        )
        ecdh_fp = details.get("ecdh_fingerprint")
        if ecdh_fp:
            info += f"ECDH Key Fingerprint: {ecdh_fp}\n"
        else:
            info += "ECDH Key Fingerprint: Not set\n"

        info += f"\nPublic key:\n{details['public_key_pem']}"

        self.detail_text.config(state='normal')
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.insert('1.0', info)
        self.detail_text.config(state='disabled')

    # ---- Dialogs ----
    def add_friend_dialog(self):
        dlg = tk.Toplevel(self.app.root)
        dlg.title("Add Friend")
        dlg.geometry("550x530")
        dlg.resizable(False, False)
        dlg.transient(self.app.root)
        dlg.grab_set()
        dlg.configure(bg=self.app.style.colors.bg)

        ttk.Label(dlg, text="Friend's Name:").pack(pady=(15, 5))
        name_var = tk.StringVar()
        ttk.Entry(dlg, textvariable=name_var, width=40,
                  bootstyle="primary").pack(pady=5)

        ttk.Label(dlg, text="Friend's Public Key (PEM):").pack(pady=(10, 5))
        key_text = ttk.ScrolledText(dlg, height=6, width=50)
        key_text.pack(pady=5)

        ttk.Label(dlg, text="Shared Secret (Base64, optional):").pack(pady=(10, 5))
        secret_var = tk.StringVar()
        ttk.Entry(dlg, textvariable=secret_var, width=50,
                  bootstyle="primary").pack(pady=5)

        ttk.Label(dlg, text="X25519 Public Key (Base64, optional):").pack(pady=(10, 5))
        x25519_var = tk.StringVar()
        x25519_entry = ttk.Entry(dlg, textvariable=x25519_var, width=50,
                                 bootstyle="primary")
        x25519_entry.pack(pady=5)
        x25519_fp_var = tk.StringVar(value="")
        ttk.Label(dlg, textvariable=x25519_fp_var,
                  font=("Consolas", 9),
                  bootstyle="warning").pack()

        def update_x25519_fp(*args):
            b64 = x25519_var.get().strip()
            if not b64:
                x25519_fp_var.set("")
                return
            try:
                raw = base64.b64decode(b64)
                if len(raw) != 32:
                    x25519_fp_var.set("Invalid length (must be 32 bytes)")
                    return
                from crypto import sha256_fingerprint
                fp = sha256_fingerprint(raw)
                x25519_fp_var.set(f"X25519 Fingerprint: {fp}")
            except Exception:
                x25519_fp_var.set("Invalid Base64")

        x25519_var.trace_add('write', update_x25519_fp)

        def save():
            name = name_var.get().strip()
            pem = key_text.get("1.0", tk.END).strip()
            secret_b64 = secret_var.get().strip()
            x_b64 = x25519_var.get().strip() or None

            if not name or not pem:
                messagebox.showerror("Error", "Name and key are required.", parent=dlg)
                return

            shared_secret = None
            pw = ""
            if secret_b64:
                try:
                    shared_secret = base64.b64decode(secret_b64)
                    if len(shared_secret) != 32:
                        raise ValueError("Length must be 32 bytes")
                except Exception as e:
                    messagebox.showerror("Invalid Secret",
                                         f"Shared secret invalid: {e}",
                                         parent=dlg)
                    return
                pw = password_dialog(dlg,
                                     "Enter Master Password to encrypt friend's secret",
                                     confirm=False)
                if not pw:
                    return
                if not self.app.ks.verify_password(pw):
                    messagebox.showerror("Wrong Password",
                                         "Master password incorrect.",
                                         parent=dlg)
                    return

            # Optional X25519 validation is handled by the service,
            # but we do a quick length check for immediate feedback.
            if x_b64:
                try:
                    raw = base64.b64decode(x_b64)
                    if len(raw) != 32:
                        messagebox.showerror("Invalid",
                                             "X25519 key must be 32 bytes.",
                                             parent=dlg)
                        return
                except Exception:
                    messagebox.showerror("Invalid",
                                         "X25519 key is not valid Base64.",
                                         parent=dlg)
                    return

            try:
                # Delegate to service – it validates and saves
                self.app.friends_service.add_friend(
                    name=name,
                    public_key_pem=pem,
                    shared_secret=shared_secret,
                    master_password=pw,
                    x25519_pub_b64=x_b64,
                )
                self.refresh_list()
                self.app.encrypt_tab._update_friend_list()
                dlg.destroy()
                messagebox.showinfo("Success", f"Friend '{name}' added.")
            except FriendsServiceError as e:
                messagebox.showerror("Error", str(e), parent=dlg)

        ttk.Button(dlg, text="Save", command=save,
                   bootstyle="success").pack(pady=10)

    def remove_friend_dialog(self):
        # Use service to get names
        names = [friend["name"] for friend in self.app.friends_service.get_all_friends()]
        if not names:
            messagebox.showinfo("No Friends", "You have no friends to remove.")
            return
        choice = simpledialog.askstring("Remove Friend",
                                        f"Enter friend name to remove:\n{', '.join(names)}")
        if choice and choice in names:
            self.app.friends_service.remove_friend(choice)
            self.refresh_list()
            self.app.encrypt_tab._update_friend_list()
            messagebox.showinfo("Removed", f"Friend '{choice}' removed.")
        else:
            messagebox.showerror("Not Found", "Name not found in friend list.")

    def ecdh_with_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a friend from list.")
            return
        item = self.tree.item(selected[0])
        friend_name = item['values'][1]

        # Make sure friend exists (service will check later but we need PEM for info)
        friend_details = self.app.friends_service.get_friend_details(friend_name)
        if not friend_details:
            messagebox.showerror("Error", "Friend not found in database")
            return

        from ecdh import perform_ecdh
        result = perform_ecdh(self.app.root, purpose=f"friend: {friend_name}")
        if result is None:
            return
        new_secret, friend_x25519_b64 = result
        if new_secret:
            pw = password_dialog(self.app.root,
                                 "Enter master password to encrypt new shared secret",
                                 confirm=False)
            if pw:
                if not self.app.ks.verify_password(pw):
                    messagebox.showerror("Wrong Password", "Master password incorrect.")
                    return
                try:
                    # Use update_shared_secret (friend already exists)
                    self.app.friends_service.update_shared_secret(
                        name=friend_name,
                        new_secret=new_secret,
                        master_password=pw,
                        x25519_pub_b64=friend_x25519_b64,
                    )
                    self.refresh_list()
                    self.app.encrypt_tab._update_friend_list()
                    messagebox.showinfo(
                        "Success",
                        f"Shared secret for {friend_name} updated via ECDH.\n"
                        "ECDH public key saved."
                    )
                except FriendsServiceError as e:
                    messagebox.showerror("Error", str(e))

    def show_my_pubkey(self):
        # Use service – it will raise an error if no key loaded
        try:
            info = self.app.friends_service.get_my_public_info()
        except FriendsServiceError as e:
            messagebox.showerror("Error", str(e))
            return

        pem = info["public_key_pem"]
        fp = info["fingerprint"]

        top = tk.Toplevel(self.app.root)
        top.title("My Public Key")
        top.geometry("500x380")
        top.configure(bg=self.app.style.colors.bg)

        ttk.Label(top, text="My Public Key Fingerprint:",
                  font=("Segoe UI", 10, "bold"),
                  bootstyle="inverse-primary").pack(pady=(10, 0))
        ttk.Label(top, text=fp, font=("Consolas", 11),
                  bootstyle="inverse-secondary").pack(pady=(0, 10))

        txt = ttk.ScrolledText(top, wrap=tk.WORD)
        txt.insert("1.0", pem)
        txt.config(state='disabled')
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        def copy_pubkey():
            self.app.root.clipboard_clear()
            self.app.root.clipboard_append(pem)
            messagebox.showinfo("Copied", "Public key copied to clipboard.", parent=top)

        ttk.Button(top, text="Copy Public Key", command=copy_pubkey,
                   bootstyle="info").pack(pady=10)