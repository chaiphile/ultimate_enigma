import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import base64

from services.friends import FriendsService, FriendsServiceError
from services.event_bus import event_bus, Events
from views.dialogs import password_dialog
from views.utils import init_modal, friendly_error, ToolTip


class AddFriendDialog:
    def __init__(self, parent, friends_service: FriendsService, bg: str, refresh_list):
        self.parent = parent
        self.friends_service = friends_service
        self.bg = bg
        self.refresh_list = refresh_list

    def show(self):
        dlg = tk.Toplevel(self.parent)
        dlg.title("Add Friend")
        dlg.geometry("580x850")
        dlg.resizable(True, True)
        dlg.minsize(580, 800)
        dlg.transient(self.parent)
        dlg.grab_set()
        dlg.configure(bg=self.bg)

        form = ttk.Frame(dlg, padding=20)
        form.pack(fill=tk.BOTH, expand=True)

        ttk.Label(form, text="Friend's Name:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        name_var = tk.StringVar()
        name_entry = ttk.Entry(form, textvariable=name_var, width=50,
                  bootstyle="primary")
        name_entry.pack(fill=tk.X, pady=(0, 12))

        ttk.Label(form, text="Friend's Public Key (PEM):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        key_text = ttk.ScrolledText(form, height=6, width=55, font=("Consolas", 9))
        key_text.pack(fill=tk.X, pady=(0, 12))

        ttk.Label(form, text="Shared Secret (Base64, optional):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        secret_var = tk.StringVar()
        ttk.Entry(form, textvariable=secret_var, width=50,
                  bootstyle="primary").pack(fill=tk.X, pady=(0, 12))

        ttk.Label(form, text="X25519 Public Key (Base64, optional):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        x25519_var = tk.StringVar()
        x25519_entry = ttk.Entry(form, textvariable=x25519_var, width=50,
                                 bootstyle="primary")
        x25519_entry.pack(fill=tk.X, pady=(0, 4))
        x25519_fp_var = tk.StringVar(value="")
        ttk.Label(form, textvariable=x25519_fp_var,
                  font=("Consolas", 9), bootstyle="warning").pack(anchor="w", pady=(0, 8))

        ttk.Label(form, text="PQC Combined Public Key (Base64, optional):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        pqc_var = tk.StringVar()
        pqc_entry = ttk.Entry(form, textvariable=pqc_var, width=50,
                              bootstyle="info")
        pqc_entry.pack(fill=tk.X, pady=(0, 4))
        pqc_status_var = tk.StringVar(value="")
        ttk.Label(form, textvariable=pqc_status_var,
                  font=("Consolas", 9), bootstyle="info").pack(anchor="w", pady=(0, 8))

        def update_pqc_status(*args):
            b64 = pqc_var.get().strip()
            if not b64:
                pqc_status_var.set("")
                return
            try:
                raw = base64.b64decode(b64)
                if len(raw) < 36:
                    pqc_status_var.set("⚠ Too short for valid PQC combined public key")
                    return
                pqc_status_var.set(f"✅ Valid PQC combined public key ({len(raw)} bytes)")
            except Exception:
                pqc_status_var.set("⚠ Invalid Base64")

        pqc_var.trace_add('write', update_pqc_status)

        ttk.Label(form, text="Hybrid Signing Combined Public Key (Base64, optional):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        hybrid_sig_var = tk.StringVar()
        hybrid_sig_entry = ttk.Entry(form, textvariable=hybrid_sig_var, width=50,
                                     bootstyle="info")
        hybrid_sig_entry.pack(fill=tk.X, pady=(0, 4))
        hybrid_sig_status_var = tk.StringVar(value="")
        ttk.Label(form, textvariable=hybrid_sig_status_var,
                  font=("Consolas", 9), bootstyle="info").pack(anchor="w", pady=(0, 8))

        def update_hybrid_sig_status(*args):
            b64 = hybrid_sig_var.get().strip()
            if not b64:
                hybrid_sig_status_var.set("")
                return
            try:
                raw = base64.b64decode(b64)
                if len(raw) < 36:
                    hybrid_sig_status_var.set("⚠ Too short for valid hybrid signing combined public key")
                    return
                hybrid_sig_status_var.set(f"✅ Valid hybrid signing combined public key ({len(raw)} bytes)")
            except Exception:
                hybrid_sig_status_var.set("⚠ Invalid Base64")

        hybrid_sig_var.trace_add('write', update_hybrid_sig_status)

        caps_frame = ttk.Frame(form)
        caps_frame.pack(fill=tk.X, pady=(0, 8))
        dr_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(caps_frame, text="Supports Double Ratchet Protocol",
                        variable=dr_var, bootstyle="round-toggle").pack(side=tk.LEFT)

        def update_x25519_fp(*args):
            b64 = x25519_var.get().strip()
            if not b64:
                x25519_fp_var.set("")
                return
            try:
                raw = base64.b64decode(b64)
                if len(raw) != 32:
                    x25519_fp_var.set("⚠ Invalid length (must be 32 bytes)")
                    return
                from crypto import sha256_fingerprint
                fp = sha256_fingerprint(raw)
                x25519_fp_var.set(f"✅ X25519 Fingerprint: {fp}")
            except Exception:
                x25519_fp_var.set("⚠ Invalid Base64")

        x25519_var.trace_add('write', update_x25519_fp)

        btn_frame = ttk.Frame(dlg, padding=(20, 10))
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)

        init_modal(dlg, self.parent, focus_widget=name_entry)

        def save():
            name = name_var.get().strip()
            pem = key_text.get("1.0", tk.END).strip()
            secret_b64 = secret_var.get().strip()
            x_b64 = x25519_var.get().strip() or None

            if not name or not pem:
                messagebox.showerror("Error", "Name and public key are required.", parent=dlg)
                return

            shared_secret = None
            pw = ""
            if secret_b64:
                try:
                    shared_secret = base64.b64decode(secret_b64)
                    if len(shared_secret) != 32:
                        raise ValueError("Shared secret must be exactly 32 bytes when Base64-decoded.")
                except Exception as e:
                    messagebox.showerror("Invalid Shared Secret",
                                         friendly_error(e), parent=dlg)
                    return
                pw = password_dialog(dlg,
                                     "Enter Master Password to encrypt friend's secret",
                                     confirm=False)
                if not pw:
                    return
                if not self.friends_service.verify_master_password(pw):
                    messagebox.showerror("Wrong Password",
                                         "The master password is incorrect.", parent=dlg)
                    return

            pqc_b64 = pqc_var.get().strip() or None
            hybrid_sig_b64 = hybrid_sig_var.get().strip() or None

            capabilities = {}
            if dr_var.get():
                capabilities["double_ratchet"] = True

            try:
                self.friends_service.add_friend(
                    name=name,
                    public_key_pem=pem,
                    shared_secret=shared_secret,
                    master_password=pw,
                    x25519_pub_b64=x_b64,
                    capabilities=capabilities if capabilities else None,
                    pqc_combined_pub_b64=pqc_b64,
                    hybrid_sig_pub_b64=hybrid_sig_b64,
                )
                self.refresh_list()
                dlg.destroy()
                messagebox.showinfo("Success", f"Friend '{name}' added successfully.")
                event_bus.publish(Events.FRIEND_LIST_CHANGED, source="friends_tab")
            except FriendsServiceError as e:
                messagebox.showerror("Error", friendly_error(e), parent=dlg)

        save_btn = ttk.Button(btn_frame, text="💾 Save Friend", command=save,
                              bootstyle="success")
        save_btn.pack(side=tk.RIGHT, padx=5)
        ToolTip(save_btn, "Save the new friend with the entered information")
        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=dlg.destroy,
                                bootstyle="secondary-outline")
        cancel_btn.pack(side=tk.RIGHT, padx=5)
        ToolTip(cancel_btn, "Cancel and close the window")
        dlg.bind("<Return>", lambda e: save())
