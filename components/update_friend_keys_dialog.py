"""Dialog for updating a friend's public keys (RSA, ECDH, PQC, Hybrid Sig).

Each tab shows the current key status and lets the user paste a replacement.
Only the tabs where a new key is provided will be updated; existing keys in
all other slots are preserved.
"""

import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import base64

from services.friends import FriendsService, FriendsServiceError
from services.ecdh_service import ECDHService
from views.dialogs import password_dialog
from views.utils import init_modal, friendly_error
from src.crypto_utils import pem_to_pubkey, pubkey_to_pem
from crypto import sha256_fingerprint


class UpdateFriendKeysDialog:
    def __init__(self, parent, friends_service: FriendsService, bg: str,
                 refresh_list, preselect_name: str = ""):
        self.parent = parent
        self.friends_service = friends_service
        self.bg = bg
        self.refresh_list = refresh_list
        self.preselect_name = preselect_name
        self._master_pw = ""

    def show(self):
        pw = password_dialog(
            self.parent,
            "Update Friend Keys – Master Password Required",
            confirm=False,
        )
        if not pw:
            return
        if not self.friends_service.verify_master_password(pw):
            messagebox.showerror(
                "Access Denied",
                "Incorrect master password.",
                parent=self.parent,
            )
            return
        self._master_pw = pw
        self._build_dialog()

    def _build_dialog(self):
        dlg = tk.Toplevel(self.parent)
        dlg.title("Update Friend Public Keys")
        dlg.geometry("700x680")
        dlg.resizable(True, True)
        dlg.minsize(600, 580)
        dlg.transient(self.parent)
        dlg.grab_set()
        dlg.configure(bg=self.bg)

        init_modal(dlg, self.parent)

        # ── Friend selector ──────────────────────────────────────────────
        top = ttk.Frame(dlg, padding=(15, 12, 15, 6))
        top.pack(fill=tk.X)

        ttk.Label(top, text="Friend:", font=("Segoe UI", 10, "bold")).pack(
            side=tk.LEFT, padx=(0, 8))
        friend_names = self.friends_service.get_friend_names()
        preselect = self.preselect_name if self.preselect_name and self.preselect_name in friend_names else (friend_names[0] if friend_names else "")
        friend_var = tk.StringVar(value=preselect)
        friend_combo = ttk.Combobox(top, textvariable=friend_var,
                                    values=friend_names, state="readonly",
                                    width=35, bootstyle="primary")
        friend_combo.pack(side=tk.LEFT)

        status_var = tk.StringVar(value="")
        status_lbl = ttk.Label(dlg, textvariable=status_var,
                                font=("Segoe UI", 9), padding=(15, 0))
        status_lbl.pack(fill=tk.X)

        # ── Notebook tabs ────────────────────────────────────────────────
        nb = ttk.Notebook(dlg, bootstyle="primary")
        nb.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 4))

        # ── Helper: current-info label ────────────────────────────────────
        def make_current_label(parent_frame, text):
            lbl = ttk.Label(parent_frame, text=text,
                            font=("Consolas", 9), bootstyle="secondary",
                            wraplength=580, justify="left")
            lbl.pack(anchor="w", pady=(0, 8))
            return lbl

        # ════════════════════════════════════════════════════════════════
        # TAB 1: RSA Public Key
        # ════════════════════════════════════════════════════════════════
        tab_rsa = ttk.Frame(nb, padding=15)
        nb.add(tab_rsa, text="  RSA Key  ")

        ttk.Label(tab_rsa,
                  text="Replace the friend's RSA-4096 public key.\n"
                       "Use this after they rotate their master RSA key.",
                  font=("Segoe UI", 9), wraplength=580).pack(anchor="w", pady=(0, 8))

        rsa_current_var = tk.StringVar(value="")
        ttk.Label(tab_rsa, text="Current fingerprint:",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w")
        rsa_current_lbl = ttk.Label(tab_rsa, textvariable=rsa_current_var,
                                    font=("Consolas", 9), bootstyle="secondary")
        rsa_current_lbl.pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_rsa, text="New RSA Public Key (PEM):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        rsa_text = ttk.ScrolledText(tab_rsa, height=8, wrap=tk.WORD,
                                    font=("Consolas", 9))
        rsa_text.pack(fill=tk.X, pady=(0, 6))

        rsa_fp_var = tk.StringVar(value="")
        ttk.Label(tab_rsa, textvariable=rsa_fp_var,
                  font=("Consolas", 9), bootstyle="warning").pack(anchor="w", pady=(0, 6))

        def on_rsa_change(*_):
            pem = rsa_text.get("1.0", tk.END).strip()
            if not pem:
                rsa_fp_var.set("")
                return
            try:
                pub = pem_to_pubkey(pem)
                fp = sha256_fingerprint(pubkey_to_pem(pub).encode())
                rsa_fp_var.set(f"✅ New fingerprint: {fp}")
            except Exception as e:
                rsa_fp_var.set(f"⚠ Invalid PEM: {friendly_error(e)}")

        rsa_text.bind("<KeyRelease>", on_rsa_change)

        def do_update_rsa():
            fname = friend_var.get()
            if not fname:
                messagebox.showwarning("No Friend", "Select a friend first.", parent=dlg)
                return
            pem = rsa_text.get("1.0", tk.END).strip()
            if not pem:
                messagebox.showwarning("Empty", "Paste the new RSA public key.", parent=dlg)
                return
            try:
                self.friends_service.update_friend_pub_keys(
                    name=fname, master_password=self._master_pw, new_rsa_pem=pem)
                self.refresh_list()
                status_var.set(f"✅ RSA key updated for '{fname}'")
                messagebox.showinfo("Updated", f"RSA public key updated for '{fname}'.",
                                    parent=dlg)
                _refresh_current(fname)
            except FriendsServiceError as e:
                messagebox.showerror("Error", friendly_error(e), parent=dlg)

        ttk.Button(tab_rsa, text="🔑 Update RSA Key", command=do_update_rsa,
                   bootstyle="primary").pack(anchor="w")

        # ════════════════════════════════════════════════════════════════
        # TAB 2: ECDH (X25519)
        # ════════════════════════════════════════════════════════════════
        tab_ecdh = ttk.Frame(nb, padding=15)
        nb.add(tab_ecdh, text="  ECDH Key  ")

        ttk.Label(tab_ecdh,
                  text="Update the friend's X25519 public key.\n"
                       "This stores their ECDH public key for fingerprint display and ratchet init.\n"
                       "To also derive a new shared secret, use 'ECDH Exchange' instead.",
                  font=("Segoe UI", 9), wraplength=580).pack(anchor="w", pady=(0, 8))

        ttk.Label(tab_ecdh, text="Current ECDH fingerprint:",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w")
        ecdh_current_var = tk.StringVar(value="")
        ttk.Label(tab_ecdh, textvariable=ecdh_current_var,
                  font=("Consolas", 9), bootstyle="secondary").pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_ecdh, text="New X25519 Public Key (Base64, 32 bytes):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        ecdh_var = tk.StringVar()
        ecdh_entry = ttk.Entry(tab_ecdh, textvariable=ecdh_var, width=60,
                               bootstyle="primary")
        ecdh_entry.pack(fill=tk.X, pady=(0, 6))

        ecdh_fp_var = tk.StringVar(value="")
        ttk.Label(tab_ecdh, textvariable=ecdh_fp_var,
                  font=("Consolas", 9), bootstyle="warning").pack(anchor="w", pady=(0, 6))

        def on_ecdh_change(*_):
            b64 = ecdh_var.get().strip()
            if not b64:
                ecdh_fp_var.set("")
                return
            try:
                raw = ECDHService.decode_public_key(b64)
                fp = ECDHService.fingerprint(raw)
                ecdh_fp_var.set(f"✅ New fingerprint: {fp}")
            except Exception as e:
                ecdh_fp_var.set(f"⚠ Invalid: {e}")

        ecdh_var.trace_add("write", on_ecdh_change)

        def do_update_ecdh():
            fname = friend_var.get()
            if not fname:
                messagebox.showwarning("No Friend", "Select a friend first.", parent=dlg)
                return
            b64 = ecdh_var.get().strip()
            if not b64:
                messagebox.showwarning("Empty", "Paste the new X25519 public key.", parent=dlg)
                return
            try:
                self.friends_service.update_friend_pub_keys(
                    name=fname, master_password=self._master_pw, new_x25519_b64=b64)
                self.refresh_list()
                status_var.set(f"✅ ECDH key updated for '{fname}'")
                messagebox.showinfo("Updated", f"ECDH (X25519) key updated for '{fname}'.",
                                    parent=dlg)
                _refresh_current(fname)
            except FriendsServiceError as e:
                messagebox.showerror("Error", friendly_error(e), parent=dlg)

        ttk.Button(tab_ecdh, text="🔁 Update ECDH Key", command=do_update_ecdh,
                   bootstyle="secondary").pack(anchor="w")

        # ════════════════════════════════════════════════════════════════
        # TAB 3: PQC Hybrid Key
        # ════════════════════════════════════════════════════════════════
        tab_pqc = ttk.Frame(nb, padding=15)
        nb.add(tab_pqc, text="  PQC Key  ")

        ttk.Label(tab_pqc,
                  text="Update the friend's PQC combined public key (X25519 + Kyber768).\n"
                       "Use this when they regenerate their PQC keys.",
                  font=("Segoe UI", 9), wraplength=580).pack(anchor="w", pady=(0, 8))

        ttk.Label(tab_pqc, text="Current PQC key:",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w")
        pqc_current_var = tk.StringVar(value="")
        ttk.Label(tab_pqc, textvariable=pqc_current_var,
                  font=("Consolas", 9), bootstyle="secondary").pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_pqc, text="New PQC Combined Public Key (Base64):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        pqc_text = ttk.ScrolledText(tab_pqc, height=4, wrap=tk.WORD,
                                    font=("Consolas", 9))
        pqc_text.pack(fill=tk.X, pady=(0, 6))

        pqc_status_var = tk.StringVar(value="")
        ttk.Label(tab_pqc, textvariable=pqc_status_var,
                  font=("Consolas", 9), bootstyle="warning").pack(anchor="w", pady=(0, 6))

        def on_pqc_change(*_):
            b64 = pqc_text.get("1.0", tk.END).strip()
            if not b64:
                pqc_status_var.set("")
                return
            try:
                raw = base64.b64decode(b64)
                if len(raw) < 36:
                    pqc_status_var.set("⚠ Too short for a valid PQC combined key")
                else:
                    pqc_status_var.set(f"✅ Valid PQC combined key ({len(raw)} bytes)")
            except Exception:
                pqc_status_var.set("⚠ Invalid Base64")

        pqc_text.bind("<KeyRelease>", on_pqc_change)

        def do_update_pqc():
            fname = friend_var.get()
            if not fname:
                messagebox.showwarning("No Friend", "Select a friend first.", parent=dlg)
                return
            b64 = pqc_text.get("1.0", tk.END).strip()
            if not b64:
                messagebox.showwarning("Empty", "Paste the new PQC combined public key.",
                                       parent=dlg)
                return
            try:
                self.friends_service.update_friend_pub_keys(
                    name=fname, master_password=self._master_pw, new_pqc_b64=b64)
                self.refresh_list()
                status_var.set(f"✅ PQC key updated for '{fname}'")
                messagebox.showinfo("Updated", f"PQC combined public key updated for '{fname}'.",
                                    parent=dlg)
                _refresh_current(fname)
            except FriendsServiceError as e:
                messagebox.showerror("Error", friendly_error(e), parent=dlg)

        ttk.Button(tab_pqc, text="🛡 Update PQC Key", command=do_update_pqc,
                   bootstyle="info").pack(anchor="w")

        # ════════════════════════════════════════════════════════════════
        # TAB 4: Hybrid Signature Key
        # ════════════════════════════════════════════════════════════════
        tab_hsig = ttk.Frame(nb, padding=15)
        nb.add(tab_hsig, text="  Hybrid Sig Key  ")

        ttk.Label(tab_hsig,
                  text="Update the friend's hybrid signing key (Ed25519 + Dilithium3).\n"
                       "Use this when they regenerate their hybrid signing keys.",
                  font=("Segoe UI", 9), wraplength=580).pack(anchor="w", pady=(0, 8))

        ttk.Label(tab_hsig, text="Current hybrid signing key:",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w")
        hsig_current_var = tk.StringVar(value="")
        ttk.Label(tab_hsig, textvariable=hsig_current_var,
                  font=("Consolas", 9), bootstyle="secondary").pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_hsig, text="New Hybrid Signing Combined Public Key (Base64):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        hsig_text = ttk.ScrolledText(tab_hsig, height=4, wrap=tk.WORD,
                                     font=("Consolas", 9))
        hsig_text.pack(fill=tk.X, pady=(0, 6))

        hsig_fp_var = tk.StringVar(value="")
        ttk.Label(tab_hsig, textvariable=hsig_fp_var,
                  font=("Consolas", 9), bootstyle="warning").pack(anchor="w", pady=(0, 6))

        def on_hsig_change(*_):
            b64 = hsig_text.get("1.0", tk.END).strip()
            if not b64:
                hsig_fp_var.set("")
                return
            try:
                raw = base64.b64decode(b64)
                if len(raw) < 36:
                    hsig_fp_var.set("⚠ Too short for a valid hybrid signing key")
                else:
                    fp = self.friends_service.get_hybrid_sig_key_fingerprint(b64)
                    hsig_fp_var.set(f"✅ Fingerprint: {fp}" if fp else f"✅ Valid ({len(raw)} bytes)")
            except Exception:
                hsig_fp_var.set("⚠ Invalid Base64")

        hsig_text.bind("<KeyRelease>", on_hsig_change)

        def do_update_hsig():
            fname = friend_var.get()
            if not fname:
                messagebox.showwarning("No Friend", "Select a friend first.", parent=dlg)
                return
            b64 = hsig_text.get("1.0", tk.END).strip()
            if not b64:
                messagebox.showwarning("Empty",
                                       "Paste the new hybrid signing combined public key.",
                                       parent=dlg)
                return
            try:
                self.friends_service.update_friend_pub_keys(
                    name=fname, master_password=self._master_pw, new_hybrid_sig_b64=b64)
                self.refresh_list()
                status_var.set(f"✅ Hybrid signing key updated for '{fname}'")
                messagebox.showinfo(
                    "Updated",
                    f"Hybrid signing combined public key updated for '{fname}'.\n\n"
                    "Messages from this friend will be verified with the new key.",
                    parent=dlg)
                _refresh_current(fname)
            except FriendsServiceError as e:
                messagebox.showerror("Error", friendly_error(e), parent=dlg)

        ttk.Button(tab_hsig, text="✍️ Update Hybrid Sig Key", command=do_update_hsig,
                   bootstyle="success").pack(anchor="w")

        # ── Refresh current-key displays when friend selection changes ───
        def _refresh_current(fname: str = ""):
            if not fname:
                fname = friend_var.get()
            if not fname:
                return
            details = self.friends_service.get_friend_details(fname)
            if not details:
                return
            # RSA
            rsa_current_var.set(details.get("rsa_fingerprint", "—"))
            # ECDH
            ef = details.get("ecdh_fingerprint")
            ecdh_current_var.set(ef if ef else "Not configured")
            # PQC
            pqc_current_var.set("Stored" if details.get("has_pqc_key") else "Not configured")
            # Hybrid sig
            has_hs = details.get("has_hybrid_sig_key")
            if has_hs:
                hs_b64 = self.friends_service.get_friend_hybrid_sig_pub_b64(fname)
                if hs_b64:
                    fp = self.friends_service.get_hybrid_sig_key_fingerprint(hs_b64)
                    hsig_current_var.set(f"Stored (fp: {fp})" if fp else "Stored")
                else:
                    hsig_current_var.set("Not configured")
            else:
                hsig_current_var.set("Not configured")

        friend_combo.bind("<<ComboboxSelected>>", lambda _: _refresh_current())

        # Populate initial display
        _refresh_current(friend_var.get())

        ttk.Button(dlg, text="Close", command=dlg.destroy,
                   bootstyle="secondary-outline").pack(pady=(4, 10))
