import json
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox

from views.dialogs import password_dialog
from services.event_bus import event_bus, Events
from models.trust_chain import CertificateType, TrustLevel, RevocationStatus


class CertificateDialog:
    def __init__(self, parent, trust_chain_service, friends_service, bg: str,
                 mode: str = None, friend_name: str = None):
        self.parent = parent
        self.trust_chain_service = trust_chain_service
        self.friends_service = friends_service
        self.bg = bg
        self.mode = mode
        self.friend_name = friend_name

    def show(self):
        pw = password_dialog(
            self.parent,
            "🔐 Trust Chain Certificates – Master Password Required",
            confirm=False,
        )
        if not pw:
            return
        if not self.friends_service.verify_password(pw):
            messagebox.showerror(
                "Access Denied",
                "Incorrect master password.\n"
                "Trust chain certificate management requires authentication.",
                parent=self.parent,
            )
            return

        dlg = tk.Toplevel(self.parent)
        dlg.title("🔐 Trust Chain Certificates")
        dlg.geometry("700x650")
        dlg.resizable(True, True)
        dlg.minsize(600, 550)
        dlg.transient(self.parent)
        dlg.grab_set()
        dlg.configure(bg=self.bg)

        notebook = ttk.Notebook(dlg, bootstyle="info")
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))

        tab_issue = ttk.Frame(notebook, padding=15)
        notebook.add(tab_issue, text="  Issue Certificate  ")

        ttk.Label(
            tab_issue,
            text="Issue a trust certificate vouching for a friend's identity",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_issue, text="Friend:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        friend_names = self.friends_service.get_friend_names()
        issue_friend_var = tk.StringVar()
        issue_friend_combo = ttk.Combobox(
            tab_issue, textvariable=issue_friend_var,
            values=friend_names, state="readonly",
            width=40, bootstyle="info",
        )
        issue_friend_combo.pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_issue, text="Certificate Type:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        cert_type_var = tk.StringVar(value="Identity")
        cert_type_combo = ttk.Combobox(
            tab_issue, textvariable=cert_type_var,
            values=["Identity", "Recovery", "Delegation"],
            state="readonly", width=25, bootstyle="info",
        )
        cert_type_combo.pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_issue, text="Validity (days):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        validity_var = tk.StringVar(value="365")
        validity_entry = ttk.Entry(
            tab_issue, textvariable=validity_var,
            width=10, bootstyle="info",
        )
        validity_entry.pack(anchor="w", pady=(0, 10))

        issue_status_var = tk.StringVar(value="")
        ttk.Label(tab_issue, textvariable=issue_status_var,
                  font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 8))

        def do_issue():
            fname = issue_friend_var.get()
            if not fname:
                messagebox.showwarning("No Selection",
                                       "Please select a friend to issue a certificate for.",
                                       parent=dlg)
                return
            try:
                days = int(validity_var.get())
                if days <= 0:
                    raise ValueError
            except ValueError:
                messagebox.showwarning("Invalid Validity",
                                       "Please enter a positive number of days.",
                                       parent=dlg)
                return
            cert_type_label = cert_type_var.get()
            cert_type_map = {
                "Identity": CertificateType.IDENTITY,
                "Recovery": CertificateType.RECOVERY,
                "Delegation": CertificateType.DELEGATION,
            }
            cert_type = cert_type_map[cert_type_label]
            pw2 = password_dialog(
                dlg,
                "Enter Master Password to sign certificate",
                confirm=False,
            )
            if not pw2:
                return
            if not self.friends_service.verify_password(pw2):
                messagebox.showerror("Wrong Password",
                                     "Master password incorrect.", parent=dlg)
                return
            try:
                subject_pub_b64 = self.friends_service.get_friend_hybrid_sig_pub_b64(fname)
                if not subject_pub_b64:
                    messagebox.showerror(
                        "Missing Key",
                        f"No hybrid signing public key stored for '{fname}'.\n"
                        "Import their hybrid signing key first.",
                        parent=dlg,
                    )
                    return
                cert = self.trust_chain_service.issue_certificate(
                    subject_name=fname,
                    subject_pub_b64=subject_pub_b64,
                    cert_type=cert_type,
                    validity_days=days,
                    master_password=pw2,
                )
                issue_status_var.set(
                    f"✅ Certificate issued for '{fname}' ({cert_type_label}, {days} days)"
                )
                messagebox.showinfo(
                    "Success",
                    f"Certificate issued successfully!\n\n"
                    f"Subject: {fname}\n"
                    f"Type: {cert_type_label}\n"
                    f"Validity: {days} days\n"
                    f"ID: {cert.cert_id[:12]}...",
                    parent=dlg,
                )
                event_bus.publish(Events.TRUST_LEVEL_CHANGED, source="certificate_dialog", friend_name=fname)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=dlg)

        ttk.Button(
            tab_issue, text="Sign & Issue Certificate",
            command=do_issue, bootstyle="info",
        ).pack(anchor="w", pady=(10, 0))

        tab_view = ttk.Frame(notebook, padding=15)
        notebook.add(tab_view, text="  View & Revoke  ")

        ttk.Label(
            tab_view,
            text="All Issued Trust Certificates",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(0, 10))

        columns = ("subject", "issuer", "type", "expires", "status")
        cert_tree = ttk.Treeview(
            tab_view, columns=columns, show="headings",
            height=12, bootstyle="info",
        )
        cert_tree.heading("subject", text="Subject")
        cert_tree.heading("issuer", text="Issuer")
        cert_tree.heading("type", text="Type")
        cert_tree.heading("expires", text="Expires")
        cert_tree.heading("status", text="Status")
        cert_tree.column("subject", width=140)
        cert_tree.column("issuer", width=140)
        cert_tree.column("type", width=90)
        cert_tree.column("expires", width=150)
        cert_tree.column("status", width=90)
        cert_scroll = ttk.Scrollbar(tab_view, orient=tk.VERTICAL,
                                     command=cert_tree.yview, bootstyle="info-round")
        cert_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        cert_tree.configure(yscrollcommand=cert_scroll.set)
        cert_tree.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        def load_certificates():
            for item in cert_tree.get_children():
                cert_tree.delete(item)
            try:
                certs = self.trust_chain_service.get_all_certificates()
            except Exception:
                certs = []
            for cert in certs:
                import datetime
                expires_str = datetime.datetime.fromtimestamp(
                    cert.not_after
                ).strftime("%Y-%m-%d %H:%M")
                status = cert.status()
                status_map = {
                    RevocationStatus.VALID: "Valid",
                    RevocationStatus.REVOKED: "Revoked",
                    RevocationStatus.EXPIRED: "Expired",
                }
                cert_tree.insert("", tk.END, iid=cert.cert_id, values=(
                    cert.subject_name,
                    cert.issuer_name,
                    cert.cert_type.value.capitalize(),
                    expires_str,
                    status_map.get(status, "Unknown"),
                ))

        load_certificates()

        btn_view_frame = ttk.Frame(tab_view)
        btn_view_frame.pack(fill=tk.X)

        def do_verify():
            sel = cert_tree.selection()
            if not sel:
                messagebox.showwarning("No Selection",
                                       "Please select a certificate to verify.",
                                       parent=dlg)
                return
            cert_id = sel[0]
            try:
                result = self.trust_chain_service.verify_certificate(cert_id)
                if result:
                    messagebox.showinfo("Verification",
                                        "Certificate is valid and trusted.",
                                        parent=dlg)
                else:
                    messagebox.showwarning("Verification",
                                           "Certificate verification failed.",
                                           parent=dlg)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=dlg)

        def do_revoke():
            sel = cert_tree.selection()
            if not sel:
                messagebox.showwarning("No Selection",
                                       "Please select a certificate to revoke.",
                                       parent=dlg)
                return
            cert_id = sel[0]
            confirm = messagebox.askyesno(
                "Confirm Revocation",
                "Are you sure you want to revoke this certificate?\n\n"
                "This action cannot be undone.",
                parent=dlg,
            )
            if not confirm:
                return
            pw2 = password_dialog(
                dlg,
                "Enter Master Password to revoke certificate",
                confirm=False,
            )
            if not pw2:
                return
            if not self.friends_service.verify_password(pw2):
                messagebox.showerror("Wrong Password",
                                     "Master password incorrect.", parent=dlg)
                return
            try:
                self.trust_chain_service.revoke_certificate(cert_id)
                load_certificates()
                messagebox.showinfo("Revoked",
                                    "Certificate has been revoked successfully.",
                                    parent=dlg)
                event_bus.publish(Events.TRUST_LEVEL_CHANGED, source="certificate_dialog")
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=dlg)

        def do_export():
            sel = cert_tree.selection()
            if not sel:
                messagebox.showwarning("No Selection",
                                       "Please select a certificate to export.",
                                       parent=dlg)
                return
            cert_id = sel[0]
            try:
                certs = self.trust_chain_service.get_all_certificates()
                target = next((c for c in certs if c.cert_id == cert_id), None)
                if not target:
                    messagebox.showerror("Error", "Certificate not found.", parent=dlg)
                    return
                path = filedialog.asksaveasfilename(
                    parent=dlg,
                    title="Export Certificate",
                    defaultextension=".json",
                    filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                )
                if not path:
                    return
                with open(path, "w") as f:
                    json.dump(target.to_dict(), f, indent=2)
                messagebox.showinfo("Exported",
                                    f"Certificate exported to:\n{path}",
                                    parent=dlg)
            except Exception as e:
                messagebox.showerror("Export Error", str(e), parent=dlg)

        def do_import():
            path = filedialog.askopenfilename(
                parent=dlg,
                title="Import Certificate",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            )
            if not path:
                return
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                cert_dicts = data if isinstance(data, list) else [data]
                count = self.trust_chain_service.import_received_certs(cert_dicts)
                load_certificates()
                messagebox.showinfo("Imported",
                                    f"Imported {count} certificate(s).",
                                    parent=dlg)
                event_bus.publish(Events.TRUST_LEVEL_CHANGED, source="certificate_dialog")
            except Exception as e:
                messagebox.showerror("Import Error", str(e), parent=dlg)

        ttk.Button(
            btn_view_frame, text="Export",
            command=do_export, bootstyle="info-outline",
        ).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(
            btn_view_frame, text="Import",
            command=do_import, bootstyle="info-outline",
        ).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(
            btn_view_frame, text="Verify Certificate",
            command=do_verify, bootstyle="info-outline",
        ).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(
            btn_view_frame, text="Revoke Certificate",
            command=do_revoke, bootstyle="danger-outline",
        ).pack(side=tk.LEFT)

        tab_status = ttk.Frame(notebook, padding=15)
        notebook.add(tab_status, text="  Trust Status  ")

        ttk.Label(
            tab_status,
            text="Trust Level Overview",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(0, 10))

        trust_columns = ("friend", "trust_level", "cert_count", "badge")
        trust_tree = ttk.Treeview(
            tab_status, columns=trust_columns, show="headings",
            height=12, bootstyle="info",
        )
        trust_tree.heading("friend", text="Friend")
        trust_tree.heading("trust_level", text="Trust Level")
        trust_tree.heading("cert_count", text="Certificates")
        trust_tree.heading("badge", text="Status")
        trust_tree.column("friend", width=160)
        trust_tree.column("trust_level", width=120)
        trust_tree.column("cert_count", width=100)
        trust_tree.column("badge", width=160)
        trust_scroll = ttk.Scrollbar(tab_status, orient=tk.VERTICAL,
                                      command=trust_tree.yview, bootstyle="info-round")
        trust_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        trust_tree.configure(yscrollcommand=trust_scroll.set)
        trust_tree.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        def load_trust_status():
            for item in trust_tree.get_children():
                trust_tree.delete(item)
            try:
                friend_names_list = self.friends_service.get_friend_names()
            except Exception:
                friend_names_list = []
            trust_badge_map = {
                TrustLevel.TRUSTED: "🟢 TRUSTED",
                TrustLevel.VERIFIED: "🟡 VERIFIED",
                TrustLevel.BASIC: "🔵 BASIC",
                TrustLevel.NONE: "⚪ NONE",
            }
            for fname in friend_names_list:
                try:
                    level = self.trust_chain_service.get_trust_level(fname)
                except Exception:
                    level = TrustLevel.NONE
                try:
                    certs = self.trust_chain_service.get_certs_for_friend(fname)
                    cert_count = len(certs)
                except Exception:
                    cert_count = 0
                trust_tree.insert("", tk.END, values=(
                    fname,
                    level.name,
                    cert_count,
                    trust_badge_map.get(level, "⚪ NONE"),
                ))

        load_trust_status()

        btn_trust_frame = ttk.Frame(tab_status)
        btn_trust_frame.pack(fill=tk.X)
        ttk.Button(
            btn_trust_frame, text="🔄 Refresh",
            command=load_trust_status, bootstyle="info-outline",
        ).pack(side=tk.RIGHT)

        ttk.Button(dlg, text="Close", command=dlg.destroy,
                   bootstyle="secondary-outline").pack(pady=(0, 10))
