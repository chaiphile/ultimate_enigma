import json
import logging
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox

from views.dialogs import password_dialog
from views.utils import init_modal, run_busy, friendly_error, ToolTip
from services.event_bus import event_bus, Events
from models.trust_chain import CertificateType, TrustLevel, RevocationStatus

logger = logging.getLogger(__name__)


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
        if not self.friends_service.verify_master_password(pw):
            messagebox.showerror(
                "دسترسی رد شد",
                "رمز عبور اصلی نادرست است.\n"
                "مدیریت گواهی زنجیره اعتماد نیاز به احراز هویت دارد.",
                parent=self.parent,
            )
            return

        dlg = tk.Toplevel(self.parent)
        dlg.title("🔐 Trust Chain Certificates")
        dlg.geometry("700x650")
        dlg.resizable(True, True)
        dlg.minsize(600, 550)
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
            issue_status_var.set("")
            fname = issue_friend_var.get()
            if not fname:
                messagebox.showwarning("هیچ انتخابی",
                                       "لطفاً یک دوست برای صدور گواهی انتخاب کنید.",
                                       parent=dlg)
                return
            try:
                days = int(validity_var.get())
                if days <= 0:
                    raise ValueError
            except ValueError:
                messagebox.showwarning("اعتبار نامعتبر",
                                       "لطفاً یک عدد صحیح مثبت برای روزها وارد کنید.",
                                       parent=dlg)
                return
            cert_type_label = cert_type_var.get()
            # UI labels map 1:1 to CertificateType members (no relabeling).
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
            if not self.friends_service.verify_master_password(pw2):
                messagebox.showerror("رمز عبور اشتباه",
                                     "رمز عبور اصلی نادرست است.", parent=dlg)
                return
            subject_pub_b64 = self.friends_service.get_friend_hybrid_sig_pub_b64(fname)
            if not subject_pub_b64:
                messagebox.showerror(
                    "کلید موجود نیست",
                    f"کلید عمومی امضای ترکیبی برای '{fname}' ذخیره نشده است.\n"
                    "ابتدا کلید امضای ترکیبی آن را وارد کنید.",
                    parent=dlg,
                )
                return

            def _work():
                # Signing is blocking; runs off the UI thread. NO UI calls here.
                return self.trust_chain_service.issue_certificate(
                    subject_name=fname,
                    subject_pub_b64=subject_pub_b64,
                    cert_type=cert_type,
                    validity_days=days,
                    master_password=pw2,
                )

            def _done(cert):
                issue_status_var.set(
                    f"✅ Certificate issued for '{fname}' ({cert_type_label}, {days} days)"
                )
                messagebox.showinfo(
                    "موفقیت",
                    f"گواهی با موفقیت صادر شد!\n\n"
                    f"موضوع: {fname}\n"
                    f"نوع: {cert_type_label}\n"
                    f"اعتبار: {days} روز\n"
                    f"شناسه: {cert.cert_id[:12]}...",
                    parent=dlg,
                )
                event_bus.publish(Events.TRUST_LEVEL_CHANGED, source="certificate_dialog", friend_name=fname)

            def _err(e):
                logger.exception("Failed to issue certificate")
                issue_status_var.set("")
                messagebox.showerror("خطا", friendly_error(e), parent=dlg)

            run_busy(dlg, _work, on_done=_done, on_error=_err,
                     busy_widgets=[issue_btn])

        issue_btn = ttk.Button(
            tab_issue, text="Sign & Issue Certificate",
            command=do_issue, bootstyle="info",
        )
        issue_btn.pack(anchor="w", pady=(10, 0))
        ToolTip(issue_btn, "امضا و صدور گواهی اعتماد برای دوست انتخاب شده")

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

        cert_load_status_var = tk.StringVar(value="")
        ttk.Label(tab_view, textvariable=cert_load_status_var,
                  font=("Segoe UI", 9), bootstyle="danger").pack(anchor="w", pady=(0, 4))

        def load_certificates():
            for item in cert_tree.get_children():
                cert_tree.delete(item)
            try:
                certs = self.trust_chain_service.get_all_certificates()
            except Exception:
                logger.exception("Failed to load certificates")
                cert_load_status_var.set("⚠ Failed to load certificates — see logs")
                return
            cert_load_status_var.set("")
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
                type_label = cert.cert_type.value.capitalize()
                cert_tree.insert("", tk.END, iid=cert.cert_id, values=(
                    cert.subject_name,
                    cert.issuer_name,
                    type_label,
                    expires_str,
                    status_map.get(status, "Unknown"),
                ))

        load_certificates()

        btn_view_frame = ttk.Frame(tab_view)
        btn_view_frame.pack(fill=tk.X, pady=(0, 2))
        export_row = ttk.Frame(btn_view_frame)
        export_row.pack(fill=tk.X, pady=(0, 4))
        action_row = ttk.Frame(btn_view_frame)
        action_row.pack(fill=tk.X)

        def do_verify():
            sel = cert_tree.selection()
            if not sel:
                messagebox.showwarning("هیچ انتخابی",
                                       "لطفاً یک گواهی برای تأیید انتخاب کنید.",
                                       parent=dlg)
                return
            cert_id = sel[0]

            def _work():
                return self.trust_chain_service.verify_certificate(cert_id)

            def _done(result):
                if result:
                    messagebox.showinfo("تأیید",
                                        "گواهی معتبر و مورد اعتماد است.",
                                        parent=dlg)
                else:
                    messagebox.showwarning("تأیید",
                                           "تأیید گواهی ناموفق بود.",
                                           parent=dlg)

            def _err(e):
                logger.exception("Certificate verification error")
                messagebox.showerror("خطا", friendly_error(e), parent=dlg)

            run_busy(dlg, _work, on_done=_done, on_error=_err,
                     busy_widgets=[verify_btn])

        def do_revoke():
            sel = cert_tree.selection()
            if not sel:
                messagebox.showwarning("هیچ انتخابی",
                                       "لطفاً یک گواهی برای لغو انتخاب کنید.",
                                       parent=dlg)
                return
            cert_id = sel[0]
            confirm = messagebox.askyesno(
                "تأیید لغو",
                "آیا مطمئن هستید که می‌خواهید این گواهی را لغو کنید؟\n\n"
                "این عمل قابل بازگشت نیست.",
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
            if not self.friends_service.verify_master_password(pw2):
                messagebox.showerror("رمز عبور اشتباه",
                                     "رمز عبور اصلی نادرست است.", parent=dlg)
                return

            def _work():
                self.trust_chain_service.revoke_certificate(cert_id)

            def _done(_result):
                load_certificates()
                messagebox.showinfo("لغو شد",
                                    "گواهی با موفقیت لغو شد.",
                                    parent=dlg)
                event_bus.publish(Events.TRUST_LEVEL_CHANGED, source="certificate_dialog")

            def _err(e):
                logger.exception("Failed to revoke certificate")
                messagebox.showerror("خطا", friendly_error(e), parent=dlg)

            run_busy(dlg, _work, on_done=_done, on_error=_err,
                     busy_widgets=[revoke_btn])

        def do_export():
            sel = cert_tree.selection()
            if not sel:
                messagebox.showwarning("هیچ انتخابی",
                                       "لطفاً یک گواهی برای صادرات انتخاب کنید.",
                                       parent=dlg)
                return
            cert_id = sel[0]
            try:
                cert_dict = self.trust_chain_service.export_single_certificate(cert_id)
                path = filedialog.asksaveasfilename(
                    parent=dlg,
                    title="Export Certificate",
                    defaultextension=".json",
                    filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                )
                if not path:
                    return
                with open(path, "w") as f:
                    json.dump(cert_dict, f, indent=2)
                messagebox.showinfo("صادر شد",
                                    f"گواهی صادر شد به:\n{path}",
                                    parent=dlg)
            except Exception as e:
                logger.exception("Certificate export failed")
                messagebox.showerror("خطای صادرات", friendly_error(e), parent=dlg)

        def do_export_delegation():
            try:
                bundle = self.trust_chain_service.export_delegation_certificates()
                if not bundle["certificates"]:
                    messagebox.showinfo("بدون گواهی نمایندگی",
                                        "هیچ گواهی نمایندگی در فروشگاه محلی یافت نشد.",
                                        parent=dlg)
                    return
                path = filedialog.asksaveasfilename(
                    parent=dlg,
                    title="Export Delegation Certificates",
                    defaultextension=".json",
                    filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                )
                if not path:
                    return
                with open(path, "w") as f:
                    json.dump(bundle, f, indent=2)
                count = len(bundle["certificates"])
                messagebox.showinfo("صادر شد",
                                    f"{count} گواهی نمایندگی صادر شد به:\n{path}",
                                    parent=dlg)
            except Exception as e:
                logger.exception("Delegation export failed")
                messagebox.showerror("خطای صادرات", friendly_error(e), parent=dlg)

        def do_export_all():
            try:
                bundle = self.trust_chain_service.export_trust_bundle()
                path = filedialog.asksaveasfilename(
                    parent=dlg,
                    title="Export All Certificates",
                    defaultextension=".json",
                    filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                )
                if not path:
                    return
                with open(path, "w") as f:
                    json.dump(bundle, f, indent=2)
                count = len(bundle.get("certificates", []))
                messagebox.showinfo("صادر شد",
                                    f"{count} گواهی صادر شد به:\n{path}",
                                    parent=dlg)
            except Exception as e:
                logger.exception("Export all certificates failed")
                messagebox.showerror("خطای صادرات", friendly_error(e), parent=dlg)

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
                total = len(cert_dicts)
                count = self.trust_chain_service.import_received_certs(cert_dicts)
                load_certificates()
                rejected = total - count
                if rejected > 0:
                    messagebox.showwarning(
                        "واردات با رد",
                        f"تعداد {count} از {total} گواهی وارد شد.\n\n"
                        f"{rejected} مورد رد شد زیرا امضای آنها قابل تأیید "
                        f"نبود یا صادرکننده یک تماس شناخته‌شده نیست. "
                        f"ابتدا صادرکننده را اضافه کنید، سپس دوباره وارد کنید.",
                        parent=dlg)
                else:
                    messagebox.showinfo("وارد شد",
                                        f"تعداد {count} گواهی وارد شد.",
                                        parent=dlg)
                event_bus.publish(Events.TRUST_LEVEL_CHANGED, source="certificate_dialog")
            except Exception as e:
                logger.exception("Certificate import failed")
                messagebox.showerror("خطای واردات", friendly_error(e), parent=dlg)

        # Export row
        export_sel_btn = ttk.Button(
            export_row, text="Export Selected",
            command=do_export, bootstyle="info-outline",
        )
        export_sel_btn.pack(side=tk.LEFT, padx=(0, 5))
        ToolTip(export_sel_btn, "صادرات گواهی انتخاب شده به صورت فایل JSON")
        export_del_btn = ttk.Button(
            export_row, text="Export Delegation Certs",
            command=do_export_delegation, bootstyle="info-outline",
        )
        export_del_btn.pack(side=tk.LEFT, padx=(0, 5))
        ToolTip(export_del_btn, "صادرات گواهی‌های نمایندگی")
        export_all_btn = ttk.Button(
            export_row, text="Export All Certs",
            command=do_export_all, bootstyle="info-outline",
        )
        export_all_btn.pack(side=tk.LEFT)
        ToolTip(export_all_btn, "صادرات همه گواهی‌ها به صورت یک بسته")

        # Action row
        import_btn = ttk.Button(
            action_row, text="Import",
            command=do_import, bootstyle="secondary-outline",
        )
        import_btn.pack(side=tk.LEFT, padx=(0, 5))
        ToolTip(import_btn, "وارد کردن گواهی از فایل JSON")
        verify_btn = ttk.Button(
            action_row, text="Verify Certificate",
            command=do_verify, bootstyle="info-outline",
        )
        verify_btn.pack(side=tk.LEFT, padx=(0, 5))
        ToolTip(verify_btn, "تأیید اعتبار گواهی انتخاب شده")
        revoke_btn = ttk.Button(
            action_row, text="Revoke Certificate",
            command=do_revoke, bootstyle="danger-outline",
        )
        revoke_btn.pack(side=tk.LEFT)
        ToolTip(revoke_btn, "لغو اعتبار گواهی انتخاب شده (غیرقابل بازگشت)")

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

        trust_load_status_var = tk.StringVar(value="")
        ttk.Label(tab_status, textvariable=trust_load_status_var,
                  font=("Segoe UI", 9), bootstyle="danger").pack(anchor="w", pady=(0, 4))

        def load_trust_status():
            for item in trust_tree.get_children():
                trust_tree.delete(item)
            try:
                friend_names_list = self.friends_service.get_friend_names()
            except Exception:
                logger.exception("Failed to load friend names for trust status")
                trust_load_status_var.set("⚠ Failed to load trust status — see logs")
                return
            trust_load_status_var.set("")
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
        refresh_trust_btn = ttk.Button(
            btn_trust_frame, text="🔄 Refresh",
            command=load_trust_status, bootstyle="info-outline",
        )
        refresh_trust_btn.pack(side=tk.RIGHT)
        ToolTip(refresh_trust_btn, "بروزرسانی وضعیت اعتماد دوستان")

        # ------------------------------------------------------------------
        # Tab: Delegation Powers
        # ------------------------------------------------------------------

        tab_delegation = ttk.Frame(notebook, padding=15)
        notebook.add(tab_delegation, text="  Delegation Powers  ")

        ttk.Label(
            tab_delegation,
            text="Delegation Certificates Held by You",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            tab_delegation,
            text="Valid delegation certs others have issued to you, "
                 "granting authority to update their key or revoke their trust certificates.",
            font=("Segoe UI", 9),
            wraplength=620,
            justify="left",
        ).pack(anchor="w", pady=(0, 10))

        del_columns = ("delegator", "expires", "cert_id_short")
        del_tree = ttk.Treeview(
            tab_delegation, columns=del_columns, show="headings",
            height=8, bootstyle="info",
        )
        del_tree.heading("delegator", text="Delegator (Issuer)")
        del_tree.heading("expires", text="Expires")
        del_tree.heading("cert_id_short", text="Cert ID")
        del_tree.column("delegator", width=200)
        del_tree.column("expires", width=160)
        del_tree.column("cert_id_short", width=120)
        del_scroll = ttk.Scrollbar(tab_delegation, orient=tk.VERTICAL,
                                    command=del_tree.yview, bootstyle="info-round")
        del_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        del_tree.configure(yscrollcommand=del_scroll.set)
        del_tree.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        del_load_status_var = tk.StringVar(value="")
        ttk.Label(tab_delegation, textvariable=del_load_status_var,
                  font=("Segoe UI", 9), bootstyle="danger").pack(anchor="w", pady=(0, 4))

        def load_delegation_certs():
            for item in del_tree.get_children():
                del_tree.delete(item)
            try:
                certs = self.trust_chain_service.get_delegation_certs_held_by_me()
            except Exception:
                logger.exception("Failed to load delegation certificates")
                del_load_status_var.set("⚠ Failed to load delegation certs — see logs")
                return
            del_load_status_var.set("")
            import datetime
            for cert in certs:
                expires_str = datetime.datetime.fromtimestamp(
                    cert.not_after
                ).strftime("%Y-%m-%d %H:%M")
                del_tree.insert("", tk.END, iid=cert.cert_id, values=(
                    cert.issuer_name,
                    expires_str,
                    cert.cert_id[:12] + "...",
                ))
            if not certs:
                del_tree.insert("", tk.END, values=(
                    "No valid delegation certs found", "", "",
                ))

        load_delegation_certs()

        # ---- shared helpers ------------------------------------------------

        def _get_delegator():
            """Return delegator name from selected tree row, or None."""
            sel = del_tree.selection()
            if not sel:
                messagebox.showwarning("هیچ انتخابی",
                                       "ابتدا یک گواهی نمایندگی انتخاب کنید.",
                                       parent=dlg)
                return None
            vals = del_tree.item(sel[0], "values")
            if not vals or vals[0].startswith("No valid"):
                return None
            return vals[0]

        def _prompt_key(title_str: str, label_str: str) -> str | None:
            """Open a small dialog to paste a Base64 key; returns the string or None."""
            key_dlg = tk.Toplevel(dlg)
            key_dlg.title(title_str)
            key_dlg.geometry("560x230")
            key_dlg.resizable(True, False)
            ttk.Label(key_dlg, text=label_str,
                      font=("Segoe UI", 10), wraplength=530,
                      ).pack(anchor="w", padx=15, pady=(15, 4))
            key_text = tk.Text(key_dlg, height=5, width=70,
                               wrap=tk.WORD, font=("Courier New", 9))
            key_text.pack(padx=15, pady=(0, 8), fill=tk.X)
            result = {"v": None}
            def _ok():
                result["v"] = key_text.get("1.0", tk.END).strip()
                key_dlg.destroy()
            kbf = ttk.Frame(key_dlg)
            kbf.pack(pady=(0, 15))
            ttk.Button(kbf, text="OK", command=_ok,
                       bootstyle="info").pack(side=tk.LEFT, padx=5)
            ttk.Button(kbf, text="Cancel", command=key_dlg.destroy,
                       bootstyle="secondary-outline").pack(side=tk.LEFT, padx=5)
            init_modal(key_dlg, dlg, focus_widget=key_text)
            dlg.wait_window(key_dlg)
            return result["v"] or None

        def _verify_pw(delegator_name: str) -> str | None:
            """Prompt for master password, verify it, return it or None."""
            pw2 = password_dialog(
                dlg,
                f"Enter Master Password to update '{delegator_name}'",
                confirm=False,
            )
            if not pw2:
                return None
            if not self.friends_service.verify_master_password(pw2):
                messagebox.showerror("رمز عبور اشتباه",
                                     "رمز عبور اصلی نادرست است.", parent=dlg)
                return None
            return pw2

        # ---- action handlers -----------------------------------------------

        def do_update_delegator_key():
            name = _get_delegator()
            if not name:
                return
            new_b64 = _prompt_key(
                f"Update Hybrid Key – {name}",
                f"Paste the new hybrid signing public key (Base64) for '{name}':",
            )
            if not new_b64:
                return
            pw2 = _verify_pw(name)
            if not pw2:
                return
            try:
                self.trust_chain_service.update_delegator_pub_key(name, new_b64, pw2)
                messagebox.showinfo("کلید به‌روز شد",
                                    f"کلید امضای ترکیبی برای '{name}' به‌روز شد.",
                                    parent=dlg)
                event_bus.publish(Events.FRIEND_LIST_CHANGED,
                                  source="certificate_dialog", friend_name=name)
            except Exception as e:
                logger.exception("Failed to update delegator hybrid key")
                messagebox.showerror("خطا", friendly_error(e), parent=dlg)

        def do_update_x25519():
            name = _get_delegator()
            if not name:
                return
            new_b64 = _prompt_key(
                f"Update X25519 Key – {name}",
                f"Paste the new X25519 public key (Base64, 32 bytes) for '{name}':",
            )
            if not new_b64:
                return
            pw2 = _verify_pw(name)
            if not pw2:
                return
            try:
                self.trust_chain_service.update_delegator_x25519_key(name, new_b64, pw2)
                messagebox.showinfo("کلید به‌روز شد",
                                    f"کلید X25519 برای '{name}' به‌روز شد.",
                                    parent=dlg)
                event_bus.publish(Events.FRIEND_LIST_CHANGED,
                                  source="certificate_dialog", friend_name=name)
            except Exception as e:
                logger.exception("Failed to update delegator X25519 key")
                messagebox.showerror("خطا", friendly_error(e), parent=dlg)

        def do_update_pem():
            name = _get_delegator()
            if not name:
                return
            new_pem = _prompt_key(
                f"Update RSA PEM – {name}",
                f"Paste the new RSA public key (PEM format) for '{name}':",
            )
            if not new_pem:
                return
            pw2 = _verify_pw(name)
            if not pw2:
                return
            try:
                self.trust_chain_service.update_delegator_pem(name, new_pem, pw2)
                messagebox.showinfo("کلید به‌روز شد",
                                    f"کلید عمومی RSA (PEM) برای '{name}' به‌روز شد.",
                                    parent=dlg)
                event_bus.publish(Events.FRIEND_LIST_CHANGED,
                                  source="certificate_dialog", friend_name=name)
            except Exception as e:
                logger.exception("Failed to update delegator RSA PEM")
                messagebox.showerror("خطا", friendly_error(e), parent=dlg)

        def do_update_pqc():
            name = _get_delegator()
            if not name:
                return
            new_b64 = _prompt_key(
                f"Update PQC Key – {name}",
                f"Paste the new PQC combined public key (Base64) for '{name}':",
            )
            if not new_b64:
                return
            pw2 = _verify_pw(name)
            if not pw2:
                return
            try:
                self.trust_chain_service.update_delegator_pqc_key(name, new_b64, pw2)
                messagebox.showinfo("کلید به‌روز شد",
                                    f"کلید ترکیبی PQC برای '{name}' به‌روز شد.",
                                    parent=dlg)
                event_bus.publish(Events.FRIEND_LIST_CHANGED,
                                  source="certificate_dialog", friend_name=name)
            except Exception as e:
                logger.exception("Failed to update delegator PQC key")
                messagebox.showerror("خطا", friendly_error(e), parent=dlg)

        def do_remove_all_keys():
            name = _get_delegator()
            if not name:
                return
            if not messagebox.askyesno(
                "تأیید حذف کلیدها",
                f"همه کلیدهای عمومی اختیاری (X25519، PQC، امضای ترکیبی) برای '{name}' حذف شوند؟\n\n"
                "کلید هویت RSA PEM حفظ می‌شود.\n"
                "این عمل قابل بازگشت نیست.",
                parent=dlg,
            ):
                return
            pw2 = _verify_pw(name)
            if not pw2:
                return
            try:
                self.trust_chain_service.remove_all_delegator_optional_keys(name, pw2)
                messagebox.showinfo("کلیدها حذف شدند",
                                    f"همه کلیدهای اختیاری برای '{name}' پاک شدند.",
                                    parent=dlg)
                event_bus.publish(Events.FRIEND_LIST_CHANGED,
                                  source="certificate_dialog", friend_name=name)
            except Exception as e:
                logger.exception("Failed to remove delegator optional keys")
                messagebox.showerror("خطا", friendly_error(e), parent=dlg)

        def do_revoke_all_delegator_certs():
            name = _get_delegator()
            if not name:
                return
            if not messagebox.askyesno(
                "تأیید لغو کامل",
                f"همه گواهی‌های اعتماد برای '{name}' لغو شوند؟\n\n"
                "سطح اعتماد آنها به NONE بازنشانی می‌شود.\n"
                "این عمل قابل بازگشت نیست.",
                parent=dlg,
            ):
                return
            pw2 = _verify_pw(name)
            if not pw2:
                return
            try:
                count = self.trust_chain_service.revoke_all_certs_for_delegator(name)
                messagebox.showinfo("لغو کامل شد",
                                    f"تعداد {count} گواهی برای '{name}' لغو شد.\n"
                                    "سطح اعتماد آنها اکنون NONE است.",
                                    parent=dlg)
                event_bus.publish(Events.TRUST_LEVEL_CHANGED,
                                  source="certificate_dialog", friend_name=name)
            except Exception as e:
                logger.exception("Failed to revoke all delegator certs")
                messagebox.showerror("خطا", friendly_error(e), parent=dlg)

        def do_revoke_recovery_shares():
            name = _get_delegator()
            if not name:
                return
            if not messagebox.askyesno(
                "تأیید لغو اشتراک",
                f"همه سوابق اشتراک بازیابی محلی برای '{name}' حذف شوند؟\n\n"
                "این کار اشتراک‌هایی که توزیع کرده‌اند و همچنین هر کپی\n"
                "که به نمایندگی از آنها محلی نگهداری می‌شود را حذف می‌کند.\n"
                "این عمل قابل بازگشت نیست.",
                parent=dlg,
            ):
                return
            try:
                count = self.trust_chain_service.revoke_delegator_recovery_shares(name)
                messagebox.showinfo("اشتراک‌ها لغو شدند",
                                    f"تعداد {count} رکورد اشتراک بازیابی برای '{name}' حذف شد.",
                                    parent=dlg)
            except Exception as e:
                logger.exception("Failed to revoke delegator recovery shares")
                messagebox.showerror("خطا", friendly_error(e), parent=dlg)

        # ---- button rows ---------------------------------------------------

        del_btn_frame = ttk.Frame(tab_delegation)
        del_btn_frame.pack(fill=tk.X, pady=(2, 0))

        # Row 1 – Update keys
        row1 = ttk.Frame(del_btn_frame)
        row1.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(row1, text="Update Keys:", font=("Segoe UI", 9, "bold"),
                  width=12, anchor="e").pack(side=tk.LEFT, padx=(0, 6))
        hyb_btn = ttk.Button(row1, text="Hybrid Key",
                             command=do_update_delegator_key,
                             bootstyle="info-outline")
        hyb_btn.pack(side=tk.LEFT, padx=(0, 4))
        ToolTip(hyb_btn, "به‌روزرسانی کلید امضای ترکیبی نماینده")
        x25519_btn = ttk.Button(row1, text="X25519 Key",
                                command=do_update_x25519,
                                bootstyle="info-outline")
        x25519_btn.pack(side=tk.LEFT, padx=(0, 4))
        ToolTip(x25519_btn, "به‌روزرسانی کلید X25519 نماینده")
        rsa_btn = ttk.Button(row1, text="RSA PEM",
                             command=do_update_pem,
                             bootstyle="info-outline")
        rsa_btn.pack(side=tk.LEFT, padx=(0, 4))
        ToolTip(rsa_btn, "به‌روزرسانی کلید عمومی RSA نماینده")
        pqc_btn = ttk.Button(row1, text="PQC Key",
                             command=do_update_pqc,
                             bootstyle="info-outline")
        pqc_btn.pack(side=tk.LEFT)
        ToolTip(pqc_btn, "به‌روزرسانی کلید ترکیبی PQC نماینده")

        # Row 2 – Destructive actions + Refresh
        row2 = ttk.Frame(del_btn_frame)
        row2.pack(fill=tk.X)
        ttk.Label(row2, text="Actions:", font=("Segoe UI", 9, "bold"),
                  width=12, anchor="e").pack(side=tk.LEFT, padx=(0, 6))
        remove_keys_btn = ttk.Button(row2, text="Remove All Keys",
                                     command=do_remove_all_keys,
                                     bootstyle="warning-outline")
        remove_keys_btn.pack(side=tk.LEFT, padx=(0, 4))
        ToolTip(remove_keys_btn, "حذف همه کلیدهای اختیاری نماینده (غیرقابل بازگشت)")
        revoke_certs_btn = ttk.Button(row2, text="Revoke All Certs",
                                      command=do_revoke_all_delegator_certs,
                                      bootstyle="danger-outline")
        revoke_certs_btn.pack(side=tk.LEFT, padx=(0, 4))
        ToolTip(revoke_certs_btn, "لغو همه گواهی‌های اعتماد نماینده (غیرقابل بازگشت)")
        revoke_shares_btn = ttk.Button(row2, text="Revoke Recovery Shares",
                                       command=do_revoke_recovery_shares,
                                       bootstyle="danger-outline")
        revoke_shares_btn.pack(side=tk.LEFT, padx=(0, 4))
        ToolTip(revoke_shares_btn, "لغو اشتراک‌های بازیابی نماینده")
        refresh_del_btn = ttk.Button(row2, text="Refresh",
                                     command=load_delegation_certs,
                                     bootstyle="secondary-outline")
        refresh_del_btn.pack(side=tk.RIGHT)
        ToolTip(refresh_del_btn, "بروزرسانی لیست گواهی‌های نمایندگی")

        close_cert_btn = ttk.Button(dlg, text="Close", command=dlg.destroy,
                                    bootstyle="secondary-outline")
        close_cert_btn.pack(pady=(0, 10))
        ToolTip(close_cert_btn, "بستن پنجره مدیریت گواهی‌ها")

        init_modal(dlg, self.parent, focus_widget=issue_friend_combo)
