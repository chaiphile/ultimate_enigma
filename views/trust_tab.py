"""Trust chain certificate management tab.

Manages trust certificates between friends, allowing users to issue,
import, revoke certificates and manage key recovery shares.

Publishes Events:
    TRUST_LEVEL_CHANGED - when a trust level changes for a friend.
    CERTIFICATE_ISSUED - when a certificate is issued.
    CERTIFICATE_REVOKED - when a certificate is revoked.
"""

import json
import logging
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

logger = logging.getLogger(__name__)
import ttkbootstrap as ttk
from ttkbootstrap.dialogs import Messagebox

from services.event_bus import event_bus, Events
from views.dialogs import password_dialog
from views.utils import init_modal, friendly_error, ToolTip


class TrustTab:
    def __init__(self, parent: tk.Widget, trust_chain_service, friends_service,
                 style_config=None, global_secret_service=None) -> None:
        """
        Args:
            parent: Notebook or parent widget
            trust_chain_service: Injected TrustChainService instance
            friends_service: Injected FriendsService instance
            style_config: Dict with 'bg', 'fg' keys (optional, falls back to ttk.Style)
            global_secret_service: Injected GlobalSecretService for key replacement after recovery
        """
        self.trust_service = trust_chain_service
        self.friends_service = friends_service
        self.global_secret_service = global_secret_service
        self.frame = ttk.Frame(parent)

        if style_config:
            self._bg = style_config.get('bg')
            self._fg = style_config.get('fg')
        else:
            s = ttk.Style()
            self._bg = s.colors.bg
            self._fg = s.colors.fg

        self.all_friend_names = []
        self._tooltips = {}
        self._trust_cache = {}  # name -> trust_info, refreshed once per refresh_list
        self._build_ui()
        event_bus.subscribe(Events.TRUST_LEVEL_CHANGED, self.notify_trust_changed)

    def _build_ui(self) -> None:
        top_bar = ttk.Frame(self.frame, padding=(10, 8))
        top_bar.pack(fill=tk.X)

        btn_specs = [
            ("🎛 Certificate Control Panel", self.issue_cert_dialog, "success",
             "باز کردن پنجره مدیریت گواهی‌های زنجیره اعتماد"),
            ("📥 Import (Paste)", self.import_cert_dialog, "info",
             "وارد کردن گواهی با چسباندن متن JSON"),
            ("📂 Import from File", self.import_cert_file_dialog, "info",
             "وارد کردن گواهی از فایل JSON"),
            ("📤 Export Bundle", self.export_cert_bundle_dialog, "info",
             "صادر کردن همه گواهی‌ها به صورت یک بسته JSON"),
            ("🔑 Split Recovery Key", self.split_key_dialog, "warning",
             "تقسیم کلید بازیابی به اشتراک‌های متعدد"),
            ("🔓 Recover Key", self.recover_key_dialog, "danger",
             "بازیابی کلید از اشتراک‌ها"),
            ("🔄 Refresh", self.refresh_list, "secondary-outline",
             "بروزرسانی لیست گواهی‌ها"),
        ]
        for text, cmd, style, tip in btn_specs:
            btn = ttk.Button(top_bar, text=text, command=cmd, bootstyle=style)
            btn.pack(side=tk.LEFT, padx=(0, 6))
            ToolTip(btn, tip)

        ttk.Frame(top_bar).pack(side=tk.LEFT, expand=True)

        search_frame = ttk.Frame(top_bar)
        search_frame.pack(side=tk.RIGHT)
        ttk.Label(search_frame, text="🔍", font=("Segoe UI Emoji", 10)).pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var,
                                      width=25, bootstyle="primary")
        self.search_entry.pack(side=tk.LEFT, padx=(4, 0))
        self.search_var.trace_add('write', lambda *a: self.filter_list())

        list_frame = ttk.Frame(self.frame, padding=(10, 0))
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        columns = ("status", "name", "trust_level", "cert_count", "last_cert", "expiry")
        self.tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="headings",
            bootstyle="primary",
            selectmode="browse",
            height=14,
        )

        col_config = {
            "status":       {"text": "Status",      "width": 70,  "anchor": "center"},
            "name":         {"text": "Friend Name", "width": 140, "anchor": "w"},
            "trust_level":  {"text": "Trust Level", "width": 100, "anchor": "center"},
            "cert_count":   {"text": "Certs",       "width": 80,  "anchor": "center"},
            "last_cert":    {"text": "Last Cert",   "width": 120, "anchor": "center"},
            "expiry":       {"text": "Expiry",      "width": 100, "anchor": "center"},
        }
        for col_id, cfg in col_config.items():
            self.tree.heading(col_id, text=cfg["text"], anchor=cfg["anchor"])
            self.tree.column(col_id, width=cfg["width"], anchor=cfg["anchor"],
                             minwidth=50)

        # Theme-derived row colors so dark themes aren't broken. Textual status
        # stays the primary signal so meaning isn't color-only.
        style = ttk.Style()
        colors = style.colors
        self.tree.tag_configure("has_certs", background=colors.success,
                                foreground=colors.selectfg)
        self.tree.tag_configure("no_certs", background=colors.bg,
                                foreground=colors.fg)
        self.tree.tag_configure("even_row", background=colors.bg,
                                foreground=colors.fg)
        self.tree.tag_configure("odd_row", background=colors.inputbg,
                                foreground=colors.fg)

        vsb = ttk.Scrollbar(list_frame, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        # Empty-state placeholder shown over the table when there are no rows.
        self._empty_label = ttk.Label(
            list_frame, text="", font=("Segoe UI", 11),
            bootstyle="secondary", anchor="center", justify="center",
        )

        self.tree.bind('<<TreeviewSelect>>', self.on_select)
        self.tree.bind('<Button-3>', self._show_context_menu)
        self.tree.bind('<Motion>', self._on_motion)

        self.ctx_menu = tk.Menu(self.frame, tearoff=0)
        self.ctx_menu.add_command(label="🎛 Certificate Control Panel",
                                  command=self.issue_cert_dialog)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="👁 View Certificate Details",
                                  command=lambda: self.on_select())
        self.ctx_menu.add_command(label="🗑 Revoke Selected Certificate",
                                  command=self._ctx_revoke_cert)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="🔑 Split Recovery Key",
                                  command=self.split_key_dialog)

        detail_frame = ttk.Labelframe(self.frame, text="  Selected Friend Trust Details  ",
                                      bootstyle="info", padding=5)
        detail_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        info_grid = ttk.Frame(detail_frame)
        info_grid.pack(fill=tk.X, padx=5, pady=(5, 0))

        self._detail_labels = {}
        detail_fields = [
            ("name_lbl", "Name:", 0, 0),
            ("trust_lbl", "Trust Level:", 1, 0),
            ("cert_count_lbl", "Certificate Count:", 2, 0),
            ("signers_lbl", "Signers:", 3, 0),
            ("expiry_lbl", "Nearest Expiry:", 4, 0),
        ]
        for key, label_text, row, col in detail_fields:
            ttk.Label(info_grid, text=label_text,
                      font=("Segoe UI", 9, "bold")).grid(row=row, column=col,
                                                          sticky="e", padx=(0, 8), pady=2)
            val_label = ttk.Label(info_grid, text="—", font=("Consolas", 9),
                                  wraplength=500, justify="left")
            val_label.grid(row=row, column=col + 1, sticky="w", pady=2)
            self._detail_labels[key] = val_label

        info_grid.columnconfigure(1, weight=1)

        pem_frame = ttk.Frame(detail_frame)
        pem_frame.pack(fill=tk.X, padx=5, pady=(8, 5))
        ttk.Label(pem_frame, text="Certificate Details:",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.detail_text = ttk.ScrolledText(pem_frame, height=4, wrap=tk.WORD,
                                            state='disabled', font=("Consolas", 8))
        self.detail_text.pack(fill=tk.X, pady=(2, 0))

        self.status_var = tk.StringVar(value="No friend selected")
        status_bar = ttk.Label(self.frame, textvariable=self.status_var,
                               font=("Segoe UI", 8), relief="sunken",
                               anchor="w", padding=(10, 2))
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        self.refresh_list()

    def refresh_list(self) -> None:
        friends = self.friends_service.get_all_friends()
        self.all_friend_names = [friend["name"] for friend in friends]
        # Load trust info once per refresh so per-keystroke filtering doesn't
        # hammer the DB.
        self._trust_cache = {}
        for name in self.all_friend_names:
            info = dict(self.trust_service.get_trust_info(name))
            # Determine raw cert states so we can distinguish "no certs yet"
            # from "all certs revoked/expired" and render distinct text.
            raw_certs = self.trust_service.get_certs_for_friend(name)
            info["_raw_cert_count"] = len(raw_certs)
            info["_has_revoked"] = any(c.revoked for c in raw_certs)
            info["_has_expired"] = any(
                (not c.revoked and c.is_expired()) for c in raw_certs
            )
            self._trust_cache[name] = info
        self.filter_list()

    _TRUST_MAP = {
        "trusted": "Trusted",
        "partially_trusted": "Partial",
        "untrusted": "Untrusted",
        "unknown": "Unknown",
    }

    def _status_text(self, trust_info) -> str:
        """Render a distinct TEXT status, including expired/revoked states."""
        cert_count = trust_info.get("certificate_count", 0)
        badge = trust_info.get("badge", "⚪")
        if cert_count == 0:
            if trust_info.get("_has_revoked"):
                return "🚫 Revoked"
            if trust_info.get("_has_expired"):
                return "⌛ Expired"
        trust_level = trust_info.get("trust_level", "untrusted")
        trust_text = self._TRUST_MAP.get(trust_level, trust_level.title())
        return f"{badge} {trust_text}"

    def filter_list(self) -> None:
        query = self.search_var.get().lower()
        self._tooltips.clear()

        for item in self.tree.get_children():
            self.tree.delete(item)

        row_idx = 0
        for name in self.all_friend_names:
            if query and query not in name.lower():
                continue

            trust_info = self._trust_cache.get(name, {})
            trust_level = trust_info.get("trust_level", "untrusted")
            cert_count = trust_info.get("certificate_count", 0)
            last_cert = trust_info.get("last_certificate_date", "—")
            nearest_expiry = trust_info.get("nearest_expiry", "—")

            trust_text = self._TRUST_MAP.get(trust_level, trust_level.title())
            status_text = self._status_text(trust_info)
            has_certs = cert_count > 0

            tags = []
            if has_certs:
                tags.append("has_certs")
            else:
                tags.append("even_row" if row_idx % 2 == 0 else "odd_row")

            iid = self.tree.insert(
                "", tk.END,
                values=(status_text, name, trust_text, cert_count, last_cert, nearest_expiry),
                tags=tags,
            )

            self._tooltips[iid] = {
                "name": name,
                "trust_level": trust_level,
                "cert_count": cert_count,
            }
            row_idx += 1

        count = len(self.tree.get_children())
        self._update_empty_state(count, query)
        self.status_var.set(f"{count} friend(s) listed" +
                            (f" • Filtered by \"{query}\"" if query else ""))

    def _update_empty_state(self, count: int, query: str) -> None:
        """Show a placeholder distinguishing no-friends / no-certs / no-matches."""
        if count > 0:
            self._empty_label.place_forget()
            return
        if not self.all_friend_names:
            text = "No friends yet — add friends to manage their trust certificates."
        elif query:
            text = "No matches for your search."
        elif any(
            info.get("certificate_count", 0) > 0
            for info in self._trust_cache.values()
        ):
            text = "No matches for your search."
        else:
            text = ("No certificates yet — use 🎛 Certificate Control Panel "
                    "to issue or import a certificate.")
        self._empty_label.config(text=text)
        self._empty_label.place(relx=0.5, rely=0.5, anchor="center")

    def _on_motion(self, event) -> None:
        # Intentionally a no-op: previously this overwrote the shared status var
        # on every mouse move, clobbering selection/action status.
        return

    def _show_context_menu(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.ctx_menu.post(event.x_root, event.y_root)

    def _get_selected_name(self):
        selected = self.tree.selection()
        if not selected:
            return None
        item = self.tree.item(selected[0])
        return item['values'][1]

    def on_select(self, event=None) -> None:
        name = self._get_selected_name()
        if not name:
            return

        trust_info = self.trust_service.get_trust_info(name)
        if not trust_info:
            return

        trust_level = trust_info.get("trust_level", "untrusted")
        trust_map = {
            "trusted": "Trusted",
            "partially_trusted": "Partially Trusted",
            "untrusted": "Untrusted",
            "unknown": "Unknown",
        }
        trust_text = trust_map.get(trust_level, trust_level.title())
        cert_count = trust_info.get("certificate_count", 0)
        signers = trust_info.get("signers", "—")
        nearest_expiry = trust_info.get("nearest_expiry", "—")

        self._detail_labels["name_lbl"].config(text=name)
        self._detail_labels["trust_lbl"].config(text=trust_text)
        self._detail_labels["cert_count_lbl"].config(text=str(cert_count))
        self._detail_labels["signers_lbl"].config(text=signers)
        self._detail_labels["expiry_lbl"].config(text=nearest_expiry)

        cert_details = trust_info.get("certificate_details", "No certificates found.")
        self.detail_text.config(state='normal')
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.insert('1.0', cert_details)
        self.detail_text.config(state='disabled')

        self.status_var.set(f"Selected: {name}")

    def issue_cert_dialog(self) -> None:
        name = self._get_selected_name()
        parent = self.frame.winfo_toplevel()
        try:
            from components.certificate_dialog import CertificateDialog
            CertificateDialog(parent, self.trust_service, self.friends_service,
                              self._bg, mode="issue", friend_name=name).show()
        except ImportError as e:
            logger.warning("Trust dialog component not available: %s", e)
            messagebox.showinfo(
                "در دسترس نیست",
                "این قابلیت نیاز به اجزای اضافی دارد.",
                parent=parent,
            )

    def import_cert_dialog(self) -> None:
        parent = self.frame.winfo_toplevel()
        dlg = tk.Toplevel(parent)
        dlg.title("Import Certificate")
        dlg.geometry("560x480")
        dlg.resizable(True, True)
        dlg.minsize(480, 360)
        dlg.configure(bg=self._bg)

        form = ttk.Frame(dlg, padding=20)
        form.pack(fill=tk.BOTH, expand=True)

        ttk.Label(form, text="Paste Certificate Bundle (PEM or Base64):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 8))

        cert_input = ttk.ScrolledText(form, height=16, wrap=tk.WORD,
                                      font=("Consolas", 9))
        cert_input.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        ttk.Label(form, text="Optional: Add a note for this certificate:",
                  font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 4))
        note_var = tk.StringVar()
        ttk.Entry(form, textvariable=note_var, width=50, bootstyle="primary").pack(anchor="w", pady=(0, 10))

        btn_frame = ttk.Frame(dlg, padding=(20, 10))
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)

        def do_import():
            cert_data = cert_input.get("1.0", tk.END).strip()
            if not cert_data:
                messagebox.showwarning("خالی", "لطفاً یک بسته گواهی را جای‌گذاری کنید.", parent=dlg)
                return
            note = note_var.get().strip()
            try:
                parsed = json.loads(cert_data)
                if isinstance(parsed, dict) and "certificates" in parsed:
                    cert_dicts = parsed["certificates"]
                elif isinstance(parsed, list):
                    cert_dicts = parsed
                else:
                    cert_dicts = [parsed]
                total = len(cert_dicts)
                count = self.trust_service.import_received_certs(cert_dicts)
                self.refresh_list()
                dlg.destroy()
                rejected = total - count
                if rejected > 0:
                    messagebox.showwarning(
                        "وارد شده با موارد رد شده",
                        f"{count} از {total} گواهی وارد شد.\n\n"
                        f"{rejected} مورد به دلیل تأیید نشدن امضا یا عدم شناسایی صادرکننده "
                        f"به عنوان یک مخاطب شناخته شده رد شدند. "
                        f"ابتدا صادرکننده را اضافه کنید، سپس دوباره وارد کنید.",
                        parent=parent,
                    )
                else:
                    messagebox.showinfo(
                        "وارد شد", f"{count} گواهی وارد شد.", parent=parent
                    )
                event_bus.publish(Events.TRUST_LEVEL_CHANGED, source="trust_tab")

            except Exception as e:
                messagebox.showerror("واردات ناموفق", friendly_error(e), parent=dlg)

        import_trust_btn = ttk.Button(btn_frame, text="📥 Import", command=do_import,
                                      bootstyle="info")
        import_trust_btn.pack(side=tk.RIGHT, padx=5)
        ToolTip(import_trust_btn, "وارد کردن گواهی زنجیره اعتماد")
        cancel_trust_btn = ttk.Button(btn_frame, text="Cancel", command=dlg.destroy,
                                      bootstyle="secondary-outline")
        cancel_trust_btn.pack(side=tk.RIGHT, padx=5)
        ToolTip(cancel_trust_btn, "انصراف از وارد کردن گواهی")

        init_modal(dlg, parent, focus_widget=cert_input)

    def export_cert_bundle_dialog(self) -> None:
        parent = self.frame.winfo_toplevel()
        path = filedialog.asksaveasfilename(
            parent=parent,
            title="Export Trust Certificate Bundle",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            bundle = self.trust_service.export_trust_bundle()
            with open(path, "w") as f:
                json.dump(bundle, f, indent=2)
            messagebox.showinfo(
                "صادر شد",
                f"بسته صادر شد به:\n{path}",
                parent=parent,
            )
        except Exception as e:
            messagebox.showerror("خطای صادرات", friendly_error(e), parent=parent)

    def import_cert_file_dialog(self) -> None:
        parent = self.frame.winfo_toplevel()
        path = filedialog.askopenfilename(
            parent=parent,
            title="Import Certificate Bundle",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r") as f:
                data = json.load(f)
            if isinstance(data, dict) and "certificates" in data:
                cert_dicts = data["certificates"]
            elif isinstance(data, list):
                cert_dicts = data
            else:
                cert_dicts = [data]
            total = len(cert_dicts)
            count = self.trust_service.import_received_certs(cert_dicts)
            self.refresh_list()
            rejected = total - count
            if rejected > 0:
                messagebox.showwarning(
                    "وارد شده با موارد رد شده",
                    f"{count} از {total} گواهی از فایل وارد شد.\n\n"
                    f"{rejected} مورد به دلیل تأیید نشدن امضا یا عدم شناسایی صادرکننده "
                    f"به عنوان یک مخاطب شناخته شده رد شدند. "
                    f"ابتدا صادرکننده را اضافه کنید، سپس دوباره وارد کنید.",
                    parent=parent,
                )
            else:
                messagebox.showinfo(
                    "وارد شد",
                    f"{count} گواهی از فایل وارد شد.",
                    parent=parent,
                )
            event_bus.publish(Events.TRUST_LEVEL_CHANGED, source="trust_tab")
        except Exception as e:
            messagebox.showerror("خطای واردات", friendly_error(e), parent=parent)

    def split_key_dialog(self) -> None:
        parent = self.frame.winfo_toplevel()
        try:
            from components.key_recovery_dialog import KeyRecoveryDialog
            KeyRecoveryDialog(parent, self.trust_service, self.friends_service,
                              self._bg, mode="split",
                              global_secret_service=self.global_secret_service).show()
        except ImportError as e:
            logger.warning("Trust dialog component not available: %s", e)
            messagebox.showinfo(
                "در دسترس نیست",
                "این قابلیت نیاز به اجزای اضافی دارد.",
                parent=parent,
            )

    def recover_key_dialog(self) -> None:
        parent = self.frame.winfo_toplevel()
        try:
            from components.key_recovery_dialog import KeyRecoveryDialog
            KeyRecoveryDialog(parent, self.trust_service, self.friends_service,
                              self._bg, mode="recover",
                              global_secret_service=self.global_secret_service).show()
        except ImportError as e:
            logger.warning("Trust dialog component not available: %s", e)
            messagebox.showinfo(
                "در دسترس نیست",
                "این قابلیت نیاز به اجزای اضافی دارد.",
                parent=parent,
            )

    def _ctx_revoke_cert(self) -> None:
        name = self._get_selected_name()
        if not name:
            return
        certs = self.trust_service.get_certs_for_friend(name)
        valid_certs = [c for c in certs if not c.revoked and not c.is_expired()]
        if not valid_certs:
            messagebox.showinfo("بدون گواهی", f"گواهی معتبری برای '{name}' یافت نشد.")
            return

        if len(valid_certs) == 1:
            cert = valid_certs[0]
        else:
            cert = self._choose_cert_dialog(name, valid_certs)
            if cert is None:
                return

        if not messagebox.askyesno(
            "لغو گواهی",
            f"آیا مطمئن هستید که می‌خواهید این گواهی را برای '{name}' لغو کنید؟\n\n"
            f"{self._cert_summary(cert)}\n\n"
            "این اقدام قابل بازگشت نیست."
        ):
            return
        try:
            self.trust_service.revoke_certificate(cert.cert_id, reason="Revoked by user")
            self.refresh_list()
            messagebox.showinfo("لغو شد", f"گواهی برای '{name}' لغو شد.")
            event_bus.publish(Events.CERTIFICATE_REVOKED, source="trust_tab", friend_name=name)
            event_bus.publish(Events.TRUST_LEVEL_CHANGED, source="trust_tab", friend_name=name)

        except Exception as e:
            messagebox.showerror("خطا", friendly_error(e))

    @staticmethod
    def _cert_summary(cert) -> str:
        import time
        issued = time.strftime("%Y-%m-%d", time.localtime(cert.created_at)) \
            if cert.created_at else "?"
        return (f"Issuer: {cert.issuer_name}\n"
                f"Issued: {issued}\n"
                f"Cert ID: {cert.cert_id}")

    def _choose_cert_dialog(self, name, certs):
        """Let the user pick which valid certificate to revoke. Returns a cert or None."""
        parent = self.frame.winfo_toplevel()
        dlg = tk.Toplevel(parent)
        dlg.title(f"Select Certificate to Revoke – {name}")
        dlg.geometry("560x340")
        dlg.configure(bg=self._bg)

        result = {"cert": None}

        form = ttk.Frame(dlg, padding=20)
        form.pack(fill=tk.BOTH, expand=True)

        ttk.Label(form, text=f"'{name}' has {len(certs)} valid certificates.\n"
                             "Choose which one to revoke:",
                  font=("Segoe UI", 10, "bold"), justify="left").pack(anchor="w", pady=(0, 10))

        sel_var = tk.IntVar(value=0)
        for idx, cert in enumerate(certs):
            ttk.Radiobutton(
                form, variable=sel_var, value=idx, bootstyle="primary",
                text=self._cert_summary(cert).replace("\n", "  |  "),
            ).pack(anchor="w", pady=2)

        btn_frame = ttk.Frame(dlg, padding=(20, 10))
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)

        def do_select():
            result["cert"] = certs[sel_var.get()]
            dlg.destroy()

        select_btn = ttk.Button(btn_frame, text="Select", command=do_select,
                                bootstyle="danger")
        select_btn.pack(side=tk.RIGHT, padx=5)
        ToolTip(select_btn, "انتخاب این گواهی برای لغو")
        cancel_choose_btn = ttk.Button(btn_frame, text="Cancel", command=dlg.destroy,
                                       bootstyle="secondary-outline")
        cancel_choose_btn.pack(side=tk.RIGHT, padx=5)
        ToolTip(cancel_choose_btn, "انصراف")

        init_modal(dlg, parent)
        dlg.wait_window()
        return result["cert"]

    def notify_trust_changed(self, **kwargs) -> None:
        self.refresh_list()
