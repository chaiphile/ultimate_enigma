"""Trust chain certificate management tab.

Manages trust certificates between friends, allowing users to issue,
import, revoke certificates and manage key recovery shares.

Publishes Events:
    TRUST_LEVEL_CHANGED - when a trust level changes for a friend.
    CERTIFICATE_ISSUED - when a certificate is issued.
    CERTIFICATE_REVOKED - when a certificate is revoked.
"""

import json
import tkinter as tk
from tkinter import messagebox, simpledialog
import ttkbootstrap as ttk
from ttkbootstrap.dialogs import Messagebox
import base64

from services.event_bus import event_bus, Events
from views.utils import password_dialog


class TrustTab:
    def __init__(self, parent: tk.Widget, trust_chain_service, friends_service, style_config=None) -> None:
        """
        Args:
            parent: Notebook or parent widget
            trust_chain_service: Injected TrustChainService instance
            friends_service: Injected FriendsService instance
            style_config: Dict with 'bg', 'fg' keys (optional, falls back to ttk.Style)
        """
        self.trust_service = trust_chain_service
        self.friends_service = friends_service
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
        self._build_ui()

    def _build_ui(self) -> None:
        top_bar = ttk.Frame(self.frame, padding=(10, 8))
        top_bar.pack(fill=tk.X)

        btn_specs = [
            ("➕ Issue Certificate", self.issue_cert_dialog, "success"),
            ("📥 Import Certificate", self.import_cert_dialog, "info"),
            ("🔑 Split Recovery Key", self.split_key_dialog, "warning"),
            ("🔓 Recover Key", self.recover_key_dialog, "danger"),
            ("🔄 Refresh", self.refresh_list, "secondary-outline"),
        ]
        for text, cmd, style in btn_specs:
            ttk.Button(top_bar, text=text, command=cmd,
                       bootstyle=style).pack(side=tk.LEFT, padx=(0, 6))

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

        self.tree.tag_configure("has_certs", background="#d4edda", foreground="#155724")
        self.tree.tag_configure("no_certs", background="#ffffff", foreground="#212529")
        self.tree.tag_configure("even_row", background="#f0f2f5", foreground="#212529")
        self.tree.tag_configure("odd_row", background="#ffffff", foreground="#212529")

        vsb = ttk.Scrollbar(list_frame, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        self.tree.bind('<<TreeviewSelect>>', self.on_select)
        self.tree.bind('<Button-3>', self._show_context_menu)
        self.tree.bind('<Motion>', self._on_motion)

        self.ctx_menu = tk.Menu(self.frame, tearoff=0)
        self.ctx_menu.add_command(label="➕ Issue Certificate to Friend",
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
        self.all_friend_names = [
            friend["name"] for friend in self.friends_service.get_all_friends()
        ]
        self.filter_list()

    def filter_list(self) -> None:
        query = self.search_var.get().lower()
        self._tooltips.clear()

        for item in self.tree.get_children():
            self.tree.delete(item)

        row_idx = 0
        for friend in self.friends_service.get_all_friends():
            name = friend["name"]
            if query and query not in name.lower():
                continue

            trust_info = self.trust_service.get_trust_info(name)
            trust_level = trust_info.get("trust_level", "untrusted")
            cert_count = trust_info.get("certificate_count", 0)
            last_cert = trust_info.get("last_certificate_date", "—")
            nearest_expiry = trust_info.get("nearest_expiry", "—")
            badge = trust_info.get("badge", "⚪")

            trust_map = {
                "trusted": "Trusted",
                "partially_trusted": "Partial",
                "untrusted": "Untrusted",
                "unknown": "Unknown",
            }
            trust_text = trust_map.get(trust_level, trust_level.title())

            status_text = f"{badge} {trust_text}"
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
        self.status_var.set(f"{count} friend(s) listed" +
                            (f" • Filtered by \"{query}\"" if query else ""))

    def _on_motion(self, event) -> None:
        region = self.tree.identify_region(event.x, event.y)
        if region not in ("cell", "heading"):
            return
        iid = self.tree.identify_row(event.y)
        if not iid or iid not in self._tooltips:
            return

        data = self._tooltips[iid]
        self.status_var.set(f"{data['name']} | Trust: {data['trust_level']} | Certs: {data['cert_count']}")

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
        except ImportError:
            messagebox.showinfo(
                "Issue Certificate",
                f"Certificate Issuance for: {name or '(select a friend)'}\n\n"
                "The certificate dialog component is not yet available.\n"
                "This feature will be available when CertificateDialog is implemented.",
                parent=parent,
            )

    def import_cert_dialog(self) -> None:
        parent = self.frame.winfo_toplevel()
        dlg = tk.Toplevel(parent)
        dlg.title("Import Certificate")
        dlg.geometry("520x380")
        dlg.resizable(False, False)
        dlg.transient(parent)
        dlg.grab_set()
        dlg.configure(bg=self._bg)

        form = ttk.Frame(dlg, padding=20)
        form.pack(fill=tk.BOTH, expand=True)

        ttk.Label(form, text="Paste Certificate Bundle (PEM or Base64):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 8))

        cert_input = ttk.ScrolledText(form, height=12, wrap=tk.WORD,
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
                messagebox.showwarning("Empty", "Please paste a certificate bundle.", parent=dlg)
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
                count = self.trust_service.import_received_certs(cert_dicts)
                self.refresh_list()
                dlg.destroy()
                messagebox.showinfo("Imported", f"Imported {count} certificate(s).", parent=parent)
                event_bus.publish(Events.CERTIFICATE_RECEIVED, source="trust_tab")
            except Exception as e:
                messagebox.showerror("Import Failed", str(e), parent=dlg)

        ttk.Button(btn_frame, text="📥 Import", command=do_import,
                   bootstyle="info").pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dlg.destroy,
                   bootstyle="secondary-outline").pack(side=tk.RIGHT, padx=5)

    def split_key_dialog(self) -> None:
        parent = self.frame.winfo_toplevel()
        try:
            from components.key_recovery_dialog import KeyRecoveryDialog
            KeyRecoveryDialog(parent, self.trust_service, self.friends_service,
                              self._bg, mode="split").show()
        except ImportError:
            messagebox.showinfo(
                "Split Recovery Key",
                "Key recovery share generation is not yet available.\n"
                "This feature will be available when KeyRecoveryDialog is implemented.",
                parent=parent,
            )

    def recover_key_dialog(self) -> None:
        parent = self.frame.winfo_toplevel()
        try:
            from components.key_recovery_dialog import KeyRecoveryDialog
            KeyRecoveryDialog(parent, self.trust_service, self.friends_service,
                              self._bg, mode="recover").show()
        except ImportError:
            messagebox.showinfo(
                "Recover Key",
                "Key recovery reconstruction is not yet available.\n"
                "This feature will be available when KeyRecoveryDialog is implemented.",
                parent=parent,
            )

    def _ctx_revoke_cert(self) -> None:
        name = self._get_selected_name()
        if not name:
            return
        certs = self.trust_service.get_certs_for_friend(name)
        valid_certs = [c for c in certs if not c.revoked and not c.is_expired()]
        if not valid_certs:
            messagebox.showinfo("No Certificates", f"No valid certificates found for '{name}'.")
            return
        if not messagebox.askyesno(
            "Revoke Certificate",
            f"Are you sure you want to revoke the certificate for '{name}'?\n\n"
            "This action cannot be undone."
        ):
            return
        try:
            self.trust_service.revoke_certificate(valid_certs[0].cert_id, reason="Revoked by user")
            self.refresh_list()
            messagebox.showinfo("Revoked", f"Certificate for '{name}' revoked.")
            event_bus.publish(Events.CERTIFICATE_REVOKED, source="trust_tab", friend_name=name)
            event_bus.publish(Events.TRUST_LEVEL_CHANGED, source="trust_tab", friend_name=name)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def notify_trust_changed(self) -> None:
        self.refresh_list()
