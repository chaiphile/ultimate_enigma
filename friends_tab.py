"""Friends management tab – redesigned with modern table UI.

Publishes Events:
    FRIEND_LIST_CHANGED - when friends are added, removed, or modified.
    FRIEND_ADDED - when a new friend is added.
    FRIEND_REMOVED - when a friend is removed.
    RATCHET_INITIALIZED - when a ratchet session is initialized.
    RATCHET_RESET - when a ratchet session is reset.
"""

import tkinter as tk
from tkinter import messagebox, simpledialog
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.tooltip import ToolTip
import base64

from services.friends_service import FriendsService, FriendsServiceError
from services.event_bus import event_bus, Events
from utils import password_dialog


class FriendsTab:
    def __init__(self, parent, friends_service: FriendsService, style_config=None):
        """
        Args:
            parent: Notebook or parent widget
            friends_service: Injected FriendsService instance
            style_config: Dict with 'bg', 'fg' keys (optional, falls back to ttk.Style)
        """
        self.service = friends_service
        self.frame = ttk.Frame(parent)

        # Store style config for dialogs
        if style_config:
            self._bg = style_config.get('bg')
            self._fg = style_config.get('fg')
        else:
            s = ttk.Style()
            self._bg = s.colors.bg
            self._fg = s.colors.fg

        self.all_friend_names = []
        self._tooltips = {}  # Track tooltip widgets to avoid leaks
        self._build_ui()

    # ---- UI construction ----
    def _build_ui(self):
        # ── Top action bar ──────────────────────────────────────────────
        top_bar = ttk.Frame(self.frame, padding=(10, 8))
        top_bar.pack(fill=tk.X)

        btn_specs = [
            ("➕ Add Friend", self.add_friend_dialog, "success"),
            ("➖ Remove", self.remove_friend_dialog, "danger-outline"),
            ("🔑 My Public Key", self.show_my_pubkey, "info-outline"),
            ("✏️ Set My Name", self.set_my_name_dialog, "primary-outline"),
            ("🔁 ECDH Exchange", self.ecdh_with_selected, "secondary-outline"),
            ("🛡 PQC Exchange", self.pqc_exchange_dialog, "info"),
            ("✍️ Hybrid Sig Exchange", self.hybrid_sig_exchange_dialog, "success"),
            ("🔐 Init Ratchet", self.init_ratchet_dialog, "warning-outline"),
        ]
        for text, cmd, style in btn_specs:
            ttk.Button(top_bar, text=text, command=cmd,
                       bootstyle=style).pack(side=tk.LEFT, padx=(0, 6))

        # Spacer pushes search to the right
        ttk.Frame(top_bar).pack(side=tk.LEFT, expand=True)

        # Search box (right-aligned)
        search_frame = ttk.Frame(top_bar)
        search_frame.pack(side=tk.RIGHT)
        ttk.Label(search_frame, text="🔍", font=("Segoe UI Emoji", 10)).pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var,
                                      width=25, bootstyle="primary")
        self.search_entry.pack(side=tk.LEFT, padx=(4, 0))
        self.search_var.trace_add('write', lambda *a: self.filter_list())

        # ── Treeview table ──────────────────────────────────────────────
        list_frame = ttk.Frame(self.frame, padding=(10, 0))
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        columns = ("status", "name", "rsa_fp", "ecdh_status", "pqc_status", "hybrid_sig_status", "ratchet_status")
        self.tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="headings",
            bootstyle="primary",
            selectmode="browse",
            height=14,
        )

        # Column configuration
        col_config = {
            "status":          {"text": "Status",       "width": 70,  "anchor": "center"},
            "name":            {"text": "Friend Name",  "width": 140, "anchor": "w"},
            "rsa_fp":          {"text": "RSA Fingerprint", "width": 160, "anchor": "w"},
            "ecdh_status":     {"text": "ECDH Key",     "width": 70,  "anchor": "center"},
            "pqc_status":      {"text": "PQC Key",      "width": 70,  "anchor": "center"},
            "hybrid_sig_status": {"text": "Hybrid Sig", "width": 80,  "anchor": "center"},
            "ratchet_status":  {"text": "Ratchet",      "width": 70,  "anchor": "center"},
        }
        for col_id, cfg in col_config.items():
            self.tree.heading(col_id, text=cfg["text"], anchor=cfg["anchor"])
            self.tree.column(col_id, width=cfg["width"], anchor=cfg["anchor"],
                             minwidth=50)

        # Row tags for visual differentiation
        self.tree.tag_configure("has_secret", background="#d4edda", foreground="#155724")
        self.tree.tag_configure("no_secret", background="#ffffff", foreground="#212529")
        self.tree.tag_configure("even_row", background="#f0f2f5", foreground="#212529")
        self.tree.tag_configure("odd_row", background="#ffffff", foreground="#212529")

        # Scrollbar
        vsb = ttk.Scrollbar(list_frame, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        # Bindings
        self.tree.bind('<<TreeviewSelect>>', self.on_select)
        self.tree.bind('<Button-3>', self._show_context_menu)  # Right-click
        self.tree.bind('<Motion>', self._on_motion)  # Tooltip on hover

        # ── Context menu ────────────────────────────────────────────────
        self.ctx_menu = tk.Menu(self.frame, tearoff=0)
        self.ctx_menu.add_command(label="📋 Copy RSA Fingerprint",
                                  command=self._ctx_copy_rsa_fp)
        self.ctx_menu.add_command(label="📋 Copy ECDH Fingerprint",
                                  command=self._ctx_copy_ecdh_fp)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="🔁 Perform ECDH Exchange",
                                  command=self.ecdh_with_selected)
        self.ctx_menu.add_command(label="🔐 Initialize Ratchet",
                                  command=self.init_ratchet_dialog)
        self.ctx_menu.add_command(label="🔄 Reset Ratchet",
                                  command=self.reset_ratchet_dialog)
        self.ctx_menu.add_command(label="👁 View Full Details",
                                  command=lambda: self.on_select())
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="❌ Remove Friend",
                                  command=self.remove_friend_dialog)

        # ── Detail panel ────────────────────────────────────────────────
        detail_frame = ttk.Labelframe(self.frame, text="  Selected Friend Details  ",
                                      bootstyle="info", padding=5)
        detail_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        # Info grid inside detail panel
        info_grid = ttk.Frame(detail_frame)
        info_grid.pack(fill=tk.X, padx=5, pady=(5, 0))

        self._detail_labels = {}
        detail_fields = [
            ("name_lbl", "Name:", 0, 0),
            ("rsa_lbl", "RSA Fingerprint:", 1, 0),
            ("ecdh_lbl", "ECDH Fingerprint:", 2, 0),
            ("pqc_lbl", "PQC Hybrid Key:", 3, 0),
            ("hybrid_sig_lbl", "Hybrid Signature Key:", 4, 0),
            ("secret_lbl", "Shared Secret:", 5, 0),
            ("ratchet_lbl", "Double Ratchet:", 6, 0),
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

        # PEM display (collapsible feel via fixed height)
        pem_frame = ttk.Frame(detail_frame)
        pem_frame.pack(fill=tk.X, padx=5, pady=(8, 5))
        ttk.Label(pem_frame, text="Public Key PEM:",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.detail_pem = ttk.ScrolledText(pem_frame, height=3, wrap=tk.WORD,
                                           state='disabled', font=("Consolas", 8))
        self.detail_pem.pack(fill=tk.X, pady=(2, 0))

        # Status bar at bottom
        self.status_var = tk.StringVar(value="No friend selected")
        status_bar = ttk.Label(self.frame, textvariable=self.status_var,
                               font=("Segoe UI", 8), relief="sunken",
                               anchor="w", padding=(10, 2))
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        self.refresh_list()

    # ---- Data refresh ----
    def refresh_list(self):
        self.all_friend_names = [
            friend["name"] for friend in self.service.get_all_friends()
        ]
        self.filter_list()

    def filter_list(self):
        query = self.search_var.get().lower()
        # Clear existing tooltips
        self._tooltips.clear()

        for item in self.tree.get_children():
            self.tree.delete(item)

        row_idx = 0
        for friend in self.service.get_all_friends():
            name = friend["name"]
            if query and query not in name.lower():
                continue

            has_secret = friend["has_shared_secret"]
            rsa_fp = friend["rsa_fingerprint"]
            ecdh_fp = friend.get("ecdh_fingerprint")

            # Status badge text
            status_text = "🟢 Secure" if has_secret else "⚪ No Key"
            # ECDH status
            ecdh_text = "✅ Active" if ecdh_fp else "—"
            pqc_text = "🛡 Yes" if friend.get("has_pqc_key") else "—"
            hybrid_sig_text = "✍️ Yes" if friend.get("has_hybrid_sig_key") else "—"
            ratchet_text = "🔐 Active" if friend.get("has_ratchet") else "—"

            # Truncate RSA fingerprint for table display
            rsa_display = rsa_fp[:24] + "…" if len(rsa_fp) > 24 else rsa_fp

            # Determine tags – every row gets an explicit background
            tags = []
            if has_secret:
                tags.append("has_secret")
            else:
                tags.append("even_row" if row_idx % 2 == 0 else "odd_row")

            iid = self.tree.insert(
                "", tk.END,
                values=(status_text, name, rsa_display, ecdh_text, pqc_text, hybrid_sig_text, ratchet_text),
                tags=tags,
            )

            # Store full data for tooltip / context menu
            self._tooltips[iid] = {
                "rsa_fp": rsa_fp,
                "ecdh_fp": ecdh_fp,
                "name": name,
            }
            row_idx += 1

        count = len(self.tree.get_children())
        self.status_var.set(f"{count} friend(s) listed" +
                            (f" • Filtered by \"{query}\"" if query else ""))

    # ---- Hover tooltip ----
    def _on_motion(self, event):
        region = self.tree.identify_region(event.x, event.y)
        if region not in ("cell", "heading"):
            return
        iid = self.tree.identify_row(event.y)
        if not iid or iid not in self._tooltips:
            return

        data = self._tooltips[iid]
        tip_text = f"RSA: {data['rsa_fp']}"
        if data['ecdh_fp']:
            tip_text += f"\nECDH: {data['ecdh_fp']}"

        # Simple approach: update tree's own tooltip-like behavior via status bar
        self.status_var.set(f"{data['name']} | RSA: {data['rsa_fp']}" +
                            (f" | ECDH: {data['ecdh_fp']}" if data['ecdh_fp'] else ""))

    # ---- Context menu ----
    def _show_context_menu(self, event):
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

    def _ctx_copy_rsa_fp(self):
        name = self._get_selected_name()
        if not name:
            return
        details = self.service.get_friend_details(name)
        if details:
            self.frame.winfo_toplevel().clipboard_clear()
            self.frame.winfo_toplevel().clipboard_append(details["rsa_fingerprint"])
            self.status_var.set(f"Copied RSA fingerprint for {name}")

    def _ctx_copy_ecdh_fp(self):
        name = self._get_selected_name()
        if not name:
            return
        details = self.service.get_friend_details(name)
        if details and details.get("ecdh_fingerprint"):
            self.frame.winfo_toplevel().clipboard_clear()
            self.frame.winfo_toplevel().clipboard_append(details["ecdh_fingerprint"])
            self.status_var.set(f"Copied ECDH fingerprint for {name}")
        else:
            messagebox.showinfo("No ECDH Key", f"No ECDH key set for {name}.")

    # ---- Event handlers ----
    def on_select(self, event=None):
        name = self._get_selected_name()
        if not name:
            return

        details = self.service.get_friend_details(name)
        if not details:
            return

        # Update detail labels
        self._detail_labels["name_lbl"].config(text=details["name"])
        self._detail_labels["rsa_lbl"].config(text=details["rsa_fingerprint"])
        self._detail_labels["ecdh_lbl"].config(
            text=details.get("ecdh_fingerprint") or "Not configured"
        )
        pqc_status = "🛡 Stored" if details.get("has_pqc_key") else "❌ Not configured"
        self._detail_labels["pqc_lbl"].config(text=pqc_status)

        hybrid_sig_status = "✍️ Stored" if details.get("has_hybrid_sig_key") else "❌ Not configured"
        self._detail_labels["hybrid_sig_lbl"].config(text=hybrid_sig_status)

        secret_status = "✅ Yes — Encrypted" if details["has_shared_secret"] else "❌ No"
        self._detail_labels["secret_lbl"].config(text=secret_status)

        ratchet_status = "🔐 Active" if details.get("has_ratchet") else "❌ Not initialized"
        if details.get("supports_double_ratchet") and not details.get("has_ratchet"):
            ratchet_status = "⚠ Supported but not initialized"
        self._detail_labels["ratchet_lbl"].config(text=ratchet_status)

        # Update PEM text
        self.detail_pem.config(state='normal')
        self.detail_pem.delete('1.0', tk.END)
        self.detail_pem.insert('1.0', details['public_key_pem'])
        self.detail_pem.config(state='disabled')

        self.status_var.set(f"Selected: {name}")

    # ---- Dialogs ----
    def add_friend_dialog(self):
        parent = self.frame.winfo_toplevel()

        dlg = tk.Toplevel(parent)
        dlg.title("Add Friend")
        dlg.geometry("580x720")
        dlg.resizable(True, True)
        dlg.minsize(580, 680)
        dlg.transient(parent)
        dlg.grab_set()
        dlg.configure(bg=self._bg)

        # Styled form
        form = ttk.Frame(dlg, padding=20)
        form.pack(fill=tk.BOTH, expand=True)

        ttk.Label(form, text="Friend's Name:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        name_var = tk.StringVar()
        ttk.Entry(form, textvariable=name_var, width=50,
                  bootstyle="primary").pack(fill=tk.X, pady=(0, 12))

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

        # PQC Combined Public Key field
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
                    pqc_status_var.set("⚠ Too short for valid PQC combined key")
                    return
                pqc_status_var.set(f"✅ Valid PQC combined key ({len(raw)} bytes)")
            except Exception:
                pqc_status_var.set("⚠ Invalid Base64")

        pqc_var.trace_add('write', update_pqc_status)

        # Hybrid Signing Combined Public Key field
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
                    hybrid_sig_status_var.set("⚠ Too short for valid hybrid signing key")
                    return
                hybrid_sig_status_var.set(f"✅ Valid hybrid signing combined key ({len(raw)} bytes)")
            except Exception:
                hybrid_sig_status_var.set("⚠ Invalid Base64")

        hybrid_sig_var.trace_add('write', update_hybrid_sig_status)

        # Capabilities checkbox
        caps_frame = ttk.Frame(form)
        caps_frame.pack(fill=tk.X, pady=(0, 8))
        dr_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(caps_frame, text="Supports Double Ratchet protocol",
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

        # Button bar
        btn_frame = ttk.Frame(dlg, padding=(20, 10))
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)

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
                        raise ValueError("Length must be 32 bytes")
                except Exception as e:
                    messagebox.showerror("Invalid Secret",
                                         f"Shared secret invalid: {e}", parent=dlg)
                    return
                pw = password_dialog(dlg,
                                     "Enter Master Password to encrypt friend's secret",
                                     confirm=False)
                if not pw:
                    return
                if not self.service.verify_password(pw):
                    messagebox.showerror("Wrong Password",
                                         "Master password incorrect.", parent=dlg)
                    return

            pqc_b64 = pqc_var.get().strip() or None
            hybrid_sig_b64 = hybrid_sig_var.get().strip() or None

            capabilities = {}
            if dr_var.get():
                capabilities["double_ratchet"] = True

            try:
                self.service.add_friend(
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
                event_bus.publish(Events.FRIEND_ADDED, source="friends_tab", friend_name=name)
                event_bus.publish(Events.FRIEND_LIST_CHANGED, source="friends_tab")
            except FriendsServiceError as e:
                messagebox.showerror("Error", str(e), parent=dlg)

        ttk.Button(btn_frame, text="💾 Save Friend", command=save,
                   bootstyle="success").pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dlg.destroy,
                   bootstyle="secondary-outline").pack(side=tk.RIGHT, padx=5)

    def remove_friend_dialog(self):
        names = self.service.get_friend_names()
        if not names:
            messagebox.showinfo("No Friends", "You have no friends to remove.")
            return

        # Pre-select currently selected friend if any
        preselect = self._get_selected_name()

        choice = simpledialog.askstring(
            "Remove Friend",
            f"Enter friend name to remove:\n{', '.join(names)}",
            initialvalue=preselect or ""
        )
        if choice and choice in names:
            if messagebox.askyesno("Confirm", f"Are you sure you want to remove '{choice}'?"):
                self.service.remove_friend(choice)
                self.refresh_list()
                messagebox.showinfo("Removed", f"Friend '{choice}' removed.")
                event_bus.publish(Events.FRIEND_REMOVED, source="friends_tab", friend_name=choice)
                event_bus.publish(Events.FRIEND_LIST_CHANGED, source="friends_tab")
        elif choice:
            messagebox.showerror("Not Found", "Name not found in friend list.")

    def ecdh_with_selected(self):
        name = self._get_selected_name()
        if not name:
            messagebox.showwarning("No Selection", "Please select a friend from the list first.")
            return

        friend_details = self.service.get_friend_details(name)
        if not friend_details:
            messagebox.showerror("Error", "Friend not found in database")
            return

        from ecdh import perform_ecdh
        parent = self.frame.winfo_toplevel()
        result = perform_ecdh(parent, purpose=f"friend: {name}")
        if result is None:
            return

        new_secret, friend_x25519_b64 = result
        if new_secret:
            pw = password_dialog(parent,
                                 "Enter master password to encrypt new shared secret",
                                 confirm=False)
            if pw:
                if not self.service.verify_password(pw):
                    messagebox.showerror("Wrong Password", "Master password incorrect.")
                    return
                try:
                    self.service.update_shared_secret(
                        name=name,
                        new_secret=new_secret,
                        master_password=pw,
                        x25519_pub_b64=friend_x25519_b64,
                    )
                    self.refresh_list()
                    messagebox.showinfo(
                        "Success",
                        f"Shared secret for {name} updated via ECDH.\n"
                        "ECDH public key saved."
                    )
                except FriendsServiceError as e:
                    messagebox.showerror("Error", str(e))

    def show_my_pubkey(self):
        try:
            info = self.service.get_my_public_info()
        except FriendsServiceError as e:
            messagebox.showerror("Error", str(e))
            return

        pem = info["public_key_pem"]
        fp = info["fingerprint"]

        parent = self.frame.winfo_toplevel()
        top = tk.Toplevel(parent)
        top.title("My Public Key")
        top.geometry("700x600")
        top.resizable(True, True)
        top.minsize(500, 400)
        top.configure(bg=self._bg)

        btn_bar = ttk.Frame(top, padding=10)
        btn_bar.pack(side=tk.BOTTOM, fill=tk.X)

        def copy_pubkey():
            parent.clipboard_clear()
            parent.clipboard_append(pem)
            messagebox.showinfo("Copied", "Public key copied to clipboard.", parent=top)

        def copy_fp():
            parent.clipboard_clear()
            parent.clipboard_append(fp)
            messagebox.showinfo("Copied", "Fingerprint copied to clipboard.", parent=top)

        ttk.Button(btn_bar, text="📋 Copy Public Key", command=copy_pubkey,
                   bootstyle="info").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_bar, text="📋 Copy Fingerprint", command=copy_fp,
                   bootstyle="info-outline").pack(side=tk.LEFT, padx=5)

        content = ttk.Frame(top, padding=10)
        content.pack(fill=tk.BOTH, expand=True)

        ttk.Label(content, text="My Public Key Fingerprint:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        fp_label = ttk.Label(content, text=fp, font=("Consolas", 11),
                             bootstyle="inverse-secondary")
        fp_label.pack(anchor="w", pady=(0, 12))

        ttk.Label(content, text="PEM:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        txt = ttk.ScrolledText(content, wrap=tk.WORD, font=("Consolas", 9))
        txt.insert("1.0", pem)
        txt.config(state='disabled')
        txt.pack(fill=tk.BOTH, expand=True)

    # ---- Double Ratchet dialogs ----
    def init_ratchet_dialog(self):
        """Dialog to initialize a Double Ratchet session for the selected friend."""
        name = self._get_selected_name()
        if not name:
            messagebox.showwarning("No Selection",
                                   "Please select a friend from the list first.")
            return

        details = self.service.get_friend_details(name)
        if not details:
            messagebox.showerror("Error", "Friend not found.")
            return

        # Check prerequisites
        if not details["has_shared_secret"]:
            messagebox.showwarning(
                "Missing Shared Secret",
                f"No shared secret configured for '{name}'.\n"
                "Perform an ECDH exchange before initializing the ratchet."
            )
            return

        if not details.get("ecdh_fingerprint"):
            messagebox.showwarning(
                "Missing X25519 Key",
                f"No X25519 public key stored for '{name}'.\n"
                "Perform an ECDH exchange before initializing the ratchet."
            )
            return

        parent = self.frame.winfo_toplevel()
        dlg = tk.Toplevel(parent)
        dlg.title(f"Initialize Double Ratchet – {name}")
        dlg.geometry("460x320")
        dlg.resizable(False, False)
        dlg.transient(parent)
        dlg.grab_set()
        dlg.configure(bg=self._bg)

        form = ttk.Frame(dlg, padding=20)
        form.pack(fill=tk.BOTH, expand=True)

        ttk.Label(form, text=f"Friend: {name}",
                  font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 8))

        ecdh_fp = details.get("ecdh_fingerprint", "Unknown")
        ttk.Label(form, text=f"X25519 Fingerprint: {ecdh_fp}",
                  font=("Consolas", 9), bootstyle="secondary").pack(anchor="w", pady=(0, 12))

        ttk.Label(form, text="Your Role:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))

        role_var = tk.StringVar(value="alice")
        role_frame = ttk.Frame(form)
        role_frame.pack(anchor="w", pady=(0, 12))
        ttk.Radiobutton(role_frame, text="Alice (Initiator – sends first message)",
                        variable=role_var, value="alice",
                        bootstyle="primary").pack(anchor="w")
        ttk.Radiobutton(role_frame, text="Bob (Responder – receives first message)",
                        variable=role_var, value="bob",
                        bootstyle="primary").pack(anchor="w")

        ttk.Separator(form).pack(fill=tk.X, pady=(0, 12))

        ttk.Label(form,
                  text="⚠ This will replace any existing ratchet session.\n"
                       "Both parties must agree on roles and use the same shared secret.",
                  font=("Segoe UI", 9), bootstyle="warning",
                  wraplength=400, justify="left").pack(anchor="w")

        btn_frame = ttk.Frame(dlg, padding=(20, 10))
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)

        def do_init():
            pw = password_dialog(dlg, "Enter Master Password", confirm=False)
            if not pw:
                return
            if not self.service.verify_password(pw):
                messagebox.showerror("Wrong Password", "Master password incorrect.",
                                     parent=dlg)
                return
            try:
                self.service.init_ratchet(name, role_var.get(), pw)
                self.refresh_list()
                dlg.destroy()
                messagebox.showinfo(
                    "Success",
                    f"Double Ratchet session initialized as {role_var.get().upper()} "
                    f"for '{name}'.\n\n"
                    "Messages to/from this friend will now use forward-secret encryption."
                )
                event_bus.publish(Events.RATCHET_INITIALIZED, source="friends_tab", friend_name=name)
                event_bus.publish(Events.FRIEND_LIST_CHANGED, source="friends_tab")
            except FriendsServiceError as e:
                messagebox.showerror("Ratchet Init Failed", str(e), parent=dlg)

        ttk.Button(btn_frame, text="🔐 Initialize", command=do_init,
                   bootstyle="warning").pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dlg.destroy,
                   bootstyle="secondary-outline").pack(side=tk.RIGHT, padx=5)

    def reset_ratchet_dialog(self):
        """Confirm and delete the Double Ratchet session for the selected friend."""
        name = self._get_selected_name()
        if not name:
            messagebox.showwarning("No Selection",
                                   "Please select a friend from the list first.")
            return

        if not self.service.has_active_ratchet(name):
            messagebox.showinfo("No Ratchet",
                                f"No active ratchet session for '{name}'.")
            return

        if not messagebox.askyesno(
            "Reset Ratchet",
            f"Are you sure you want to delete the Double Ratchet session for '{name}'?\n\n"
            "This cannot be undone. Future messages will fall back to legacy encryption "
            "until a new session is established."
        ):
            return

        # Master password is required to re-encrypt the shared secret
        # during the save_friend REPLACE that updates capabilities.
        parent = self.frame.winfo_toplevel()
        pw = password_dialog(parent, "Enter Master Password", confirm=False)
        if not pw:
            return
        if not self.service.verify_password(pw):
            messagebox.showerror("Wrong Password", "Master password incorrect.")
            return

        try:
            self.service.reset_ratchet(name, master_password=pw)
            self.refresh_list()
            messagebox.showinfo("Reset Complete",
                                f"Ratchet session for '{name}' has been deleted.")
            event_bus.publish(Events.RATCHET_RESET, source="friends_tab", friend_name=name)
            event_bus.publish(Events.FRIEND_LIST_CHANGED, source="friends_tab")
        except FriendsServiceError as e:
            messagebox.showerror("Error", str(e))

    # ---- PQC Hybrid Key Exchange dialog ----
    def pqc_exchange_dialog(self):
        """Dialog for Post-Quantum Hybrid KEM key exchange.

        Requires master password authentication before granting access to
        any PQC key material or operations.

        Allows users to:
        1. Generate local PQC keys and view/copy the combined public key.
        2. Import a friend's PQC combined public key.
        3. Perform encapsulation (generate shared secret + ciphertext to send).
        4. Perform decapsulation (recover shared secret from received ciphertext).
        """
        parent = self.frame.winfo_toplevel()

        # ── Master Password Gate ────────────────────────────────────────
        # Require authentication before exposing any PQC key material
        pqc_pw = password_dialog(
            parent,
            "🛡 PQC Key Exchange – Master Password Required",
            confirm=False,
        )
        if not pqc_pw:
            return  # User cancelled
        if not self.service.verify_password(pqc_pw):
            messagebox.showerror(
                "Access Denied",
                "Incorrect master password.\n"
                "PQC key exchange requires authentication.",
                parent=parent,
            )
            return

        dlg = tk.Toplevel(parent)
        dlg.title("🛡 Post-Quantum Hybrid Key Exchange")
        dlg.geometry("680x720")
        dlg.resizable(True, True)
        dlg.minsize(580, 600)
        dlg.transient(parent)
        dlg.grab_set()
        dlg.configure(bg=self._bg)

        notebook = ttk.Notebook(dlg, bootstyle="primary")
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))

        # ── Tab 1: My PQC Keys ───────────────────────────────────────────
        tab_keys = ttk.Frame(notebook, padding=15)
        notebook.add(tab_keys, text="  My PQC Keys  ")

        my_pub_text = ttk.ScrolledText(tab_keys, height=4, wrap=tk.WORD,
                                       font=("Consolas", 9), state='disabled')
        my_status_var = tk.StringVar(value="Checking...")

        def load_my_pqc():
            pub_b64 = self.service.get_my_pqc_combined_pub()
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
                parent.clipboard_clear()
                parent.clipboard_append(content)
                messagebox.showinfo("Copied", "PQC combined public key copied to clipboard.",
                                    parent=dlg)

        def generate_pqc():
            pw = password_dialog(dlg, "Enter Master Password to generate PQC keys",
                                 confirm=False)
            if not pw:
                return
            if not self.service.verify_password(pw):
                messagebox.showerror("Wrong Password", "Master password incorrect.",
                                     parent=dlg)
                return
            try:
                pub_b64 = self.service.generate_pqc_keys(pw)
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

        # ── Tab 2: Encapsulate (Initiate Exchange) ───────────────────────
        tab_encap = ttk.Frame(notebook, padding=15)
        notebook.add(tab_encap, text="  Encapsulate (Send)  ")

        ttk.Label(tab_encap,
                  text="Select a friend with a stored PQC public key to derive a shared secret.",
                  font=("Segoe UI", 9), wraplength=600).pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_encap, text="Friend:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        friend_names = [f["name"] for f in self.service.get_all_friends()
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
                ct_b64, shared_secret = self.service.pqc_encapsulate(fname, "")
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
                # Offer to save the shared secret
                save_pw = password_dialog(
                    dlg,
                    "Enter Master Password to save the derived shared secret",
                    confirm=False
                )
                if save_pw and self.service.verify_password(save_pw):
                    self.service.update_shared_secret(
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
                # Copy only the ciphertext portion
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
                    parent.clipboard_clear()
                    parent.clipboard_append(ct_line)
                    messagebox.showinfo("Copied", "Ciphertext copied to clipboard.",
                                        parent=dlg)

        encap_btn_row = ttk.Frame(tab_encap)
        encap_btn_row.pack(fill=tk.X)
        ttk.Button(encap_btn_row, text="🔒 Encapsulate & Derive Secret",
                   command=do_encapsulate, bootstyle="info").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(encap_btn_row, text="📋 Copy Ciphertext",
                   command=copy_encap_result, bootstyle="info-outline").pack(side=tk.LEFT)

        # ── Tab 3: Decapsulate (Receive) ─────────────────────────────────
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
            if not self.service.verify_password(pw):
                messagebox.showerror("Wrong Password", "Master password incorrect.",
                                     parent=dlg)
                return
            try:
                shared_secret = self.service.pqc_decapsulate(ct_b64, pw)
                ss_b64 = base64.b64encode(shared_secret).decode()
                fp = base64.b64encode(shared_secret[:8]).decode()
                decap_result_var.set(
                    f"✅ Shared secret recovered!\n"
                    f"Secret (Base64): {ss_b64}\n"
                    f"Fingerprint: {fp}\n\n"
                    f"You can now use this secret for encrypted communication."
                )
                # Offer to save for a specific friend
                all_names = self.service.get_friend_names()
                if all_names:
                    save_for = simpledialog.askstring(
                        "Save Shared Secret",
                        "Optionally save this secret for a friend:\n"
                        f"{', '.join(all_names)}\n\n"
                        "(Leave empty to skip saving)",
                        parent=dlg
                    )
                    if save_for and save_for in all_names:
                        self.service.update_shared_secret(
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

        # ── Tab 4: Import Friend PQC Key ─────────────────────────────────
        tab_import = ttk.Frame(notebook, padding=15)
        notebook.add(tab_import, text="  Import Friend Key  ")

        ttk.Label(tab_import,
                  text="Import a friend's PQC combined public key for future encapsulation.",
                  font=("Segoe UI", 9), wraplength=600).pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_import, text="Friend:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        all_friend_names = self.service.get_friend_names()
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
            # Validate
            try:
                raw = base64.b64decode(key_b64)
                if len(raw) < 36:
                    raise ValueError("Too short")
            except Exception as e:
                messagebox.showerror("Invalid Key",
                                     f"Invalid PQC combined public key: {e}",
                                     parent=dlg)
                return
            # Save by re-saving the friend with the PQC key
            details = self.service.get_friend_details(fname)
            if not details:
                messagebox.showerror("Error", f"Friend '{fname}' not found.",
                                     parent=dlg)
                return
            try:
                secret = self.service.get_friend_secret(fname)
                x_b64 = self.service.get_friend_x25519_key(fname)
                caps = self.service.get_friend_capabilities(fname)

                # If friend has an existing shared secret, we need the master
                # password to re-encrypt it during the save_friend REPLACE.
                pw = ""
                if secret:
                    pw = password_dialog(
                        dlg,
                        "Enter Master Password to encrypt shared secret",
                        confirm=False,
                    )
                    if not pw:
                        return
                    if not self.service.verify_password(pw):
                        messagebox.showerror("Wrong Password",
                                             "Master password incorrect.",
                                             parent=dlg)
                        return

                self.service.add_friend(
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

        # Close button
        ttk.Button(dlg, text="Close", command=dlg.destroy,
                   bootstyle="secondary-outline").pack(pady=(0, 10))

    # ---- Hybrid Signature Key Exchange dialog ----
    def hybrid_sig_exchange_dialog(self):
        """Dialog for Hybrid Signature (Ed25519 + Dilithium3) key exchange.

        Requires master password authentication before granting access to
        any hybrid signing key material or operations.

        Allows users to:
        1. Generate local hybrid signing keys and view/copy the combined public key.
        2. Import a friend's hybrid signing combined public key.
        3. View fingerprints for out-of-band verification.
        """
        parent = self.frame.winfo_toplevel()

        # ── Master Password Gate ────────────────────────────────────────
        pqc_pw = password_dialog(
            parent,
            "✍️ Hybrid Signature Key Exchange – Master Password Required",
            confirm=False,
        )
        if not pqc_pw:
            return
        if not self.service.verify_password(pqc_pw):
            messagebox.showerror(
                "Access Denied",
                "Incorrect master password.\n"
                "Hybrid signature key exchange requires authentication.",
                parent=parent,
            )
            return

        dlg = tk.Toplevel(parent)
        dlg.title("✍️ Hybrid Signature Key Exchange (Ed25519 + Dilithium3)")
        dlg.geometry("680x680")
        dlg.resizable(True, True)
        dlg.minsize(580, 580)
        dlg.transient(parent)
        dlg.grab_set()
        dlg.configure(bg=self._bg)

        notebook = ttk.Notebook(dlg, bootstyle="success")
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))

        # ── Tab 1: My Hybrid Signing Keys ───────────────────────────────
        tab_keys = ttk.Frame(notebook, padding=15)
        notebook.add(tab_keys, text="  My Signing Keys  ")

        my_pub_text = ttk.ScrolledText(tab_keys, height=4, wrap=tk.WORD,
                                       font=("Consolas", 9), state='disabled')
        my_status_var = tk.StringVar(value="Checking...")
        my_fp_var = tk.StringVar(value="")

        def load_my_hybrid_sig():
            pub_b64 = self.service.get_my_hybrid_sig_combined_pub()
            my_pub_text.config(state='normal')
            my_pub_text.delete('1.0', tk.END)
            if pub_b64:
                my_pub_text.insert('1.0', pub_b64)
                my_status_var.set(f"✅ Hybrid signing keys loaded ({len(pub_b64)} chars Base64)")
                fp = self.service.get_hybrid_sig_key_fingerprint(pub_b64)
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
                parent.clipboard_clear()
                parent.clipboard_append(content)
                messagebox.showinfo("Copied",
                                    "Hybrid signing combined public key copied to clipboard.",
                                    parent=dlg)

        def generate_hybrid_sig():
            pw = password_dialog(dlg,
                                 "Enter Master Password to generate hybrid signing keys",
                                 confirm=False)
            if not pw:
                return
            if not self.service.verify_password(pw):
                messagebox.showerror("Wrong Password", "Master password incorrect.",
                                     parent=dlg)
                return
            try:
                pub_b64 = self.service.generate_hybrid_sig_keys(pw)
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

        ttk.Button(btn_row_keys, text="📋 Copy Public Key", command=copy_my_hybrid_sig,
                   bootstyle="success-outline").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_row_keys, text="🔑 Generate New Signing Keys",
                   command=generate_hybrid_sig,
                   bootstyle="success").pack(side=tk.LEFT)

        # ── Tab 2: Import Friend Hybrid Signing Key ─────────────────────
        tab_import = ttk.Frame(notebook, padding=15)
        notebook.add(tab_import, text="  Import Friend Key  ")

        ttk.Label(tab_import,
                  text="Import a friend's hybrid signing combined public key to verify\n"
                       "their messages with both Ed25519 and Dilithium3.",
                  font=("Segoe UI", 9), wraplength=600).pack(anchor="w", pady=(0, 10))

        ttk.Label(tab_import, text="Friend:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        all_friend_names = self.service.get_friend_names()
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
            fp = self.service.get_hybrid_sig_key_fingerprint(content)
            import_fp_var.set(f"Fingerprint: {fp}" if fp else "⚠ Invalid Base64")

        import_key_text.bind('<KeyRelease>', lambda e: update_import_fp())

        import_status_var = tk.StringVar(value="")
        ttk.Label(tab_import, textvariable=import_status_var,
                  font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 8))

        def do_import_hybrid_sig_key():
            fname = import_friend_var.get()
            key_b64 = import_key_text.get('1.0', tk.END).strip()
            if not fname:
                messagebox.showwarning("No Selection", "Please select a friend.",
                                       parent=dlg)
                return
            if not key_b64:
                messagebox.showwarning("Empty Key",
                                       "Please paste the hybrid signing combined public key.",
                                       parent=dlg)
                return
            # If friend has an existing shared secret, we need the master password
            pw = ""
            secret = self.service.get_friend_secret(fname)
            if secret:
                pw = password_dialog(
                    dlg,
                    "Enter Master Password to encrypt shared secret",
                    confirm=False,
                )
                if not pw:
                    return
                if not self.service.verify_password(pw):
                    messagebox.showerror("Wrong Password",
                                         "Master password incorrect.",
                                         parent=dlg)
                    return
            try:
                self.service.import_friend_hybrid_sig_pub(
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

        # ── Tab 3: Status Overview ──────────────────────────────────────
        tab_status = ttk.Frame(notebook, padding=15)
        notebook.add(tab_status, text="  Status  ")

        ttk.Label(tab_status,
                  text="Hybrid Signing Key Status Overview",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 10))

        # My key status
        my_pub = self.service.get_my_hybrid_sig_combined_pub()
        my_key_status = "✅ Generated" if my_pub else "❌ Not generated"
        ttk.Label(tab_status, text=f"My Hybrid Signing Keys: {my_key_status}",
                  font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 4))

        if my_pub:
            fp = self.service.get_hybrid_sig_key_fingerprint(my_pub)
            ttk.Label(tab_status, text=f"  Fingerprint: {fp}",
                      font=("Consolas", 9), bootstyle="warning").pack(anchor="w", pady=(0, 8))

        ttk.Separator(tab_status, orient='horizontal').pack(fill=tk.X, pady=8)

        # Friends' key status
        ttk.Label(tab_status, text="Friends with Hybrid Signing Keys:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))

        friends_frame = ttk.Frame(tab_status)
        friends_frame.pack(fill=tk.X)

        friends_with_hybrid = [
            f for f in self.service.get_all_friends()
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

        # Summary
        total_friends = len(self.service.get_all_friends())
        hybrid_sig_friends = len(friends_with_hybrid)
        ttk.Label(tab_status,
                  text=f"Summary: {hybrid_sig_friends}/{total_friends} friends with hybrid signing keys",
                  font=("Segoe UI", 9)).pack(anchor="w")

        # Close button
        ttk.Button(dlg, text="Close", command=dlg.destroy,
                   bootstyle="secondary-outline").pack(pady=(0, 10))

    # ---- Set My Name dialog ----
    def set_my_name_dialog(self):
        """Allow the user to set their display name for ratchet envelopes."""
        parent = self.frame.winfo_toplevel()
        current_name = getattr(self.service, '_ks', None)
        if current_name is not None:
            current_name = current_name.my_name
        else:
            current_name = ""

        new_name = simpledialog.askstring(
            "Set My Display Name",
            "Your display name is embedded in Double Ratchet messages so that\n"
            "recipients can identify which ratchet session to use.\n\n"
            "This name MUST match what your contacts have saved as your friend name.",
            initialvalue=current_name,
            parent=parent,
        )
        if new_name is not None:
            new_name = new_name.strip()
            if not new_name:
                messagebox.showwarning("Empty Name", "Name cannot be empty.", parent=parent)
                return
            ks = getattr(self.service, '_ks', None)
            if ks is not None:
                ks.set_my_name(new_name)
                messagebox.showinfo("Success", f"Display name set to '{new_name}'.", parent=parent)
            else:
                messagebox.showerror("Error", "KeyStore not available.", parent=parent)

    # ---- External notification hook ----
    def notify_friend_list_changed(self):
        """Called by app when external changes affect friend list."""
        self.refresh_list()
