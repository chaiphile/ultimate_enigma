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
from ttkbootstrap.tooltip import ToolTip
import base64

from services.friends_service import FriendsService, FriendsServiceError
from services.event_bus import event_bus, Events
from views.utils import password_dialog
from components.add_friend_dialog import AddFriendDialog
from components.pqc_exchange_dialog import PqcExchangeDialog
from components.hybrid_sig_exchange_dialog import HybridSigExchangeDialog


class FriendsTab:
    def __init__(self, parent: tk.Widget, friends_service: FriendsService, style_config=None) -> None:
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
    def _build_ui(self) -> None:
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
    def refresh_list(self) -> None:
        self.all_friend_names = [
            friend["name"] for friend in self.service.get_all_friends()
        ]
        self.filter_list()

    def filter_list(self) -> None:
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
    def _on_motion(self, event) -> None:
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

    def _ctx_copy_rsa_fp(self) -> None:
        name = self._get_selected_name()
        if not name:
            return
        details = self.service.get_friend_details(name)
        if details:
            self.frame.winfo_toplevel().clipboard_clear()
            self.frame.winfo_toplevel().clipboard_append(details["rsa_fingerprint"])
            self.status_var.set(f"Copied RSA fingerprint for {name}")

    def _ctx_copy_ecdh_fp(self) -> None:
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
    def on_select(self, event=None) -> None:
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

    def add_friend_dialog(self) -> None:
        parent = self.frame.winfo_toplevel()
        AddFriendDialog(parent, self.service, self._bg, self.refresh_list).show()

    def remove_friend_dialog(self) -> None:
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

    def ecdh_with_selected(self) -> None:
        name = self._get_selected_name()
        if not name:
            messagebox.showwarning("No Selection", "Please select a friend from the list first.")
            return

        friend_details = self.service.get_friend_details(name)
        if not friend_details:
            messagebox.showerror("Error", "Friend not found in database")
            return

        from views.ecdh import perform_ecdh
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

    def show_my_pubkey(self) -> None:
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
    def init_ratchet_dialog(self) -> None:
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

    def reset_ratchet_dialog(self) -> None:
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

    def pqc_exchange_dialog(self) -> None:
        parent = self.frame.winfo_toplevel()
        PqcExchangeDialog(parent, self.service, self._bg, self.refresh_list).show()

    def hybrid_sig_exchange_dialog(self) -> None:
        parent = self.frame.winfo_toplevel()
        HybridSigExchangeDialog(parent, self.service, self._bg, self.refresh_list).show()

    # ---- Set My Name dialog ----
    def set_my_name_dialog(self) -> None:
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
    def notify_friend_list_changed(self) -> None:
        """Called by app when external changes affect friend list."""
        self.refresh_list()
