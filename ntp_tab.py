"""NTP Tab – Network Time Protocol synchronization status and manual sync."""

import tkinter as tk
import threading
import time
from datetime import datetime, timezone
import ttkbootstrap as ttkb
from ttkbootstrap.constants import *

from ntp_client import get_ntp_time, NTP_SERVERS as CONSENSUS_SERVERS

PRESET_NTP_SERVERS = [
    "ntp.day.ir",
    "pool.ntp.org",
    "time.nist.gov",
    "time.google.com",
    "time.cloudflare.com",
    "ntp.ubuntu.com",
]

# Build ordered fallback list: presets first, then consensus servers not already in presets
_FALLBACK_SERVERS = list(PRESET_NTP_SERVERS)
for _srv in CONSENSUS_SERVERS:
    if _srv not in _FALLBACK_SERVERS:
        _FALLBACK_SERVERS.append(_srv)


class NtpTab:
    def __init__(self, parent, app):
        self.app = app
        self.frame = ttkb.Frame(parent)
        self._syncing = False
        self._build_ui()
        self._start_auto_refresh()

    def _build_ui(self):
        # --- Bottom action bar (packed FIRST so it's always visible) ---
        bottom_bar = ttkb.Frame(self.frame, padding=(15, 10))
        bottom_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.sync_btn = ttkb.Button(bottom_bar, text="🔄 Sync Now",
                                    command=self._manual_sync,
                                    bootstyle="success",
                                    width=18)
        self.sync_btn.pack(side=tk.LEFT, padx=8)

        self.status_indicator = ttkb.Label(bottom_bar, text="",
                                           font=("Segoe UI", 10),
                                           bootstyle="inverse-secondary")
        self.status_indicator.pack(side=tk.LEFT, padx=10)

        # --- Main scrollable content area ---
        f = ttkb.Frame(self.frame, padding=(15, 15, 15, 5))
        f.pack(fill=tk.BOTH, expand=True)

        # Title
        ttkb.Label(f, text="🕐 NTP Synchronization",
                   font=("Segoe UI", 18, "bold"),
                   bootstyle="inverse-primary").pack(pady=(0, 5))

        ttkb.Label(f, text="Network Time Protocol Status & Manual Sync",
                   font=("Segoe UI", 10),
                   bootstyle="inverse-secondary").pack(pady=(0, 15))

        # Status frame
        status_frame = ttkb.Labelframe(f, text="Current Status", padding=20, bootstyle="dark")
        status_frame.pack(fill=tk.X, pady=(0, 20))

        # NTP Time display
        time_row = ttkb.Frame(status_frame)
        time_row.pack(fill=tk.X, pady=5)
        ttkb.Label(time_row, text="NTP Server Time:",
                   font=("Segoe UI", 11, "bold"),
                   bootstyle="inverse-secondary", width=18).pack(side=tk.LEFT)
        self.ntp_time_label = ttkb.Label(time_row, text="Not synchronized",
                                         font=("Consolas", 14),
                                         bootstyle="inverse-warning")
        self.ntp_time_label.pack(side=tk.LEFT, padx=10)

        # Local Time display
        local_row = ttkb.Frame(status_frame)
        local_row.pack(fill=tk.X, pady=5)
        ttkb.Label(local_row, text="Local System Time:",
                   font=("Segoe UI", 11, "bold"),
                   bootstyle="inverse-secondary", width=18).pack(side=tk.LEFT)
        self.local_time_label = ttkb.Label(local_row, text="--",
                                           font=("Consolas", 14),
                                           bootstyle="inverse-info")
        self.local_time_label.pack(side=tk.LEFT, padx=10)

        # Offset display
        offset_row = ttkb.Frame(status_frame)
        offset_row.pack(fill=tk.X, pady=5)
        ttkb.Label(offset_row, text="Time Offset:",
                   font=("Segoe UI", 11, "bold"),
                   bootstyle="inverse-secondary", width=18).pack(side=tk.LEFT)
        self.offset_label = ttkb.Label(offset_row, text="--",
                                       font=("Consolas", 12),
                                       bootstyle="inverse-secondary")
        self.offset_label.pack(side=tk.LEFT, padx=10)

        # Last sync display
        last_row = ttkb.Frame(status_frame)
        last_row.pack(fill=tk.X, pady=5)
        ttkb.Label(last_row, text="Last Successful Sync:",
                   font=("Segoe UI", 11, "bold"),
                   bootstyle="inverse-secondary", width=18).pack(side=tk.LEFT)
        self.last_sync_label = ttkb.Label(last_row, text="Never",
                                          font=("Segoe UI", 10),
                                          bootstyle="inverse-secondary")
        self.last_sync_label.pack(side=tk.LEFT, padx=10)

        # Server selection
        sep = ttkb.Separator(f, orient="horizontal")
        sep.pack(fill="x", pady=(10, 15))

        server_frame = ttkb.Labelframe(f, text="NTP Server Configuration", padding=15, bootstyle="dark")
        server_frame.pack(fill=tk.X, pady=(0, 15))

        # Preset dropdown
        preset_row = ttkb.Frame(server_frame)
        preset_row.pack(fill=tk.X, pady=(0, 8))
        ttkb.Label(preset_row, text="Preset Servers:",
                   font=("Segoe UI", 10, "bold"),
                   bootstyle="inverse-secondary", width=14).pack(side=tk.LEFT)
        self._selected_server = tk.StringVar(value=PRESET_NTP_SERVERS[0])
        self.server_combo = ttkb.Combobox(
            preset_row,
            textvariable=self._selected_server,
            values=PRESET_NTP_SERVERS,
            state="readonly",
            width=30,
            bootstyle="dark"
        )
        self.server_combo.pack(side=tk.LEFT, padx=5)
        self.server_combo.bind("<<ComboboxSelected>>", self._on_server_changed)

        # Custom server entry
        custom_row = ttkb.Frame(server_frame)
        custom_row.pack(fill=tk.X)
        ttkb.Label(custom_row, text="Custom Server:",
                   font=("Segoe UI", 10, "bold"),
                   bootstyle="inverse-secondary", width=14).pack(side=tk.LEFT)
        self.custom_server_var = tk.StringVar()
        self.custom_entry = ttkb.Entry(custom_row, textvariable=self.custom_server_var,
                                       width=32, bootstyle="dark")
        self.custom_entry.pack(side=tk.LEFT, padx=5)
        self.custom_entry.bind("<KeyRelease>", self._on_custom_server_changed)

        # Active server display
        active_row = ttkb.Frame(server_frame)
        active_row.pack(fill=tk.X, pady=(8, 0))
        ttkb.Label(active_row, text="Active Server:",
                   font=("Segoe UI", 10, "bold"),
                   bootstyle="inverse-secondary", width=14).pack(side=tk.LEFT)
        self.server_label = ttkb.Label(active_row, text=f"{PRESET_NTP_SERVERS[0]}:123",
                                       font=("Consolas", 10),
                                       bootstyle="inverse-info")
        self.server_label.pack(side=tk.LEFT, padx=5)



    def _start_auto_refresh(self):
        """Refresh local time display every second."""
        self._update_local_time()
        self.frame.after(1000, self._start_auto_refresh)

    def _update_local_time(self):
        now = datetime.now()
        self.local_time_label.config(text=now.strftime("%Y-%m-%d %H:%M:%S"))

    def _manual_sync(self):
        if self._syncing:
            return
        self._syncing = True
        self.sync_btn.config(state=tk.DISABLED)
        self.status_indicator.config(text="⏳ Synchronizing...", bootstyle="inverse-warning")
        threading.Thread(target=self._do_sync, daemon=True).start()

    def _get_active_server(self):
        """Return the currently selected NTP server hostname."""
        custom = self.custom_server_var.get().strip()
        if custom:
            return custom
        return self._selected_server.get()

    def _on_server_changed(self, event=None):
        """Clear custom entry when a preset is selected and update label."""
        self.custom_server_var.set("")
        self._update_active_server_label()

    def _on_custom_server_changed(self, event=None):
        """Update label when custom server text changes."""
        self._update_active_server_label()

    def _update_active_server_label(self):
        server = self._get_active_server()
        self.server_label.config(text=f"{server}:123")

    def _do_sync(self):
        """Try the selected server first, then fall back to all others."""
        primary = self._get_active_server()
        
        # Try primary server first
        t = get_ntp_time(server=primary)
        if t is not None:
            self.frame.after(0, lambda: self._on_sync_complete(t, primary))
            return
        
        # Primary failed – update status and try fallbacks
        self.frame.after(0, lambda: self.status_indicator.config(
            text=f"⚠️ {primary} failed, trying alternatives...",
            bootstyle="inverse-warning"
        ))
        
        # Build fallback list (all known servers except the one we already tried)
        fallbacks = [s for s in _FALLBACK_SERVERS if s != primary]
        
        for srv in fallbacks:
            t = get_ntp_time(server=srv)
            if t is not None:
                self.frame.after(0, lambda ts=t, s=srv: self._on_sync_complete(ts, s, fallback=True))
                return
        
        # All servers failed
        self.frame.after(0, lambda: self._on_sync_complete(None, primary))

    def _on_sync_complete(self, ntp_timestamp, server_used=None, fallback=False):
        self._syncing = False
        self.sync_btn.config(state=tk.NORMAL)

        if ntp_timestamp is not None:
            ntp_dt = datetime.fromtimestamp(ntp_timestamp, tz=timezone.utc)
            local_dt = datetime.now(timezone.utc)
            offset_ms = (ntp_dt - local_dt).total_seconds() * 1000

            self.ntp_time_label.config(
                text=ntp_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
                bootstyle="inverse-success"
            )
            self.offset_label.config(
                text=f"{offset_ms:+.2f} ms",
                bootstyle="inverse-success" if abs(offset_ms) < 1000 else "inverse-danger"
            )
            self.last_sync_label.config(
                text=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            
            if fallback and server_used:
                status_msg = f"✅ Synced via {server_used} (fallback)"
                # Update active server label to show which server actually worked
                self.server_label.config(text=f"{server_used}:123")
            else:
                status_msg = "✅ Synchronized successfully"
            self.status_indicator.config(text=status_msg, bootstyle="inverse-success")

            # Update encryption service if available
            if hasattr(self.app, 'encryption_service'):
                self.app.encryption_service.update_ntp_time(ntp_timestamp)
        else:
            self.ntp_time_label.config(text="Sync Failed", bootstyle="inverse-danger")
            self.offset_label.config(text="--", bootstyle="inverse-secondary")
            tried = server_used or "unknown"
            self.status_indicator.config(
                text=f"❌ All NTP servers unreachable (tried {len(_FALLBACK_SERVERS)} servers)",
                bootstyle="inverse-danger"
            )
