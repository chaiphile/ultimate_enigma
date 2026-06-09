"""EnigmaApp – main application window, header, tabs orchestration."""

import tkinter as tk
from tkinter import messagebox
from pathlib import Path
from queue import Queue, Empty
import logging
import gc
import time
import threading
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

from visual_enigma import VisualEnigma
from key_manager import KeyStore, init_db
from utils import password_dialog
from services.encryption_service import EncryptionService
from services.file_service import FileService  # new service
from services.friends_service import FriendsService
from services.clipboard_service import ClipboardService
from encrypt_tab import EncryptTab
from decrypt_tab import DecryptTab
from friends_tab import FriendsTab
from secret_tab import SecretTab
from file_tab import FileTab
from about_tab import AboutTab
from ntp_tab import NtpTab
from ntp_client import get_ntp_time

logger = logging.getLogger(__name__)


class EnigmaApp:
    def __init__(self, root):
        self.root = root
        root.geometry("1100x750")
        root.minsize(900, 600)

        icon = tk.PhotoImage(width=1, height=1)
        root.iconphoto(True, icon)

        self.style = ttk.Style()
        self.bg = self.style.colors.bg
        self.fg = self.style.colors.fg
        self.accent = self.style.colors.primary
        self.secondary = self.style.colors.secondary
        self.dark = self.style.colors.dark

    # 1. ابتدا KeyStore و صف را بسازید
        self.ks = KeyStore()
        self.task_queue = Queue()
        self.process_queue()

        if not self._load_keys():
            root.destroy()
            return

    # 2. سپس سرویس‌ها را با ks موجود بسازید
        self.encryption_service = EncryptionService(self.ks)
        self.file_service = FileService(self.ks)
        self.friends_service = FriendsService(self.ks)
        self.clipboard_service = ClipboardService(root)

    # 3. حالا نخ NTP را راه‌اندازی کنید (encryption_service وجود دارد)
        self._ntp_thread = threading.Thread(target=self._ntp_sync_loop, daemon=True)
        self._ntp_thread.start()   # تایپو اصلاح شود

    # بقیه‌ی تنظیمات
        self.last_sent_b64 = ""
        self.vis_enigma = VisualEnigma()
        self.rotor_positions = [0, 0, 0]

        self._setup_header()
        self._setup_tabs()
        self._start_rotor_animation()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    # ------------------------------------------------------------------
    # Window close & queue processing
    # ------------------------------------------------------------------
    def on_close(self):
        self.clipboard_service.shutdown()
        self.ks.wipe()
        self.root.destroy()

    def _ntp_sync_loop(self):
        while True:
            t = get_ntp_time()
            if t is not None:
                self.encryption_service.update_ntp_time(t)
            else:
                self.encryption_service.update_ntp_time(None)

            time.sleep(1800)                    

    def process_queue(self):
        try:
            while True:
                task = self.task_queue.get_nowait()
                task()
        except Empty:
            pass
        self.root.after(100, self.process_queue)

    # ------------------------------------------------------------------
    # Key loading
    # ------------------------------------------------------------------
    def _load_keys(self) -> bool:
        first_run = not (Path.home() / ".ultimate_enigma" / "enigma.db").exists()
        if first_run:
            pw = password_dialog(self.root, "Set Master Password", confirm=True)
            if not pw:
                return False
            init_db(pw)
            if not self.ks.load(pw):
                messagebox.showerror("Error", "Failed to load new keys.")
                pw = None; gc.collect()
                return False
            pw = None; gc.collect()
            return True
        else:
            for _ in range(3):
                pw = password_dialog(self.root, "Unlock Private Key", confirm=False)
                if not pw:
                    return False
                if not self.ks.verify_password(pw):
                    messagebox.showerror("Wrong Password", "Incorrect password.")
                    continue
                if self.ks.load(pw):
                    pw = None; gc.collect()
                    return True
                else:
                    messagebox.showerror("Error", "Failed to load keys.")
                    return False
            messagebox.showerror("Access Denied", "Too many attempts.")
            return False

    # ------------------------------------------------------------------
    # Header & tab setup
    # ------------------------------------------------------------------
    def _setup_header(self):
        header = ttk.Frame(self.root, bootstyle="dark", height=80)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        ttk.Label(header, text="ULTIMATE ENIGMA MESSENGER",
                  font=("Segoe UI", 16, "bold"),
                  bootstyle="inverse-warning").pack(side=tk.LEFT, padx=20, pady=10)

        ttk.Label(header, text="Hybrid Encryption · AES‑GCM + RSA‑OAEP · Time‑based keys",
                  font=("Segoe UI", 8),
                  bootstyle="inverse-secondary").pack(side=tk.LEFT, padx=5)

        self.header_canvas = tk.Canvas(
            header,
            bg=self.style.colors.dark,
            height=70, width=210,
            highlightthickness=0
        )
        self.header_canvas.pack(side=tk.RIGHT, padx=10, pady=5)

    def _setup_tabs(self):
        notebook = ttk.Notebook(self.root, bootstyle="dark")
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.encrypt_tab = EncryptTab(notebook, self, self.encryption_service)
        notebook.add(self.encrypt_tab.frame, text="✉️ Encrypt & Send")

        self.decrypt_tab = DecryptTab(notebook, self)
        notebook.add(self.decrypt_tab.frame, text="📥 Decrypt & Receive")

        self.secret_tab = SecretTab(notebook, self)
        notebook.add(self.secret_tab.frame, text="🔗 Shared Secret")

        # Pass the file service to FileTab
        self.file_tab = FileTab(notebook, self, self.file_service)
        notebook.add(self.file_tab.frame, text="🔐 File Encryption")

        self.friends_tab = FriendsTab(notebook, self)
        notebook.add(self.friends_tab.frame, text="👥 Friends")

        self.ntp_tab = NtpTab(notebook, self)
        notebook.add(self.ntp_tab.frame, text="🕐 NTP")

        self.about_tab = AboutTab(notebook, self)
        notebook.add(self.about_tab.frame, text="ℹ️ About")

    # ------------------------------------------------------------------
    # Header rotor animation
    # ------------------------------------------------------------------
    def _start_rotor_animation(self):
        self._draw_header_rotors()
        self._animate_header_rotors()

    def _draw_header_rotors(self):
        self.header_canvas.delete("all")
        self.vis_enigma.draw_compact(self.header_canvas, self.rotor_positions)

    def _animate_header_rotors(self):
        self.rotor_positions[0] = (self.rotor_positions[0] + 0.5) % 26
        if self.rotor_positions[0] < 0.5:
            self.rotor_positions[1] = (self.rotor_positions[1] + 0.5) % 26
            if self.rotor_positions[1] < 0.5:
                self.rotor_positions[2] = (self.rotor_positions[2] + 0.5) % 26
        self._draw_header_rotors()
        self.root.after(200, self._animate_header_rotors)