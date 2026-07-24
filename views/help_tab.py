"""Help tab – full user usage guidance documentation with Farsi translation."""

import tkinter as tk
import ttkbootstrap as ttk
import webbrowser
from views.utils import ToolTip


_GUIDE_SECTIONS = [
    {
        "title": "🚀 Getting Started",
        "steps": [
            ("1.Install and run", "python main.py"),
            ("2.Set master password", "At least 16 characters including uppercase, lowercase, numbers and symbols"),
            ("3.Generating keys", "4096-bit RSA key and 256-bit shared key are automatically generated"),
            ("4.TOTP setting", "The app displays a QR code — scan with Google Authenticator"),
            ("5.Set name", "Go to Friends tab → Set My Name and enter your name"),
        ],
    },
    {
        "title": "👥 Management of friends — Friends",
        "steps": [
            ("add friend", "Go to the Friends tab and click Add Friend"),
            ("", "Enter your friend's name, RSA public key, and X25519 key"),
            ("edit friend", "Right click on the friend's name → Edit"),
            ("delete friend", "Right click on the friend's name → Delete"),
            ("Set your name", "Click the Set My Name button"),
            ("ECDH key exchange", "Friends → Right click → Exchange Keys"),
            ("Manage PQC keys", "Friends → Right click → PQC Key Exchange"),
        ],
    },
    {
        "title": "✉️ Send an encrypted message — Encrypt & Send",
        "steps": [
            ("1.Choose a friend", "Select the desired friend from the drop-down list"),
            ("2.Write a message", "Write the text of the message in the input box"),
            ("3.Choose an expiration time", "Self-Destruct: 5 minutes, 10 minutes, 1 hour or as desired"),
            ("4.encryption", "Click the Encrypt button"),
            ("5.send", "Auto-encrypted text is copied to the clipboard — send to a friend"),
        ],
    },
    {
        "title": "📥 Decrypt & Receive",
        "steps": [
            ("1.Copy message", "Copy the encrypted text from your friend"),
            ("2.paste", "Paste the text in the input box of the Decrypt & Receive tab"),
            ("3.decoding", "Click the Decrypt button"),
            ("4.view", "The original text and sender information will be displayed"),
        ],
    },
    {
        "title": "🔐 file encryption — File Encryption",
        "steps": [
            ("Password encryption", "Select File → Enter Password → Encrypt"),
            ("Decrypt with password", "Select Encrypted File → Enter Password → Decrypt"),
            ("Encryption for a friend", "Choose Friend → Choose File → Encrypt for Friend"),
            ("Decode for friend", "Choose File → Decrypt from Friend"),
        ],
    },
    {
        "title": "🔗 Shared key and ECDH - Shared Secret",
        "steps": [
            ("Show the shared key", "See your 256-bit shared key in the Shared Secret tab"),
            ("Copy the key", "Press the Copy button (after 30 seconds it will be automatically deleted)"),
            ("ECDH exchange", "Exchange keys with your friends to create a secure channel"),
        ],
    },
    {
        "title": "🔗 Trust Chain",
        "steps": [
            ("Issuance of certificate", "Issue trust certificates to your friends"),
            ("Import the certificate", "Enter the certificate received from friends"),
            ("Confidence levels", "NONE → BASIC → VERIFIED → TRUSTED"),
            ("Certificate revocation", "You can revoke the issued certificate"),
        ],
    },
    {
        "title": "🕐 NTP synchronization — Time Sync",
        "steps": [
            ("Automatic synchronization", "NTP syncs automatically after startup"),
            ("Manual synchronization", "Click the Sync Now button on the NTP tab"),
            ("Validation", "View sync status and time difference"),
        ],
    },
    {
        "title": "🔒 Security & Lock — Security & Lock",
        "steps": [
            ("Emergency lock", "Press the EMERGENCY LOCK button — all keys will be erased"),
            ("Unlock", "Enter master password + TOTP"),
            ("Password required", "Click the Set Duress Password button on the About tab"),
            ("", "If forced, fake data will be displayed with this password"),
            ("Change password", "Click the Change Master Password button on the About tab"),
        ],
    },
    {
        "title": "💾 Backup — Backup & Restore",
        "steps": [
            ("Issue backup", "About → Export Backup → Enter password → Select backup path"),
            ("Import backup", "Choose About → Import Backup → backup file"),
            ("attention", "Backup includes all keys, friends and settings"),
            ("warning", "Importing a backup replaces all current data"),
        ],
    },
    {
        "title": "❓ Frequently asked questions - FAQ",
        "steps": [
            ("How do I send a message?", "Encrypt & Send → Select a friend → Write the text → Encrypt"),
            ("How do I read a message?", "Decrypt & Receive → Paste the ciphertext → Decrypt"),
            ("I forgot the password", "Use Recovery on the lock screen"),
            ("What is TOTP?", "One-time password to unlock the app, required after emergency lock"),
            ("Is internet required?", "No, the app works completely offline.NTP is optional"),
            ("How do I make a backup?", "About ← Export Backup"),
            ("How do I add friends?", "Friends ← Add Friend"),
        ],
    },
]


class HelpTab:
    def __init__(self, parent: tk.Widget) -> None:
        self.frame = ttk.Frame(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        try:
            style = ttk.Style()
            canvas_bg = style.colors.bg
        except Exception:
            canvas_bg = "#2b2b2b"

        canvas_frame = ttk.Frame(self.frame)
        canvas_frame.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(canvas_frame, highlightthickness=0, bg=canvas_bg)
        scrollbar = ttk.Scrollbar(canvas_frame, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.LEFT, fill=tk.Y)
        canvas.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        inner = ttk.Frame(canvas, padding=30)
        canvas.create_window((0, 0), window=inner, anchor="nw")

        def _configure_inner(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(1, width=canvas.winfo_width())

        inner.bind("<Configure>", _configure_inner)

        # Header
        ttk.Label(inner, text="📚 User Guide",
                  font=("Segoe UI", 18, "bold"),
                  bootstyle="inverse-primary",
                  anchor="e").pack(pady=(0, 5), fill=tk.X)
        ttk.Label(inner, text="Complete guide to using the Ultimate Enigma Messenger app",
                  font=("Segoe UI", 10),
                  bootstyle="inverse-secondary",
                  anchor="e").pack(pady=(0, 25), fill=tk.X)

        for section in _GUIDE_SECTIONS:
            sep = ttk.Separator(inner, orient="horizontal")
            sep.pack(fill=tk.X, pady=(10, 10))

            sec = ttk.LabelFrame(inner, text=section["title"],
                                 bootstyle="info", padding=15)
            sec.pack(fill=tk.X, pady=(0, 8))

            for label, desc in section["steps"]:
                row = ttk.Frame(sec)
                row.pack(fill=tk.X, pady=3)

                if label:
                    ttk.Label(row, text=label,
                              font=("Segoe UI", 10, "bold"),
                              bootstyle="inverse-primary",
                              anchor="e", width=40).pack(side=tk.RIGHT)
                if desc:
                    ttk.Label(row, text=desc,
                              font=("Segoe UI", 9),
                              bootstyle="inverse-secondary",
                              anchor="e", justify="right",
                              wraplength=500).pack(side=tk.RIGHT, padx=(5, 0))

        # Footer
        sep_end = ttk.Separator(inner, orient="horizontal")
        sep_end.pack(fill=tk.X, pady=(20, 10))

        link_frame = ttk.Frame(inner)
        link_frame.pack(pady=(0, 20))

        def _open_docs():
            webbrowser.open("https://github.com/chaiphile/ultimate_enigma/tree/main/docs")

        docs_btn = ttk.Button(link_frame, text="Documentation",
                              command=_open_docs,
                              bootstyle="info-link")
        docs_btn.pack(side=tk.RIGHT, padx=5)
        ToolTip(docs_btn, "Open the complete application documentation in the browser")

        def _open_repo():
            webbrowser.open("https://github.com/chaiphile/ultimate_enigma")

        repo_btn = ttk.Button(link_frame, text="GitHub repository",
                              command=_open_repo,
                              bootstyle="info-link")
        repo_btn.pack(side=tk.RIGHT, padx=5)
        ToolTip(repo_btn, "Open the source code repository on GitHub")

        ttk.Label(link_frame, text="Useful resources:",
                  font=("Segoe UI", 9, "bold"),
                  bootstyle="inverse-primary").pack(side=tk.RIGHT, padx=(10, 0))

        # Mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        self.frame.bind("<Destroy>", lambda e: canvas.unbind_all("<MouseWheel>"))
