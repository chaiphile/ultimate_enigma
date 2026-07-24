"""Help tab – full user usage guidance documentation with Farsi translation."""

import tkinter as tk
import ttkbootstrap as ttk
import webbrowser
from views.utils import ToolTip


_GUIDE_SECTIONS = [
    {
        "title": "🚀 شروع کار — Getting Started",
        "steps": [
            ("۱. نصب و اجرا", "python main.py"),
            ("۲. تنظیم رمز عبور اصلی", "حداقل ۱۶ کاراکتر شامل حروف بزرگ، کوچک، عدد و نماد"),
            ("۳. تولید کلیدها", "کلید RSA 4096 بیتی و کلید اشتراکی ۲۵۶ بیتی خودکار تولید می‌شوند"),
            ("۴. تنظیم TOTP", "برنامه QR کد نمایش می‌دهد — با Google Authenticator اسکن کنید"),
            ("۵. تنظیم نام", "به برگه Friends → Set My Name بروید و نام خود را وارد کنید"),
        ],
    },
    {
        "title": "👥 مدیریت دوستان — Friends",
        "steps": [
            ("افزودن دوست", "به برگه Friends بروید و Add Friend را کلیک کنید"),
            ("", "نام، کلید عمومی RSA و کلید X25519 دوست خود را وارد کنید"),
            ("ویرایش دوست", "روی نام دوست راست کلیک کنید → Edit"),
            ("حذف دوست", "روی نام دوست راست کلیک کنید → Delete"),
            ("تنظیم نام خود", "روی دکمه Set My Name کلیک کنید"),
            ("تبادل کلید ECDH", "دوستان → کلیک راست → Exchange Keys"),
            ("مدیریت کلیدهای PQC", "دوستان → کلیک راست → PQC Key Exchange"),
        ],
    },
    {
        "title": "✉️ ارسال پیام رمزنگاری‌شده — Encrypt & Send",
        "steps": [
            ("۱. انتخاب دوست", "از لیست کشویی دوست مورد نظر را انتخاب کنید"),
            ("۲. نوشتن پیام", "متن پیام را در کادر ورودی بنویسید"),
            ("۳. انتخاب زمان انقضا", "Self-Destruct: ۵ دقیقه، ۱۰ دقیقه، ۱ ساعت یا دلخواه"),
            ("۴. رمزنگاری", "دکمه Encrypt را بزنید"),
            ("۵. ارسال", "متن رمز شده خودکار در کلیپ‌بورد کپی می‌شود — برای دوست خود بفرستید"),
        ],
    },
    {
        "title": "📥 دریافت و رمزگشایی — Decrypt & Receive",
        "steps": [
            ("۱. کپی پیام", "متن رمز شده را از دوست خود کپی کنید"),
            ("۲. چسباندن", "متن را در کادر ورودی برگه Decrypt & Receive بچسبانید"),
            ("۳. رمزگشایی", "دکمه Decrypt را بزنید"),
            ("۴. مشاهده", "متن اصلی و اطلاعات فرستنده نمایش داده می‌شود"),
        ],
    },
    {
        "title": "🔐 رمزنگاری فایل — File Encryption",
        "steps": [
            ("رمزنگاری با رمز عبور", "فایل را انتخاب کنید → رمز عبور وارد کنید → Encrypt"),
            ("رمزگشایی با رمز عبور", "فایل رمز شده را انتخاب کنید → رمز عبور وارد کنید → Decrypt"),
            ("رمزنگاری برای دوست", "دوست را انتخاب کنید → فایل را انتخاب کنید → Encrypt for Friend"),
            ("رمزگشایی برای دوست", "فایل را انتخاب کنید → Decrypt from Friend"),
        ],
    },
    {
        "title": "🔗 کلید اشتراکی و ECDH — Shared Secret",
        "steps": [
            ("نمایش کلید اشتراکی", "کلید اشتراکی ۲۵۶ بیتی خود را در برگه Shared Secret ببینید"),
            ("کپی کلید", "دکمه Copy را بزنید (پس از ۳۰ ثانیه خودکار پاک می‌شود)"),
            ("تبادل ECDH", "با دوستان خود تبادل کلید انجام دهید تا کانال امن ایجاد شود"),
        ],
    },
    {
        "title": "🔗 زنجیره اعتماد — Trust Chain",
        "steps": [
            ("صدور گواهی", "برای دوستان خود گواهی اعتماد صادر کنید"),
            ("وارد کردن گواهی", "گواهی دریافتی از دوستان را وارد کنید"),
            ("سطوح اعتماد", "NONE → BASIC → VERIFIED → TRUSTED"),
            ("ابطال گواهی", "گواهی صادر شده را می‌توانید ابطال کنید"),
        ],
    },
    {
        "title": "🕐 همگام‌سازی NTP — Time Sync",
        "steps": [
            ("همگام‌سازی خودکار", "NTP به طور خودکار پس از راه‌اندازی همگام می‌شود"),
            ("همگام‌سازی دستی", "دکمه Sync Now را در برگه NTP بزنید"),
            ("اعتبارسنجی", "وضعیت همگام‌سازی و اختلاف زمانی را مشاهده کنید"),
        ],
    },
    {
        "title": "🔒 امنیت و قفل — Security & Lock",
        "steps": [
            ("قفل اضطراری", "دکمه EMERGENCY LOCK را بزنید — همه کلیدها پاک می‌شوند"),
            ("باز کردن قفل", "رمز عبور اصلی + TOTP را وارد کنید"),
            ("رمز عبور اجباری", "در برگه About دکمه Set Duress Password را بزنید"),
            ("", "در صورت اجبار، با این رمز عبور داده‌های جعلی نمایش داده می‌شود"),
            ("تغییر رمز عبور", "در برگه About دکمه Change Master Password را بزنید"),
        ],
    },
    {
        "title": "💾 پشتیبان‌گیری — Backup & Restore",
        "steps": [
            ("صدور پشتیبان", "About → Export Backup → رمز عبور را وارد کنید → مسیر ذخیره را انتخاب کنید"),
            ("وارد کردن پشتیبان", "About → Import Backup → فایل پشتیبان را انتخاب کنید"),
            ("توجه", "پشتیبان شامل همه کلیدها، دوستان و تنظیمات است"),
            ("هشدار", "وارد کردن پشتیبان همه داده‌های فعلی را جایگزین می‌کند"),
        ],
    },
    {
        "title": "❓ پرسش‌های متداول — FAQ",
        "steps": [
            ("چگونه یک پیام بفرستم؟", "Encrypt & Send ← دوست را انتخاب کنید ← متن را بنویسید ← Encrypt"),
            ("چگونه یک پیام را بخوانم؟", "Decrypt & Receive ← متن رمز را بچسبانید ← Decrypt"),
            ("رمز عبور را فراموش کرده‌ام", "از Recovery در صفحه قفل استفاده کنید"),
            ("TOTP چیست؟", "رمز یکبارمصرف برای باز کردن قفل برنامه، الزامی پس از قفل اضطراری"),
            ("آیا اینترنت نیاز است؟", "خیر، برنامه کاملاً آفلاین کار می‌کند. NTP اختیاری است"),
            ("پشتیبان‌گیری چطور انجام دهم؟", "About ← Export Backup"),
            ("چگونه دوست اضافه کنم؟", "Friends ← Add Friend"),
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
        ttk.Label(inner, text="📚 راهنمای کاربر — User Guide",
                  font=("Segoe UI", 18, "bold"),
                  bootstyle="inverse-primary",
                  anchor="e").pack(pady=(0, 5), fill=tk.X)
        ttk.Label(inner, text="راهنمای کامل استفاده از برنامه Ultimate Enigma Messenger",
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

        docs_btn = ttk.Button(link_frame, text="مستندات Docs",
                              command=_open_docs,
                              bootstyle="info-link")
        docs_btn.pack(side=tk.RIGHT, padx=5)
        ToolTip(docs_btn, "باز کردن مستندات کامل برنامه در مرورگر")

        def _open_repo():
            webbrowser.open("https://github.com/chaiphile/ultimate_enigma")

        repo_btn = ttk.Button(link_frame, text="مخزن GitHub",
                              command=_open_repo,
                              bootstyle="info-link")
        repo_btn.pack(side=tk.RIGHT, padx=5)
        ToolTip(repo_btn, "باز کردن مخزن کد منبع در گیت‌هاب")

        ttk.Label(link_frame, text="🔗 منابع مفید:",
                  font=("Segoe UI", 9, "bold"),
                  bootstyle="inverse-primary").pack(side=tk.RIGHT, padx=(10, 0))

        # Mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        self.frame.bind("<Destroy>", lambda e: canvas.unbind_all("<MouseWheel>"))
