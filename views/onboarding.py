"""First-run onboarding welcome dialog for Ultimate Enigma Messenger."""

import logging
import tkinter as tk
from pathlib import Path
import ttkbootstrap as ttk

import database
from views.utils import center_over_parent

logger = logging.getLogger(__name__)

ONBOARDING_DELAY_MS = 600
ONBOARDING_MARKER = "onboarding_seen"
ONBOARDING_WINDOW_WIDTH = 560
ONBOARDING_WINDOW_HEIGHT = 470
ONBOARDING_PADDING = 24
ONBOARDING_BODY_WRAP = 470

_FONT_TITLE = ("Segoe UI", 16, "bold")
_FONT_STEP = ("Segoe UI", 11, "bold")
_FONT_BODY = ("Segoe UI", 10)
_FONT_BUTTON = ("Segoe UI", 9, "bold")
_FONT_TAB = ("Segoe UI", 9, "bold")

_STEPS = [
    {
        "title": "🔑 Your master password",
        "body": (
            "Your identity is protected by a master password you created "
            "during setup. Keep it long, unique, and stored somewhere safe. "
            "You will need it — together with your TOTP code — to unlock the "
            "app after an emergency lock."
        ),
        "tab": None,
    },
    {
        "title": "👥 Add friends & exchange keys",
        "body": (
            "Open the Friends tab, add a contact, and complete a key exchange. "
            "A proper exchange (RSA + X25519, optionally post-quantum) must be "
            "done before you can send that friend encrypted messages."
        ),
        "tab": "Friends",
    },
    {
        "title": "✉️ Send encrypted messages",
        "body": (
            "In the Encrypt & Send tab, choose a friend, type your message, "
            "pick how long it should live, and press Encrypt. The ciphertext "
            "is copied to your clipboard — paste it to your friend through "
            "whatever channel you like."
        ),
        "tab": "Encrypt",
    },
    {
        "title": "🔗 Build a trust chain",
        "body": (
            "The Trust Chain tab lets you issue and verify certificates for "
            "contacts, moving them from NONE to BASIC, VERIFIED, and TRUSTED. "
            "Always verify fingerprints out-of-band before trusting anyone."
        ),
        "tab": "Trust",
    },
    {
        "title": "🛡️ Security tips",
        "body": (
            "Use EMERGENCY LOCK (Ctrl+Shift+L) to wipe keys instantly, sync "
            "your clock from the Time Sync tab, and export a backup from the "
            "About tab. Set a duress password so a decoy profile appears if "
            "you are ever forced to unlock."
        ),
        "tab": None,
    },
]


def _marker_path() -> Path:
    try:
        return database.DB_PATH.parent / ONBOARDING_MARKER
    except Exception:
        return Path.home() / ".ultimate_enigma" / ONBOARDING_MARKER


def _has_seen() -> bool:
    try:
        return _marker_path().exists()
    except Exception:
        logger.debug("Could not read onboarding marker", exc_info=True)
        return False


def onboarding_seen() -> bool:
    return _has_seen()


def _mark_seen() -> None:
    try:
        path = _marker_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("1", encoding="utf-8")
    except Exception:
        logger.debug("Could not persist onboarding marker", exc_info=True)


class OnboardingDialog:
    def __init__(self, root: tk.Misc, notebook: ttk.Notebook,
                 bg: str, fg: str, accent: str, secondary: str, dark: str) -> None:
        self.root = root
        self.notebook = notebook
        self.bg = bg
        self.fg = fg
        self.accent = accent
        self.secondary = secondary
        self.dark = dark
        self._index = 0
        self._dont_show = tk.BooleanVar(value=False)
        self._closing = False
        self._build_ui()

    def _build_ui(self) -> None:
        style = ttk.Style()
        style.configure("OnboardingTitle.TLabel", font=_FONT_TITLE, foreground=self.accent)
        style.configure("OnboardingBody.TLabel", font=_FONT_BODY, foreground=self.fg)
        style.configure("OnboardingStep.TLabel", font=_FONT_STEP, foreground=self.secondary)
        style.configure(
            "OnboardingAccent.Horizontal.TProgressbar",
            troughcolor=self.secondary,
            background=self.accent,
            bordercolor=self.accent,
            lightcolor=self.accent,
            darkcolor=self.accent,
        )

        dialog = ttk.Toplevel(self.root, bootstyle="dark")
        dialog.title("Welcome to Ultimate Enigma Messenger")
        dialog.geometry(f"{ONBOARDING_WINDOW_WIDTH}x{ONBOARDING_WINDOW_HEIGHT}")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.protocol("WM_DELETE_WINDOW", self._close)
        self._dialog = dialog

        container = ttk.Frame(dialog, padding=ONBOARDING_PADDING)
        container.pack(fill=tk.BOTH, expand=True)

        self._title_label = ttk.Label(
            container, text="", style="OnboardingTitle.TLabel", anchor="w"
        )
        self._title_label.pack(fill=tk.X, pady=(0, 6))

        self._step_label = ttk.Label(
            container, text="", style="OnboardingStep.TLabel", anchor="w"
        )
        self._step_label.pack(fill=tk.X, pady=(0, 8))

        self._progress = ttk.Progressbar(
            container, orient="horizontal",
            style="OnboardingAccent.Horizontal.TProgressbar", length=200
        )
        self._progress.pack(fill=tk.X, pady=(0, 12))

        self._body_label = ttk.Label(
            container, text="", style="OnboardingBody.TLabel",
            anchor="w", justify="left", wraplength=ONBOARDING_BODY_WRAP
        )
        self._body_label.pack(fill=tk.X, pady=(0, 12))

        self._tab_button = ttk.Button(
            container, text="", command=self._jump_to_step_tab,
            bootstyle="primary-outline", font=_FONT_TAB
        )
        self._tab_button.pack(anchor="w", pady=(0, 12))

        self._dont_show_check = ttk.Checkbutton(
            container, text="Don't show this welcome again",
            variable=self._dont_show, bootstyle="secondary"
        )
        self._dont_show_check.pack(anchor="w", pady=(0, 12))

        button_bar = ttk.Frame(container)
        button_bar.pack(fill=tk.X, side=tk.BOTTOM)

        self._skip_button = ttk.Button(
            button_bar, text="Skip", command=self._close,
            bootstyle="secondary-outline", font=_FONT_BUTTON
        )
        self._skip_button.pack(side=tk.LEFT)

        self._back_button = ttk.Button(
            button_bar, text="← Back", command=self._back,
            bootstyle="secondary-outline", font=_FONT_BUTTON
        )
        self._back_button.pack(side=tk.RIGHT, padx=(0, 8))

        self._next_button = ttk.Button(
            button_bar, text="Next →", command=self._next,
            bootstyle="primary", font=_FONT_BUTTON
        )
        self._next_button.pack(side=tk.RIGHT)

        dialog.bind("<Escape>", lambda e: self._close())
        dialog.bind("<Return>", lambda e: self._advance())
        dialog.bind("<KP_Enter>", lambda e: self._advance())

        try:
            dialog.grab_set()
        except Exception as exc:
            logger.debug("Could not set modal grab on onboarding: %s", exc)

        center_over_parent(dialog, self.root)
        self._render()
        try:
            dialog.focus_set()
        except Exception:
            pass

    def _render(self) -> None:
        step = _STEPS[self._index]
        self._title_label.configure(text=step["title"])
        self._body_label.configure(text=step["body"])
        self._step_label.configure(
            text=f"Step {self._index + 1} of {len(_STEPS)}"
        )
        self._progress.configure(maximum=len(_STEPS) - 1, value=self._index)
        last = self._index == len(_STEPS) - 1
        self._next_button.configure(text="Done ✓" if last else "Next →")
        self._back_button.configure(state="disabled" if self._index == 0 else "normal")
        if step["tab"]:
            self._tab_button.configure(text=f"Go to the {step['tab']} tab", state="normal")
        else:
            self._tab_button.configure(text="", state="disabled")

    def _advance(self) -> None:
        if self._index < len(_STEPS) - 1:
            self._next()
        else:
            self._finish()

    def _next(self) -> None:
        self._index += 1
        self._render()

    def _back(self) -> None:
        if self._index > 0:
            self._index -= 1
            self._render()

    def _finish(self) -> None:
        self._dont_show.set(True)
        self._close()

    def _jump_to_step_tab(self) -> None:
        keyword = _STEPS[self._index].get("tab")
        if not keyword:
            return
        try:
            for i in range(self.notebook.index("end")):
                if keyword.lower() in self.notebook.tab(i, "text").lower():
                    self.notebook.select(i)
                    return
        except Exception as exc:
            logger.debug("Could not jump to tab '%s': %s", keyword, exc)

    def _close(self) -> None:
        if self._closing:
            return
        self._closing = True
        if self._dont_show.get():
            _mark_seen()
        try:
            self._dialog.grab_release()
        except Exception:
            pass
        try:
            self._dialog.destroy()
        except Exception:
            pass


def show_onboarding(root: tk.Misc, notebook: ttk.Notebook,
                    bg: str, fg: str, accent: str, secondary: str, dark: str) -> None:
    if _has_seen():
        return
    try:
        OnboardingDialog(root, notebook, bg, fg, accent, secondary, dark)
    except Exception as exc:
        logger.debug("Could not show onboarding dialog: %s", exc)
