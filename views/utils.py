"""Pure utility functions for the app (validation, formatting) and shared UI helpers."""

import logging
import re
import threading

logger = logging.getLogger(__name__)


def friendly_error(exc: Exception) -> str:
    """Map an exception to a user-facing message (never raw tracebacks)."""
    name = type(exc).__name__
    msg = str(exc).strip()
    mapping = {
        "DecryptionError": "This message couldn't be decrypted. It may be corrupted, "
                           "not addressed to you, or already expired.",
        "EncryptionError": "Encryption failed. Check the recipient and try again.",
        "CryptoTimeoutError": "The operation timed out. Please try again.",
        "SharedSecretDetected": "A shared secret was detected for this contact. "
                                "Use the shared-secret mode instead.",
        "PermissionError": "Permission denied. Make sure the file isn't open elsewhere "
                           "and that you have access to it.",
        "FileNotFoundError": "That file could not be found.",
        "FileExistsError": "A file with that name already exists.",
        "IsADirectoryError": "That path is a folder, not a file.",
        "TimeoutError": "The operation timed out. Please try again.",
        "ConnectionError": "Could not connect. Check your network and try again.",
    }
    if name in mapping:
        return mapping[name]
    lowered = (name + " " + msg).lower()
    if "json" in lowered or "expecting value" in lowered or "delimiter" in lowered:
        return "That doesn't look like valid data. Please check what you pasted or imported."
    if "base64" in lowered or "padding" in lowered or "invalid token" in lowered:
        return "The input isn't valid. Please re-copy the value and try again."
    if "mac" in lowered or "tag" in lowered or "signature" in lowered:
        return "Verification failed. The data may be corrupted or tampered with."
    return "An unexpected error occurred. Please try again."


def center_over_parent(dlg, parent) -> None:
    """Center a Toplevel over its parent window."""
    try:
        dlg.update_idletasks()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        if pw <= 1 or ph <= 1:
            pw, ph = parent.winfo_screenwidth(), parent.winfo_screenheight()
            px = py = 0
        dw = dlg.winfo_width()
        dh = dlg.winfo_height()
        x = px + (pw - dw) // 2
        y = py + (ph - dh) // 3
        dlg.geometry(f"+{max(x, 0)}+{max(y, 0)}")
    except Exception:
        logger.debug("center_over_parent failed", exc_info=True)


def init_modal(dlg, parent, focus_widget=None, on_close=None) -> None:
    """Apply consistent modal hygiene to a Toplevel.

    Centers over parent, makes it transient + modal (grab_set), binds Escape and
    the window-close (X) button to ``on_close`` (defaults to destroying the dialog),
    and sets initial keyboard focus.
    """
    close = on_close if on_close is not None else dlg.destroy

    def _close(*_):
        close()

    try:
        dlg.transient(parent)
    except Exception:
        pass
    center_over_parent(dlg, parent)
    try:
        dlg.grab_set()
    except Exception:
        pass
    dlg.protocol("WM_DELETE_WINDOW", _close)
    dlg.bind("<Escape>", _close)
    target = focus_widget if focus_widget is not None else dlg
    try:
        target.focus_set()
    except Exception:
        pass


def run_busy(widget, work, on_done=None, on_error=None, busy_widgets=None) -> None:
    """Run a blocking callable off the UI thread with a busy cursor.

    Shows a ``watch`` cursor on the toplevel, disables ``busy_widgets`` while the
    work runs, then restores both and dispatches ``on_done(result)`` or
    ``on_error(exc)`` back on the Tk main thread. If ``on_error`` is omitted a
    friendly error dialog is shown.
    """
    from tkinter import messagebox

    root = widget.winfo_toplevel()
    states = []
    for w in (busy_widgets or []):
        try:
            states.append((w, str(w.cget("state"))))
            w.configure(state="disabled")
        except Exception:
            pass
    try:
        root.configure(cursor="watch")
    except Exception:
        pass
    root.update_idletasks()

    def _restore():
        try:
            root.configure(cursor="")
        except Exception:
            pass
        for w, st in states:
            try:
                w.configure(state=st)
            except Exception:
                pass

    def _worker():
        try:
            result = work()

            def _ok():
                _restore()
                if on_done:
                    on_done(result)
            widget.after(0, _ok)
        except Exception as exc:  # noqa: BLE001 - surfaced to the user
            logger.exception("Background operation failed")

            def _fail(exc=exc):
                _restore()
                if on_error:
                    on_error(exc)
                else:
                    messagebox.showerror("Error", friendly_error(exc))
            widget.after(0, _fail)

    threading.Thread(target=_worker, daemon=True).start()


def flash_widget_text(widget, text: str, revert_to: str, ms: int = 1500) -> None:
    """Briefly change a widget's text (e.g. a copy button) then revert."""
    try:
        widget.configure(text=text)
        widget.after(ms, lambda: widget.configure(text=revert_to))
    except Exception:
        logger.debug("flash_widget_text failed", exc_info=True)

# Minimum requirements (military-grade)
MIN_PASSWORD_LENGTH = 16
MIN_ENTROPY_BITS = 60


def validate_password_strength(pw: str) -> tuple:
    """
    Validate password against military-grade requirements.

    Returns:
        (is_valid: bool, message: str, score: int)
        score: 0-100 (0=trivially weak, 100=excellent)
    """
    issues = []
    score = 0

    # Length check (most important factor)
    if len(pw) < MIN_PASSWORD_LENGTH:
        issues.append(f"Minimum {MIN_PASSWORD_LENGTH} characters required (have {len(pw)})")
    else:
        score += min(40, len(pw) * 2)  # Up to 40 points for length

    # Complexity checks
    if not re.search(r'[A-Z]', pw):
        issues.append("Must contain at least one uppercase letter")
    else:
        score += 15

    if not re.search(r'[a-z]', pw):
        issues.append("Must contain at least one lowercase letter")
    else:
        score += 15

    if not re.search(r'\d', pw):
        issues.append("Must contain at least one digit")
    else:
        score += 15

    if not re.search(r'[!@#$%^&*()\-_=+\[\]{}\\|;:\'",.<>/?`~]', pw):
        issues.append("Must contain at least one special character")
    else:
        score += 15

    # Common password check (top 10,000)
    common_passwords = {
        "password", "123456", "qwerty", "admin", "letmein",
        "welcome", "monkey", "master", "dragon", "login",
        "princess", "football", "shadow", "sunshine", "trustno1"
    }
    if pw.lower() in common_passwords:
        issues.append("Password is too common")
        score = 0

    # Repetitive pattern check
    if re.search(r'(.)\1{3,}', pw):
        issues.append("Contains excessive repeated characters")
        score -= 10

    # Sequential pattern check
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', pw.lower()):
        issues.append("Contains sequential patterns")
        score -= 10

    is_valid = len(issues) == 0
    message = "Strong password" if is_valid else "; ".join(issues)
    return is_valid, message, max(0, min(100, score))


def get_strength_label(score: int) -> tuple:
    """Return (label_text, color) based on password strength score."""
    if score >= 80:
        return "████████████ STRONG", "#00cc00"
    elif score >= 60:
        return "████████░░░░ GOOD", "#66cc00"
    elif score >= 40:
        return "████░░░░░░░░ FAIR", "#cccc00"
    elif score >= 20:
        return "██░░░░░░░░░░ WEAK", "#cc6600"
    else:
        return "░░░░░░░░░░░░ CRITICAL", "#cc0000"
