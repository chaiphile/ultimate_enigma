"""Shared helper for submitting crypto operations with queue/thread fallback."""

import logging
import threading
from typing import Callable

logger = logging.getLogger(__name__)


def submit_crypto_task(
    crypto_queue,
    do_work: Callable,
    on_success: Callable,
    on_error: Callable,
    task_queue=None,
    frame=None,
    fallback_timeout: float = 30.0,
    error_map: dict = None,
    error_dialog: Callable = None,
):
    """Submit a crypto operation, using CryptoTaskQueue if available or a thread fallback.
    
    Args:
        crypto_queue: The CryptoTaskQueue instance (or None for fallback).
        do_work: Callable that performs the operation (runs in worker thread).
        on_success: Callback for success (runs on main thread).
        on_error: Callback for error (runs on main thread).
        task_queue: Queue for marshalling callbacks to main thread (legacy fallback).
        frame: Tkinter frame for .after() calls (legacy fallback).
        fallback_timeout: Timeout for the queue submission.
        error_map: Optional dict mapping exception types to (title, message) templates.
        error_dialog: Optional callable(exc) to show error dialogs. If provided,
                     overrides error_map and default error handling.
    """
    if crypto_queue is not None:
        crypto_queue.submit(
            do_work,
            on_success=on_success,
            on_error=on_error,
            priority=None,  # Caller should set via kwargs if needed
            timeout=fallback_timeout,
        )
    else:
        def _legacy_task():
            try:
                result = do_work()
                if frame is not None:
                    frame.after(0, lambda r=result: on_success(r))
                elif task_queue is not None:
                    task_queue.put(lambda r=result: on_success(r))
            except Exception as exc:
                logger.exception("Crypto operation failed")
                def _show_error(exc=exc):
                    if error_dialog is not None:
                        error_dialog(exc)
                    elif error_map and type(exc) in error_map:
                        title, msg = error_map[type(exc)]
                        from tkinter import messagebox
                        messagebox.showerror(title, msg or str(exc))
                    else:
                        from tkinter import messagebox
                        messagebox.showerror("Error", str(exc))
                if frame is not None:
                    frame.after(0, _show_error)
                elif task_queue is not None:
                    task_queue.put(_show_error)
                if on_error:
                    on_error(exc)

        threading.Thread(target=_legacy_task, daemon=True).start()