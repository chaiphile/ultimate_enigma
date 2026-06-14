"""Authentication UI callbacks interface and Tkinter implementation."""

from typing import Protocol, Optional, Any


class AuthUICallbacks(Protocol):
    """Interface for authentication UI callbacks."""
    
    def password_dialog(self, title: str, confirm: bool = False, **kwargs: Any) -> Optional[str]:
        """Show a password dialog and return the entered password or None if cancelled."""
        ...
    
    def show_error(self, title: str, message: str) -> None:
        """Show an error dialog."""
        ...
    
    def show_info(self, title: str, message: str) -> None:
        """Show an info dialog."""
        ...
    
    def show_warning(self, title: str, message: str) -> None:
        """Show a warning dialog."""
        ...


class TkinterAuthUI:
    """Tkinter-based authentication UI callbacks."""
    
    def __init__(self, root):
        self.root = root
    
    def password_dialog(self, title: str, confirm: bool = False, **kwargs: Any) -> Optional[str]:
        from views.dialogs import password_dialog
        return password_dialog(self.root, title, confirm=confirm, **kwargs)
    
    def show_error(self, title: str, message: str) -> None:
        from tkinter import messagebox
        messagebox.showerror(title, message)
    
    def show_info(self, title: str, message: str) -> None:
        from tkinter import messagebox
        messagebox.showinfo(title, message)
    
    def show_warning(self, title: str, message: str) -> None:
        from tkinter import messagebox
        messagebox.showwarning(title, message)
