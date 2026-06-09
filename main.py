#!/usr/bin/env python3
"""Launch the application with logging configured."""

import logging
import ttkbootstrap as ttk  # <-- Use ttkbootstrap
from ttkbootstrap.constants import *
from app import EnigmaApp

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.WARNING,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        filename='enigma.log',
        filemode='a'
    )
    # Also output to console for debugging (optional)
    console = logging.StreamHandler()
    console.setLevel(logging.WARNING)
    logging.getLogger('').addHandler(console)

    # Create themed window with a modern dark style
    root = ttk.Window(themename="darkly")   # or "superhero", "cyborg", "vapor"...
    root.title("Ultimate Enigma Messenger")
    app = EnigmaApp(root)
    root.mainloop()