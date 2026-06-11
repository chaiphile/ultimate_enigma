#!/usr/bin/env python3
"""Launch the application with logging configured."""

import sys
import os

# PyInstaller DLL path resolution for liboqs
if getattr(sys, 'frozen', False):
    _base = sys._MEIPASS
    if hasattr(os, 'add_dll_directory'):
        os.add_dll_directory(_base)
    os.environ['PATH'] = _base + os.pathsep + os.environ.get('PATH', '')

import logging
import ttkbootstrap as ttk  # <-- Use ttkbootstrap
from ttkbootstrap.constants import *
from app import EnigmaApp

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        filename='enigma.log',
        filemode='a'
    )
    # Console shows WARNING+ but NTP module gets INFO for diagnostics
    console = logging.StreamHandler()
    console.setLevel(logging.WARNING)
    logging.getLogger('').addHandler(console)

    # Ensure NTP client logs are visible at INFO level in the log file
    logging.getLogger('ntp_client').setLevel(logging.INFO)

    # Create themed window with a modern dark style
    root = ttk.Window(themename="darkly")   # or "superhero", "cyborg", "vapor"...
    root.title("Ultimate Enigma Messenger")
    app = EnigmaApp(root)
    root.mainloop()