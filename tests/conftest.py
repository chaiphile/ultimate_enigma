"""Pytest configuration – ensure project root is importable."""

import sys
from pathlib import Path

# Add the project root to sys.path so that modules like crypto, database, etc. are importable
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
