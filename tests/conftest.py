"""Pytest configuration – ensure project root is importable."""

import sys
from pathlib import Path

import pytest

# Add the project root to sys.path so that modules like crypto, database, etc. are importable
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Isolated database using temp directory for each test."""
    import database
    db_path = tmp_path / "test_enigma.db"
    monkeypatch.setattr(database, "DB_PATH", db_path)
    database.init_db()
    yield db_path
