"""Filesystem locations used by NetSentinel.

Program files (read-only when packaged) live under ``app_root()``.
User data (database, logs, settings, secrets) lives under ``data_dir()``:
  Windows : %LOCALAPPDATA%\\NetSentinel
  Other   : ~/.netsentinel   (development / testing only)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

_DATA_DIR_OVERRIDE: Path | None = None


def app_root() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)  # PyInstaller bundle
    return Path(__file__).resolve().parent.parent


def set_data_dir(path: str | os.PathLike) -> None:
    """Override the data directory (used by tests and --data-dir)."""
    global _DATA_DIR_OVERRIDE
    _DATA_DIR_OVERRIDE = Path(path)
    _DATA_DIR_OVERRIDE.mkdir(parents=True, exist_ok=True)


def data_dir() -> Path:
    if _DATA_DIR_OVERRIDE is not None:
        return _DATA_DIR_OVERRIDE
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        p = base / "NetSentinel"
    else:
        p = Path.home() / ".netsentinel"
    p.mkdir(parents=True, exist_ok=True)
    return p


def user_config_path() -> Path:
    return data_dir() / "settings.json"


def database_path() -> Path:
    return data_dir() / "netsentinel.db"


def log_dir() -> Path:
    p = data_dir() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def reports_dir() -> Path:
    p = data_dir() / "reports"
    p.mkdir(parents=True, exist_ok=True)
    return p


def asset_path(name: str) -> Path:
    return app_root() / "assets" / name
