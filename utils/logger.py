"""Central logging configuration (rotating file + console)."""
from __future__ import annotations

import logging
import logging.handlers
import sys

from utils.paths import log_dir

_CONFIGURED = False


def setup_logging(level: int = logging.INFO, console: bool = True) -> logging.Logger:
    global _CONFIGURED
    root = logging.getLogger()
    if _CONFIGURED:
        return root
    root.setLevel(level)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(threadName)s %(name)s: %(message)s")
    fh = logging.handlers.RotatingFileHandler(
        log_dir() / "netsentinel.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)
    if console and sys.stderr is not None:  # windowed PyInstaller builds have no stderr
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        root.addHandler(ch)
    _CONFIGURED = True
    return root
