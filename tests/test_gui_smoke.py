"""GUI smoke test: builds the main window, opens every page and dialog, refreshes them.

Uses the real CustomTkinter when available (Windows); otherwise a stub toolkit so the
page logic still runs in headless environments."""
import importlib.util
import os
import sys
import time

import pytest


def _real_tk_available() -> bool:
    if importlib.util.find_spec("customtkinter") is None or importlib.util.find_spec("tkinter") is None:
        return False
    try:
        import tkinter
        r = tkinter.Tk()
        r.destroy()
        return True
    except Exception:
        return False


@pytest.fixture(scope="module")
def app(tmp_path_factory):
    if not _real_tk_available():
        from tests import _tk_stub
        _tk_stub.install()
    for m in [m for m in sys.modules if m.startswith("gui")]:
        del sys.modules[m]
    from core.config import Config
    from gui.app import MainWindow
    cfg = Config(tmp_path_factory.mktemp("cfg") / "settings.json")
    cfg.set("monitoring.connection_interval_sec", 0.5)
    w = MainWindow(cfg)
    try:
        w.withdraw()
    except Exception:
        pass
    time.sleep(1.5)
    yield w
    w.on_close()


def test_every_page_builds_and_refreshes(app):
    from gui.app import NAV
    for name, _icon in NAV:
        app.show(name)
        assert app.current == name, f"page {name} failed to open"
        for _ in range(2):
            app._tick()
            time.sleep(0.2)


def test_tables_and_dialogs(app):
    from gui.components.dialogs import IPDialog, ProcessDialog
    ProcessDialog(app, os.getpid())
    IPDialog(app, "198.51.100.1")
    app.show("Live Network")
    page = app.pages["Live Network"]
    page.refresh()
    if page.table._rows:
        iid = next(iter(page.table._rows))
        page._select(iid)
        page.table.sort_by("app")
        page.table.sort_by("app")
    app.show("Applications")
    ap = app.pages["Applications"]
    if ap.table._rows:
        ap._select(next(iter(ap.table._rows)))
