"""NetSentinel — Windows privacy & network security monitor.

  python main.py                 launch the desktop app
  python main.py --headless -d 60 --report full
                                 monitor for 60 s without a GUI and export a report
  python main.py --check         print a Windows compatibility / capability report
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import time

from utils.paths import set_data_dir


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="NetSentinel", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--headless", action="store_true", help="run without GUI (console summary)")
    p.add_argument("-d", "--duration", type=float, default=30, help="headless run time in seconds")
    p.add_argument("--report", choices=["alerts", "connections", "privacy", "dns", "full"],
                   help="export a report when the headless run ends")
    p.add_argument("--format", choices=["csv", "json"], default="json")
    p.add_argument("--data-dir", help="alternate data directory (database, logs, settings)")
    p.add_argument("--check", action="store_true", help="print compatibility and capability report")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--no-auto-install", action="store_true",
                   help="do not install/upgrade missing or outdated packages automatically")
    p.add_argument("--with-optional", action="store_true",
                   help="also auto-install optional packages (scapy, maxminddb)")
    return p.parse_args(argv)


def _notify_gui_error(text: str) -> None:
    """When launched without a console (pythonw), show dependency problems in a message box."""
    if os.name == "nt" and sys.stderr is None:
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, text, "NetSentinel — setup problem", 0x10)
        except Exception:
            pass


def run_headless(args) -> int:
    from core.config import Config
    from core.monitor_service import MonitorService
    from core.reports import export_report
    from utils.helpers import fmt_bytes

    svc = MonitorService(Config())
    svc.start()
    t_end = time.time() + args.duration
    try:
        while time.time() < t_end:
            time.sleep(min(5, max(0.1, t_end - time.time())))
            o = svc.overview()
            print(f"[{time.strftime('%H:%M:%S')}] active={o['active']} external={o['external']} "
                  f"suspicious={o['suspicious']} alerts={o['alerts_total']} privacy_events={o['privacy_events']} "
                  f"iface_up={fmt_bytes(o['iface_sent'])} iface_down={fmt_bytes(o['iface_recv'])}", flush=True)
            while not svc.events.empty():
                topic, payload = svc.events.get_nowait()
                if topic == "alert":
                    print(f"  ALERT [{payload.severity}] {payload.title} — {payload.process_name} {payload.destination}")
                elif topic == "privacy":
                    print(f"  PRIVACY {payload.capability} {payload.event_type} {payload.display_name}")
    except KeyboardInterrupt:
        pass
    finally:
        svc.stop()
        print("\nCapabilities:")
        for c in svc.capabilities():
            print(f"  {c.name:34s} {c.status:12s} {c.detail}")
        if args.report:
            path = export_report(svc.db, args.report, args.format)
            print(f"\nReport written to {path}")
        svc.shutdown()
    return 0


def run_check() -> int:
    from core.config import Config
    from core.monitor_service import MonitorService
    from utils.permissions import ADMIN_FEATURES, compatibility_report
    rep = compatibility_report()
    for k, v in rep.items():
        if k != "warnings":
            print(f"{k:16s}: {v}")
    for w in rep["warnings"]:
        print("WARNING:", w)
    from utils.deps import check, problems
    d = check()
    print("\nPackages:")
    for k, v in d["installed"].items():
        print(f"  {k:16s} {v}")
    for k, v in d["optional"].items():
        print(f"  {k:16s} {v or 'not installed (optional)'}")
    for p in problems():
        print("PROBLEM:", p)
    svc = MonitorService(Config())
    print("\nCapabilities (before monitoring starts):")
    for c in svc.capabilities():
        print(f"  {c.name:34s} {c.status:12s} {c.detail}")
    print("\nFeatures that need Administrator rights:")
    for k, v in ADMIN_FEATURES.items():
        print(f"  - {k}: {v}")
    svc.shutdown()
    return 0


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.data_dir:
        set_data_dir(args.data_dir)
    from utils.logger import setup_logging
    setup_logging(logging.DEBUG if args.debug else logging.INFO, console=args.headless or args.check)
    if args.check:
        return run_check()
    if not getattr(sys, "frozen", False):   # packaged .exe bundles its own dependencies
        from utils.deps import ensure, problems
        if args.no_auto_install:
            probs = problems(include_gui=not args.headless)
        else:
            probs = ensure(include_gui=not args.headless, include_optional=args.with_optional,
                           echo=lambda m: print(m, file=sys.stderr, flush=True))
        if probs:
            print("\n".join(probs), file=sys.stderr)
            _notify_gui_error("\n".join(probs))
            if any(p.startswith(("Missing", "Python")) for p in probs):
                return 2
    if args.headless:
        return run_headless(args)
    from gui.app import run_gui
    return run_gui()


def _crash_report(exc: BaseException) -> None:
    """Never let NetSentinel vanish silently: log the traceback and show it to the user."""
    import traceback
    text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    try:
        from utils.paths import log_dir
        path = log_dir() / "crash.log"
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"\n===== {time.ctime()} =====\n{text}")
        where = f"\n\nSaved to: {path}"
    except Exception:
        where = ""
    try:
        print(text, file=sys.stderr)
    except Exception:
        pass
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, text[-1800:] + where, "NetSentinel failed to start", 0x10)
        except Exception:
            pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as e:   # noqa: BLE001
        _crash_report(e)
        sys.exit(1)
