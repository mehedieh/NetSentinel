"""Privilege and platform checks. NetSentinel runs with least privilege by default
and only asks for elevation when the user explicitly requests an admin-only feature."""
from __future__ import annotations

import logging
import os
import platform
import sys

log = logging.getLogger(__name__)

IS_WINDOWS = os.name == "nt"

ADMIN_FEATURES = {
    "Per-connection TCP byte counters (EStats)":
        "SetPerTcpConnectionEStats requires an elevated token.",
    "Packet capture (Scapy + Npcap)":
        "Npcap normally restricts capture to Administrators.",
    "Firewall block rules":
        "Creating Windows Firewall rules requires Administrator rights.",
    "Enabling the DNS Client operational log":
        "Changing event log configuration requires Administrator rights.",
    "Privacy history of other Windows users":
        "Reading other users' registry hives (HKEY_USERS) requires Administrator rights.",
    "Executable path of protected/system processes":
        "Protected processes deny query access to standard users.",
}


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def relaunch_as_admin(extra_args: list[str] | None = None) -> bool:
    """Ask Windows (UAC prompt, visible to the user) to restart NetSentinel elevated."""
    if not IS_WINDOWS:
        return False
    import ctypes
    import subprocess
    if getattr(sys, "frozen", False):
        exe, args = sys.executable, list(sys.argv[1:])
    else:
        exe = sys.executable
        args = [os.path.abspath(sys.argv[0])] + list(sys.argv[1:])
    args += extra_args or []
    params = subprocess.list2cmdline(args)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    ok = rc > 32
    if not ok:
        log.warning("Elevation was cancelled or failed (code %s)", rc)
    return ok


def windows_build() -> int | None:
    if not IS_WINDOWS:
        return None
    try:
        return sys.getwindowsversion().build
    except Exception:
        return None


def compatibility_report() -> dict:
    build = windows_build()
    rep = {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "is_windows": IS_WINDOWS,
        "windows_build": build,
        "is_windows_11": bool(build and build >= 22000),
        "is_admin": is_admin(),
        "warnings": [],
    }
    if not IS_WINDOWS:
        rep["warnings"].append("Not running on Windows: Windows-specific telemetry "
                               "(privacy monitor, EStats, firewall, DNS log) is unavailable.")
    elif build and build < 18362:
        rep["warnings"].append("Windows builds older than 1903 do not record desktop-app "
                               "microphone/camera usage in the CapabilityAccessManager store.")
    elif build and build < 22000:
        rep["warnings"].append("Windows 10 detected. NetSentinel targets Windows 11 but most "
                               "features work on Windows 10 1903+.")
    if sys.version_info < (3, 12):
        rep["warnings"].append("Python 3.12+ is recommended.")
    return rep
