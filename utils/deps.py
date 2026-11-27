"""Runtime dependency / Python version checks and automatic installation.

When NetSentinel is run from source, missing or outdated required packages are installed
or upgraded automatically with pip (into the same interpreter / virtual environment),
then the program continues. Disable with:  python main.py --no-auto-install
The packaged .exe bundles its dependencies and never runs pip.
"""
from __future__ import annotations

import importlib
import logging
import os
import subprocess
import sys
from importlib import metadata
from pathlib import Path

log = logging.getLogger(__name__)

MIN_PYTHON = (3, 12)
# name -> (minimum, exclusive upper bound) — keep in sync with requirements.txt
REQUIRED = {"psutil": ("6.1", "8"), "customtkinter": ("5.2.2", "6"),
            "matplotlib": ("3.9", "4"), "requests": ("2.32", "3")}
OPTIONAL = {"scapy": ("2.6.1", "3"), "maxminddb": ("2.6", "3")}


def _ver_tuple(v: str) -> tuple:
    out = []
    for part in v.split(".")[:3]:
        num = "".join(ch for ch in part if ch.isdigit())
        out.append(int(num) if num else 0)
    return tuple(out)


def _spec(name: str, bounds: tuple[str, str]) -> str:
    return f"{name}>={bounds[0]},<{bounds[1]}"


def check(include_gui: bool = True) -> dict:
    res = {"python": sys.version.split()[0], "python_ok": sys.version_info[:2] >= MIN_PYTHON,
           "missing": [], "outdated": [], "installed": {}, "optional": {}}
    for name, bounds in REQUIRED.items():
        if name == "customtkinter" and not include_gui:
            continue
        try:
            v = metadata.version(name)
            res["installed"][name] = v
            if not (_ver_tuple(bounds[0]) <= _ver_tuple(v) < _ver_tuple(bounds[1])):
                res["outdated"].append((name, v, _spec(name, bounds)))
        except metadata.PackageNotFoundError:
            res["missing"].append((name, None, _spec(name, bounds)))
    for name in OPTIONAL:
        try:
            res["optional"][name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            res["optional"][name] = None
    return res


def problems(include_gui: bool = True) -> list[str]:
    r = check(include_gui)
    out = []
    if not r["python_ok"]:
        out.append(f"Python {r['python']} detected; NetSentinel requires Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+.")
    if r["missing"]:
        out.append("Missing packages: " + ", ".join(s for _n, _v, s in r["missing"]))
    if r["outdated"]:
        out.append("Outdated packages: " + ", ".join(f"{n} {v} (need {s})" for n, v, s in r["outdated"]))
    return out


def pip_install(specs: list[str], upgrade: bool = True, timeout: int = 900) -> tuple[bool, str]:
    """Install/upgrade packages with the running interpreter's pip. Never uses a shell."""
    if not specs:
        return True, ""
    cmd = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-input"]
    if upgrade:
        cmd.append("--upgrade")
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    if not in_venv and not _site_writable():
        cmd.append("--user")   # system Python without admin rights: install for this user only
    cmd += specs
    kwargs = {"capture_output": True, "text": True, "timeout": timeout}
    if os.name == "nt":
        kwargs["creationflags"] = 0x08000000   # no console window flash when launched via pythonw
    log.info("Running: %s", " ".join(cmd))
    try:
        r = subprocess.run(cmd, **kwargs)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    out = (r.stdout or "")[-2000:] + (r.stderr or "")[-2000:]
    if r.returncode == 0:
        importlib.invalidate_caches()
    return r.returncode == 0, out


def _site_writable() -> bool:
    import sysconfig
    try:
        p = Path(sysconfig.get_paths()["purelib"])
        return os.access(p, os.W_OK)
    except Exception:
        return False


def ensure(include_gui: bool = True, include_optional: bool = False, echo=print) -> list[str]:
    """Install missing and upgrade outdated required packages. Returns remaining problems."""
    if getattr(sys, "frozen", False):
        return []
    r = check(include_gui)
    if not r["python_ok"]:
        return problems(include_gui)
    todo = [s for _n, _v, s in r["missing"] + r["outdated"]]
    if include_optional:
        todo += [_spec(n, OPTIONAL[n]) for n, v in r["optional"].items() if v is None]
    if todo:
        echo(f"NetSentinel: installing/updating {', '.join(todo)} …")
        ok, out = pip_install(todo)
        if ok:
            echo("NetSentinel: packages installed.")
        else:
            log.error("pip failed:\n%s", out)
            echo("NetSentinel: automatic install failed (offline, proxy or permissions?).\n"
                 f"Run manually:  \"{sys.executable}\" -m pip install -r requirements.txt\n" + out[-800:])
    return problems(include_gui)
