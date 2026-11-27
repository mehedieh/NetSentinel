"""Microphone & camera access monitoring.

Data source (read-only, no device is ever opened):
  HKCU|HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\{microphone|webcam}
    <PackageFamilyName>\\            packaged (Store/MSIX) apps
    NonPackaged\\C:#Path#To#app.exe\\  desktop (Win32) apps, '#' replaces '\\'
      Value              REG_SZ    Allow | Deny     (permission)
      LastUsedTimeStart  REG_QWORD FILETIME         (last time access began)
      LastUsedTimeStop   REG_QWORD FILETIME, 0 while access is ongoing

This is the same store that drives the Windows 11 privacy indicator and
Settings > Privacy & security > Microphone/Camera > "Recent activity".

What it can and cannot tell us is listed in BLIND_SPOTS and surfaced in the UI.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Protocol

from core.models import PrivacyEvent
from utils.helpers import filetime_to_epoch, normalize_path

log = logging.getLogger(__name__)

CAPABILITIES = {"microphone": "Microphone", "webcam": "Camera"}
CONSENT_PATH = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"

BLIND_SPOTS = [
    "Only access brokered by the Windows Capability Access Manager is recorded. Kernel drivers, "
    "some virtual-camera/audio drivers and software that talks to hardware directly are not visible.",
    "Timestamps are when Windows recorded access start/stop; they do not prove audio or video was "
    "captured, stored or transmitted.",
    "Browsers are reported as the browser executable; the individual website using the device is not exposed here.",
    "Very short accesses that begin and end between two polls are still detected (from the stored "
    "timestamps) but are reported after the fact.",
    "Accesses by other Windows user accounts are visible only when NetSentinel runs as Administrator.",
    "Windows records one 'last used' start/stop pair per app, so earlier sessions are only known "
    "if NetSentinel was running at the time.",
    "Windows 10 builds older than 1903 do not record desktop (non-packaged) apps.",
]


@dataclass
class AccessRecord:
    capability: str
    app_id: str
    app_kind: str
    scope: str
    permission: str
    last_start: Optional[float]
    last_stop: Optional[float]

    @property
    def active(self) -> bool:
        return bool(self.last_start) and (not self.last_stop or self.last_stop < self.last_start)

    @property
    def display_name(self) -> str:
        if self.app_kind == "desktop":
            return self.app_id.replace("/", "\\").rsplit("\\", 1)[-1]
        return self.app_id.split("_")[0]


@dataclass
class CapabilityState:
    capability: str
    telemetry: str = "unknown"        # available | unavailable
    reason: str = ""
    user_permission: str = ""         # Allow | Deny | "" (not set)
    machine_permission: str = ""
    active_apps: list = field(default_factory=list)
    last_access: Optional[AccessRecord] = None


class RegistrySource(Protocol):
    def subkeys(self, hive: str, path: str) -> list[str]: ...
    def values(self, hive: str, path: str) -> dict: ...


class WinRegSource:
    """winreg-backed read-only source. hive: 'HKCU' | 'HKLM' | 'HKU\\<SID>'"""

    def __init__(self):
        import winreg
        self.winreg = winreg

    def _open(self, hive: str, path: str):
        wr = self.winreg
        if hive == "HKCU":
            root, sub = wr.HKEY_CURRENT_USER, path
        elif hive == "HKLM":
            root, sub = wr.HKEY_LOCAL_MACHINE, path
        elif hive.startswith("HKU\\"):
            root, sub = wr.HKEY_USERS, hive[4:] + "\\" + path
        else:
            raise ValueError(hive)
        return wr.OpenKey(root, sub, 0, wr.KEY_READ)

    def subkeys(self, hive: str, path: str) -> list[str]:
        out = []
        with self._open(hive, path) as k:
            i = 0
            while True:
                try:
                    out.append(self.winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
        return out

    def values(self, hive: str, path: str) -> dict:
        out = {}
        with self._open(hive, path) as k:
            i = 0
            while True:
                try:
                    name, val, _t = self.winreg.EnumValue(k, i)
                except OSError:
                    break
                out[name] = val
                i += 1
        return out

    def user_sids(self) -> list[str]:
        try:
            sids = self.subkeys_root_users()
        except OSError:
            return []
        return [s for s in sids if s.startswith("S-1-5-21-") and not s.endswith("_Classes")]

    def subkeys_root_users(self) -> list[str]:
        wr = self.winreg
        out = []
        with wr.OpenKey(wr.HKEY_USERS, "", 0, wr.KEY_READ) as k:
            i = 0
            while True:
                try:
                    out.append(wr.EnumKey(k, i))
                except OSError:
                    break
                i += 1
        return out


def read_capability(source: RegistrySource, hive: str, capability: str) -> tuple[str, list[AccessRecord]]:
    """Return (capability-level permission, per-app records) for one hive."""
    base = f"{CONSENT_PATH}\\{capability}"
    scope = {"HKCU": "user", "HKLM": "machine"}.get(hive, f"user:{hive[4:]}")
    vals = source.values(hive, base)
    permission = str(vals.get("Value", "") or "")
    records: list[AccessRecord] = []
    for sub in source.subkeys(hive, base):
        if sub.lower() == "nonpackaged":
            for app in source.subkeys(hive, f"{base}\\{sub}"):
                v = _safe_values(source, hive, f"{base}\\{sub}\\{app}")
                records.append(_record(capability, app.replace("#", "\\"), "desktop", scope, v))
        else:
            v = _safe_values(source, hive, f"{base}\\{sub}")
            records.append(_record(capability, sub, "packaged", scope, v))
    return permission, records


def _safe_values(source, hive, path) -> dict:
    try:
        return source.values(hive, path)
    except OSError:
        return {}


def _record(cap, app_id, kind, scope, v) -> AccessRecord:
    return AccessRecord(cap, app_id, kind, scope, str(v.get("Value", "") or ""),
                        filetime_to_epoch(_int(v.get("LastUsedTimeStart"))),
                        filetime_to_epoch(_int(v.get("LastUsedTimeStop"))))


def _int(x) -> int:
    try:
        return int(x or 0)
    except (TypeError, ValueError):
        return 0


class PrivacyMonitor:
    def __init__(self, source: RegistrySource | None = None, include_other_users: bool = False,
                 pid_resolver: Callable[[AccessRecord], list[int]] | None = None):
        if source is None and os.name == "nt":
            try:
                source = WinRegSource()
            except ImportError:
                source = None
        self.source = source
        self.include_other_users = include_other_users
        self.pid_resolver = pid_resolver
        self._prev: dict[tuple, AccessRecord] = {}
        self._initialized = False
        self.state: dict[str, CapabilityState] = {c: CapabilityState(c) for c in CAPABILITIES}
        self.records: list[AccessRecord] = []
        self._lock = threading.RLock()

    @property
    def available(self) -> bool:
        return self.source is not None

    def _hives(self) -> list[str]:
        hives = ["HKCU", "HKLM"]
        if self.include_other_users and isinstance(self.source, WinRegSource):
            hives += [f"HKU\\{sid}" for sid in self.source.user_sids()]
        return hives

    def poll(self) -> list[PrivacyEvent]:
        if self.source is None:
            for st in self.state.values():
                st.telemetry, st.reason = "unavailable", "Windows CapabilityAccessManager store not available on this system"
            return []
        now = time.time()
        current: dict[tuple, AccessRecord] = {}
        new_state = {c: CapabilityState(c) for c in CAPABILITIES}
        for cap in CAPABILITIES:
            st = new_state[cap]
            ok_any = False
            for hive in self._hives():
                try:
                    perm, recs = read_capability(self.source, hive, cap)
                    ok_any = True
                except OSError as e:
                    if hive in ("HKCU", "HKLM"):
                        st.reason = f"{hive}: {e}"
                    continue
                if hive == "HKCU":
                    st.user_permission = perm
                elif hive == "HKLM":
                    st.machine_permission = perm
                for r in recs:
                    current[(r.capability, r.scope, r.app_id.lower())] = r
            st.telemetry = "available" if ok_any else "unavailable"
            recs = [r for r in current.values() if r.capability == cap]
            st.active_apps = sorted({r.display_name for r in recs if r.active})
            used = [r for r in recs if r.last_start]
            st.last_access = max(used, key=lambda r: r.last_start) if used else None

        events = self._diff(current, now)
        with self._lock:
            self.state = new_state
            self.records = sorted(current.values(), key=lambda r: r.last_start or 0, reverse=True)
        return events

    def _diff(self, current: dict, now: float) -> list[PrivacyEvent]:
        events: list[PrivacyEvent] = []
        first = not self._initialized
        for k, r in current.items():
            old = self._prev.get(k)
            if first:
                if r.active:
                    events.append(self._event(r, "active_at_start", r.last_start or now))
                elif r.last_start:
                    events.append(self._event(r, "historical", r.last_start))
                continue
            if old is None:
                if r.active:
                    events.append(self._event(r, "access_started", r.last_start or now))
                elif r.last_start:
                    events.append(self._event(r, "access_session", r.last_start))
                continue
            if r.active and not old.active:
                events.append(self._event(r, "access_started", r.last_start or now))
            elif not r.active and old.active:
                events.append(self._event(r, "access_stopped", r.last_stop or now))
            elif not r.active and r.last_start and r.last_start != old.last_start:
                # started and stopped between two polls
                events.append(self._event(r, "access_session", r.last_start))
            elif r.active and old.active and r.last_start != old.last_start:
                events.append(self._event(r, "access_started", r.last_start or now))
        self._prev = current
        self._initialized = True
        return events

    def _event(self, r: AccessRecord, etype: str, ts: float) -> PrivacyEvent:
        pids = []
        if self.pid_resolver:
            try:
                pids = self.pid_resolver(r)
            except Exception:
                pids = []
        return PrivacyEvent(ts=ts, capability=r.capability, event_type=etype, app_id=r.app_id,
                            app_kind=r.app_kind, scope=r.scope, start_ts=r.last_start,
                            stop_ts=r.last_stop if not r.active else None,
                            permission=r.permission, display_name=r.display_name, pids=pids)

    def snapshot(self) -> tuple[dict[str, CapabilityState], list[AccessRecord]]:
        with self._lock:
            return dict(self.state), list(self.records)


def app_matches_exe(app_id: str, app_kind: str, exe: str) -> bool:
    """Does a ConsentStore app identity correspond to a process executable?"""
    exe_n = normalize_path(exe)
    if not exe_n:
        return False
    if app_kind == "desktop":
        return normalize_path(app_id) == exe_n
    pkg = app_id.split("_")[0].lower()
    return f"\\windowsapps\\{pkg}_" in exe_n


def resolve_pids(record_or_event, processes: Iterable) -> list[int]:
    """processes: iterable of objects with .pid and .exe"""
    app_id, kind = record_or_event.app_id, record_or_event.app_kind
    return sorted({p.pid for p in processes if app_matches_exe(app_id, kind, p.exe)})
