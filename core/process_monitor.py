"""Process identity, ownership, parentage and code-signing verification.

Signature checks are slow (PowerShell / WinVerifyTrust), so they run on a background
worker in batches and are cached per (path, size, mtime).
"""
from __future__ import annotations

import logging
import os
import queue
import threading
import time
from typing import Callable, Optional

import psutil

from core.models import ProcessInfo
from utils import windows_api
from utils.helpers import suspicious_location

log = logging.getLogger(__name__)

SIG_BATCH = 20


class ProcessMonitor:
    def __init__(self, store_usernames: bool = True,
                 signature_checker: Callable[[list[str]], dict] | None = None,
                 on_signature: Callable[[str, windows_api.SignatureInfo], None] | None = None):
        self.store_usernames = store_usernames
        self._checker = signature_checker or windows_api.check_signatures
        self._on_signature = on_signature
        self._cache: dict[int, ProcessInfo] = {}          # pid -> info (latest instance)
        self._sig_cache: dict[tuple, windows_api.SignatureInfo] = {}
        self._sig_queue: "queue.Queue[str]" = queue.Queue()
        self._sig_inflight: set[str] = set()
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._visible_pids: set[int] = set()
        self._visible_ts = 0.0
        self._worker = threading.Thread(target=self._sig_worker, name="sig-worker", daemon=True)
        self._worker.start()

    # ----------------------------------------------------------- lookups
    def get(self, pid: Optional[int]) -> ProcessInfo:
        now = time.time()
        if pid is None:
            return ProcessInfo(pid=-1, name="unknown", exe_note="no PID reported", first_seen=now, last_seen=now)
        if pid == 0:
            return ProcessInfo(pid=0, name="System Idle Process", exe_note="kernel", sig_status="os",
                               first_seen=now, last_seen=now)
        if pid == 4:
            return self._system_process(now)
        with self._lock:
            info = self._cache.get(pid)
        p, ctime = None, 0.0
        try:
            p = psutil.Process(pid)
            ctime = p.create_time()
        except psutil.NoSuchProcess:
            if info:
                info.terminated = True
                return info
            return ProcessInfo(pid=pid, name="terminated process", exe_note="process exited before it could be inspected",
                               terminated=True, sig_status="unavailable", first_seen=now, last_seen=now)
        except psutil.AccessDenied:
            pass  # keep p (name/ppid are often still readable); create_time unknown
        if info and abs(info.create_time - ctime) < 0.01 and not info.terminated:
            info.last_seen = now
            self._refresh_window_flag(info)
            return info
        info = self._inspect(pid, p, ctime, now)
        with self._lock:
            self._cache[pid] = info
        return info

    def _system_process(self, now: float) -> ProcessInfo:
        return ProcessInfo(pid=4, name="System", exe="", exe_note="Windows kernel (ntoskrnl)",
                           sig_status="os", publisher="Microsoft Windows", is_os_binary=True,
                           has_window=False, first_seen=now, last_seen=now)

    def _inspect(self, pid: int, p: Optional[psutil.Process], ctime: float, now: float) -> ProcessInfo:
        info = ProcessInfo(pid=pid, create_time=ctime, first_seen=now, last_seen=now)
        if p is None:
            info.name, info.exe_note, info.sig_status = "inaccessible process", "access denied", "unavailable"
            return info
        try:
            with p.oneshot():
                info.name = _safe(p.name) or "unknown"
                info.exe = _safe(p.exe) or ""
                if not info.exe:
                    info.exe_note = "executable path not accessible (run as Administrator for protected processes)"
                if self.store_usernames:
                    info.username = _safe(p.username) or ""
                info.ppid = _safe(p.ppid)
        except psutil.NoSuchProcess:
            info.terminated = True
        if info.ppid:
            try:
                parent = psutil.Process(info.ppid)
                # guard against PID reuse: a real parent starts before its child
                if parent.create_time() <= (ctime or now) + 1:
                    info.parent_name = parent.name()
                else:
                    info.parent_name = "(parent exited; PID reused)"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                info.parent_name = "(parent not running)"
        info.suspicious_dir = suspicious_location(info.exe) or ""
        self._refresh_window_flag(info)
        if info.exe:
            sig = self.cached_signature(info.exe)
            if sig:
                _apply_sig(info, sig)
            else:
                self.request_signature(info.exe)
        else:
            info.sig_status = "unavailable"
        return info

    def _refresh_window_flag(self, info: ProcessInfo) -> None:
        if os.name != "nt":
            return
        now = time.time()
        if now - self._visible_ts > 5:
            try:
                self._visible_pids = windows_api.pids_with_visible_windows()
            except Exception:
                self._visible_pids = set()
            self._visible_ts = now
        info.has_window = info.pid in self._visible_pids

    def all_cached(self) -> list[ProcessInfo]:
        with self._lock:
            return list(self._cache.values())

    def prune(self, max_age: float = 3600) -> None:
        cutoff = time.time() - max_age
        with self._lock:
            for pid in [k for k, v in self._cache.items() if v.last_seen < cutoff]:
                del self._cache[pid]

    # --------------------------------------------------------- signatures
    @staticmethod
    def _sig_key(path: str) -> tuple:
        try:
            st = os.stat(path)
            return (path.lower(), st.st_size, int(st.st_mtime))
        except OSError:
            return (path.lower(), None, None)

    def cached_signature(self, path: str) -> Optional[windows_api.SignatureInfo]:
        with self._lock:
            return self._sig_cache.get(self._sig_key(path))

    def request_signature(self, path: str) -> None:
        with self._lock:
            if path in self._sig_inflight:
                return
            self._sig_inflight.add(path)
        self._sig_queue.put(path)

    def _sig_worker(self) -> None:
        while not self._stop.is_set():
            try:
                first = self._sig_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            batch = [first]
            time.sleep(0.3)  # let a burst accumulate
            while len(batch) < SIG_BATCH:
                try:
                    batch.append(self._sig_queue.get_nowait())
                except queue.Empty:
                    break
            try:
                results = self._checker(batch)
            except Exception as e:
                log.warning("Signature check failed: %s", e)
                results = {p: windows_api.SignatureInfo("error", detail=str(e)) for p in batch}
            for path in batch:
                sig = results.get(path) or windows_api.SignatureInfo("error", detail="no result")
                with self._lock:
                    self._sig_cache[self._sig_key(path)] = sig
                    self._sig_inflight.discard(path)
                    for info in self._cache.values():
                        if info.exe and info.exe.lower() == path.lower():
                            _apply_sig(info, sig)
                if self._on_signature:
                    try:
                        self._on_signature(path, sig)
                    except Exception:
                        log.exception("on_signature callback failed")

    def stop(self) -> None:
        self._stop.set()


def _apply_sig(info: ProcessInfo, sig: windows_api.SignatureInfo) -> None:
    info.sig_status = sig.status
    info.publisher = sig.publisher
    info.sig_type = sig.sig_type
    info.is_os_binary = sig.is_os_binary


def _safe(fn):
    try:
        return fn()
    except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return None
    except psutil.NoSuchProcess:
        raise
