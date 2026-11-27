"""Correlates microphone/camera access with subsequent outbound network activity.

A correlation is a *temporal* association only. Alerts produced here explicitly
state that they do not prove audio or video was transmitted.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional

from core.models import Connection, PrivacyEvent
from core.privacy_monitor import CAPABILITIES, app_matches_exe
from utils.helpers import DestClass, fmt_bytes, fmt_ts, normalize_path

log = logging.getLogger(__name__)


@dataclass
class CorrelationResult:
    capability: str
    app_id: str
    app_kind: str
    display_name: str
    privacy_ts: float
    window_start: float
    window_end: float
    connections: list[Connection] = field(default_factory=list)
    upload_bytes: Optional[int] = None
    upload_measured: bool = False
    measure_note: str = ""
    expected_app: bool = False

    @property
    def capability_label(self) -> str:
        return CAPABILITIES.get(self.capability, self.capability)

    def summary(self) -> str:
        first = min(self.connections, key=lambda c: c.first_seen) if self.connections else None
        parts = [f"{self.capability_label} access by {self.display_name} at {fmt_ts(self.privacy_ts)}"]
        if first:
            dt = first.first_seen - self.privacy_ts
            parts.append(f"outbound connection to {first.remote} observed at {fmt_ts(first.first_seen)} "
                         f"({dt:+.0f}s)")
            if len(self.connections) > 1:
                parts.append(f"{len(self.connections)} external connections in the window")
        if self.upload_measured:
            parts.append(f"{fmt_bytes(self.upload_bytes)} uploaded during the observation window")
        else:
            parts.append(f"upload volume not measured ({self.measure_note})")
        return "; ".join(parts)


class CorrelationEngine:
    def __init__(self, window_before: int = 5, window_after: int = 30,
                 expected_apps: list[str] | None = None,
                 upload_lookup: Callable[[str, float, float], tuple[Optional[int], bool, str]] | None = None):
        self.window_before = window_before
        self.window_after = window_after
        self.expected_apps = {a.lower() for a in (expected_apps or [])}
        self.upload_lookup = upload_lookup
        self._conns: deque[Connection] = deque(maxlen=20000)
        self._pending: list[dict] = []
        self.results: deque[CorrelationResult] = deque(maxlen=500)
        self._lock = threading.RLock()

    def add_connection(self, conn: Connection) -> None:
        if conn.dest_class != DestClass.PUBLIC or conn.direction not in ("outbound", "inbound"):
            return
        with self._lock:
            self._conns.append(conn)

    def add_privacy_event(self, ev: PrivacyEvent) -> None:
        if ev.event_type not in ("access_started", "access_session", "active_at_start"):
            return
        start = ev.start_ts or ev.ts
        with self._lock:
            self._pending.append({"ev": ev, "start": start,
                                  "end": start + self.window_after, "deadline": start + self.window_after})

    def evaluate(self, now: float | None = None) -> list[CorrelationResult]:
        """Finalise windows that have closed. Returns results that contain connections."""
        now = now or time.time()
        done: list[CorrelationResult] = []
        with self._lock:
            still = []
            for p in self._pending:
                if now < p["deadline"]:
                    still.append(p)
                    continue
                res = self._correlate(p["ev"], p["start"])
                if res.connections:
                    self.results.append(res)
                    done.append(res)
            self._pending = still
            # trim connection history to what any window could still need
            horizon = now - max(600, self.window_before + self.window_after + 60)
            while self._conns and self._conns[0].first_seen < horizon:
                self._conns.popleft()
        return done

    def _correlate(self, ev: PrivacyEvent, start: float) -> CorrelationResult:
        w0, w1 = start - self.window_before, start + self.window_after
        matches = [c for c in self._conns
                   if w0 <= c.first_seen <= w1 and app_matches_exe(ev.app_id, ev.app_kind, c.exe)]
        name = ev.display_name or ev.app_id
        exe_base = normalize_path(ev.app_id).rsplit("\\", 1)[-1] if ev.app_kind == "desktop" else name.lower()
        res = CorrelationResult(ev.capability, ev.app_id, ev.app_kind, name, start, w0, w1, matches,
                                expected_app=exe_base in self.expected_apps)
        if matches and self.upload_lookup:
            exe = matches[0].exe
            try:
                res.upload_bytes, res.upload_measured, res.measure_note = self.upload_lookup(exe, w0, w1)
            except Exception as e:
                res.measure_note = f"lookup failed: {e}"
        elif matches:
            res.measure_note = "no traffic source configured"
        return res
