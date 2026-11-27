"""Traffic accounting, spike detection, beaconing and long-lived connection analysis.

Byte counts are only recorded from real measurement sources:
  * "estats" – Windows per-connection TCP counters (admin), counted from when monitoring began
  * "pcap"   – packet header lengths from Scapy/Npcap capture (admin)
System-wide interface totals (psutil) are tracked separately and never attributed to apps.
"""
from __future__ import annotations

import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional

from core.models import Connection


@dataclass
class BeaconFinding:
    exe: str
    process_name: str
    raddr: str
    rport: int
    count: int
    mean_interval: float
    cv: float
    first: float
    last: float

    def as_dict(self) -> dict:
        return {"count": self.count, "mean_interval": self.mean_interval, "cv": self.cv}


class TrafficTracker:
    def __init__(self, spike_mb_per_min: float = 25.0, spike_factor: float = 5.0):
        self._lock = threading.RLock()
        self._last: dict[str, tuple[int, int]] = {}            # conn uid -> cumulative (out, in)
        self.per_exe: dict[str, list] = defaultdict(lambda: [0, 0, "", set()])  # out, in, name, sources
        self.per_remote: dict[str, list] = defaultdict(lambda: [0, 0])
        self.per_proto: dict[str, list] = defaultdict(lambda: [0, 0])
        self._exe_series: dict[str, deque] = defaultdict(lambda: deque(maxlen=3600))  # (ts, out, in)
        self.timeline: deque = deque(maxlen=720)                # (bucket_ts, out, in) 5-s buckets attributed
        self._hourly: dict[tuple, list] = defaultdict(lambda: [0, 0, ""])   # (hour, exe, raddr, proto)
        self._minute: dict[str, int] = defaultdict(int)
        self._minute_start = int(time.time() // 60) * 60
        self._baseline: dict[str, float] = {}
        self.spike_bytes = spike_mb_per_min * 1024 * 1024
        self.spike_factor = spike_factor
        self.sources_active: set[str] = set()

    # ------------------------------------------------------------ input
    def update_cumulative(self, conn: Connection, out_total: int, in_total: int, source: str,
                          ts: float | None = None) -> None:
        """Feed cumulative counters for one connection (EStats)."""
        ts = ts or time.time()
        with self._lock:
            prev = self._last.get(conn.uid, (0, 0))
            d_out, d_in = max(0, out_total - prev[0]), max(0, in_total - prev[1])
            self._last[conn.uid] = (out_total, in_total)
        conn.bytes_out, conn.bytes_in, conn.measure_source = out_total, in_total, source
        if d_out or d_in:
            self._account(conn.exe or conn.process_name, conn.process_name, conn.raddr, conn.proto,
                          d_out, d_in, source, ts)

    def add_delta(self, conn: Optional[Connection], exe: str, name: str, raddr: str, proto: str,
                  d_out: int, d_in: int, source: str, ts: float | None = None) -> None:
        """Feed incremental bytes (packet capture)."""
        ts = ts or time.time()
        if conn is not None:
            conn.bytes_out = (conn.bytes_out or 0) + d_out
            conn.bytes_in = (conn.bytes_in or 0) + d_in
            conn.measure_source = source
        self._account(exe or name, name, raddr, proto, d_out, d_in, source, ts)

    def _account(self, exe, name, raddr, proto, d_out, d_in, source, ts) -> None:
        key = (exe or name or "unknown")
        with self._lock:
            self.sources_active.add(source)
            e = self.per_exe[key]
            e[0] += d_out
            e[1] += d_in
            e[2] = name
            e[3].add(source)
            r = self.per_remote[raddr or "(none)"]
            r[0] += d_out
            r[1] += d_in
            pr = self.per_proto[proto]
            pr[0] += d_out
            pr[1] += d_in
            self._exe_series[key].append((ts, d_out, d_in))
            bucket = int(ts // 5) * 5
            if self.timeline and self.timeline[-1][0] == bucket:
                b = self.timeline[-1]
                self.timeline[-1] = (bucket, b[1] + d_out, b[2] + d_in)
            else:
                self.timeline.append((bucket, d_out, d_in))
            h = self._hourly[(int(ts // 3600) * 3600, key, raddr or "", proto)]
            h[0] += d_out
            h[1] += d_in
            h[2] = source
            self._minute[key] += d_out

    def forget(self, conn: Connection) -> None:
        with self._lock:
            self._last.pop(conn.uid, None)

    # ----------------------------------------------------------- queries
    def bytes_between(self, exe: str, t0: float, t1: float) -> tuple[Optional[int], bool, str]:
        if not self.sources_active:
            return None, False, "no per-process traffic source active (requires Administrator: EStats or packet capture)"
        with self._lock:
            series = list(self._exe_series.get(exe, ()))
        total = sum(o for ts, o, _i in series if t0 <= ts <= t1 + 2)
        note = "TCP counters (EStats)" if "estats" in self.sources_active else "packet capture"
        return total, True, note

    def top_apps(self, n: int = 10) -> list[tuple[str, str, int, int]]:
        with self._lock:
            items = [(k, v[2], v[0], v[1]) for k, v in self.per_exe.items()]
        return sorted(items, key=lambda x: x[2] + x[3], reverse=True)[:n]

    def top_remotes(self, n: int = 10) -> list[tuple[str, int, int]]:
        with self._lock:
            items = [(k, v[0], v[1]) for k, v in self.per_remote.items()]
        return sorted(items, key=lambda x: x[1] + x[2], reverse=True)[:n]

    def protocols(self) -> dict[str, tuple[int, int]]:
        with self._lock:
            return {k: (v[0], v[1]) for k, v in self.per_proto.items()}

    def totals(self) -> tuple[int, int]:
        with self._lock:
            return sum(v[0] for v in self.per_exe.values()), sum(v[1] for v in self.per_exe.values())

    def app_totals(self, exe: str) -> Optional[tuple[int, int]]:
        with self._lock:
            v = self.per_exe.get(exe)
            return (v[0], v[1]) if v else None

    def drain_hourly(self) -> list[tuple]:
        with self._lock:
            rows = [(k[0], k[1], k[2], k[3], v[0], v[1], v[2]) for k, v in self._hourly.items()]
            self._hourly.clear()
        return rows

    # ---------------------------------------------------- spike detection
    def check_spikes(self, now: float | None = None) -> list[dict]:
        """Call regularly. At each minute boundary compares per-app upload to an EWMA baseline."""
        now = now or time.time()
        minute = int(now // 60) * 60
        if minute == self._minute_start:
            return []
        spikes = []
        with self._lock:
            for exe, up in self._minute.items():
                base = self._baseline.get(exe)
                if up >= self.spike_bytes and (base is None or up >= self.spike_factor * max(base, 1024 * 100)):
                    spikes.append({"exe": exe, "name": self.per_exe[exe][2], "bytes": up,
                                   "baseline": base or 0, "minute": self._minute_start})
                self._baseline[exe] = up if base is None else 0.8 * base + 0.2 * up
            for exe in list(self._baseline):
                if exe not in self._minute:
                    self._baseline[exe] *= 0.8
            self._minute = defaultdict(int)
            self._minute_start = minute
        return spikes


class BeaconDetector:
    """Flags connection *starts* to the same destination at regular intervals.

    cv = stdev(intervals)/mean(intervals). Human-driven traffic is irregular (high cv);
    automated check-ins are regular (low cv). Persistent keep-alive connections that do
    not reconnect are not visible to this method (see long-lived connections instead).
    """

    def __init__(self, min_events: int = 6, max_cv: float = 0.2, min_interval: float = 5.0,
                 max_interval: float = 7200.0):
        self.min_events, self.max_cv = min_events, max_cv
        self.min_interval, self.max_interval = min_interval, max_interval
        self._events: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=60))
        self._names: dict[tuple, str] = {}
        self._lock = threading.RLock()

    def record(self, exe: str, name: str, raddr: str, rport: int, ts: float) -> None:
        key = (exe or name, raddr, rport)
        with self._lock:
            dq = self._events[key]
            if dq and ts - dq[-1] < 1.0:  # same burst
                return
            dq.append(ts)
            self._names[key] = name

    def analyze(self) -> list[BeaconFinding]:
        out = []
        with self._lock:
            items = [(k, list(v)) for k, v in self._events.items() if len(v) >= self.min_events]
        for (exe, raddr, rport), ts in items:
            ts = ts[-(self.min_events * 3):]
            iv = [b - a for a, b in zip(ts, ts[1:])]
            mean = statistics.fmean(iv)
            if not (self.min_interval <= mean <= self.max_interval):
                continue
            cv = statistics.pstdev(iv) / mean if mean else 1.0
            if cv <= self.max_cv:
                out.append(BeaconFinding(exe, self._names.get((exe, raddr, rport), ""), raddr, rport,
                                         len(ts), mean, cv, ts[0], ts[-1]))
        return out


def long_lived(conns: list[Connection], minutes: int, now: float | None = None) -> list[Connection]:
    now = now or time.time()
    return [c for c in conns if c.proto == "TCP" and c.state == "ESTABLISHED"
            and now - c.first_seen >= minutes * 60]
