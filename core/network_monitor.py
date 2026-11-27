"""Connection table polling (psutil -> GetExtendedTcpTable/GetExtendedUdpTable on Windows).

Produces *observations* of sockets. Observing a connection does not mean data moved;
byte counts come from core.packet_analyzer / core.traffic_analyzer and are tracked
separately with an explicit measurement source.
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from collections import defaultdict
from typing import Callable, Optional

import psutil

from core.models import Connection
from utils.helpers import DestClass, classify_ip, short_id

log = logging.getLogger(__name__)

_WILDCARDS = {"0.0.0.0", "::", ""}


class NetworkMonitor:
    def __init__(self, classify: Callable[[str], str] = classify_ip,
                 conn_source: Callable[[], list] | None = None):
        self._classify = classify
        self._source = conn_source or (lambda: psutil.net_connections(kind="inet"))
        self.current: dict[tuple, Connection] = {}
        self.listeners: dict[tuple, dict] = {}          # (pid, proto, laddr, lport) -> info
        self._history_counts: dict[tuple, int] = defaultdict(int)  # (exe/name, raddr, rport) -> n
        self._lock = threading.RLock()
        self.last_error: str = ""
        self.polls = 0

    def _direction(self, proto: str, status: str, pid: int, laddr: str, lport: int, raddr: str,
                   listening: set) -> str:
        if proto == "TCP" and status == "LISTEN":
            return "listen"
        if proto == "UDP" and not raddr:
            return "endpoint"
        if proto == "TCP" and ((laddr, lport) in listening or ("*", lport) in listening):
            return "inbound"
        return "outbound"

    def poll(self, name_for_pid: Callable[[int], tuple[str, str]] | None = None
             ) -> tuple[list[Connection], list[Connection], dict[tuple, Connection]]:
        """Return (new, closed, current). ``name_for_pid`` -> (process_name, exe)."""
        now = time.time()
        try:
            raw = self._source()
            self.last_error = ""
        except psutil.AccessDenied as e:
            self.last_error = f"Access denied listing connections: {e}"
            raise
        self.polls += 1

        # first pass: listening sockets (for inbound detection)
        listening: set[tuple] = set()
        listeners: dict[tuple, dict] = {}
        for c in raw:
            if c.type == socket.SOCK_STREAM and c.status == "LISTEN" and c.laddr:
                ip, port = c.laddr.ip, c.laddr.port
                listening.add(("*", port) if ip in _WILDCARDS else (ip, port))
                listeners[(c.pid, "TCP", ip, port)] = {"pid": c.pid, "proto": "TCP", "laddr": ip, "lport": port}
            elif c.type == socket.SOCK_DGRAM and c.laddr and not c.raddr:
                ip, port = c.laddr.ip, c.laddr.port
                listeners[(c.pid, "UDP", ip, port)] = {"pid": c.pid, "proto": "UDP", "laddr": ip, "lport": port}

        seen: dict[tuple, Connection] = {}
        new: list[Connection] = []
        with self._lock:
            prev = self.current
            for c in raw:
                if not c.laddr:
                    continue
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                status = c.status if proto == "TCP" else ("CONNECTED" if c.raddr else "NONE")
                pid = c.pid if c.pid is not None else -1
                # Kernel-owned TIME_WAIT remnants (PID 0) of already-closed sockets: skip
                if status == "TIME_WAIT" and pid in (0, -1):
                    continue
                if status == "LISTEN" or (proto == "UDP" and not c.raddr):
                    continue  # tracked in self.listeners
                laddr, lport = c.laddr.ip, c.laddr.port
                raddr = c.raddr.ip if c.raddr else ""
                rport = c.raddr.port if c.raddr else 0
                key = (pid, proto, laddr, lport, raddr, rport)
                if key in seen:
                    continue
                old = prev.get(key)
                if old is not None:
                    old.state = status
                    old.last_seen = now
                    seen[key] = old
                    continue
                pname, exe = name_for_pid(pid) if name_for_pid else ("unknown", "")
                conn = Connection(
                    uid=short_id(), pid=pid, proto=proto,
                    family=6 if c.family == socket.AF_INET6 else 4,
                    laddr=laddr, lport=lport, raddr=raddr, rport=rport, state=status,
                    direction=self._direction(proto, status, pid, laddr, lport, raddr, listening),
                    dest_class=self._classify(raddr) if raddr else DestClass.UNKNOWN,
                    first_seen=now, last_seen=now, process_name=pname, exe=exe)
                hkey = ((exe or pname).lower(), raddr, rport)
                conn.repeat_count = self._history_counts[hkey]
                self._history_counts[hkey] += 1
                seen[key] = conn
                new.append(conn)
            closed = []
            for key, conn in prev.items():
                if key not in seen:
                    conn.closed_at = now
                    closed.append(conn)
            self.current = seen
            self.listeners = listeners
        return new, closed, seen

    def snapshot(self) -> list[Connection]:
        with self._lock:
            return list(self.current.values())

    def lookup_by_tuple(self, proto: str, lport: int, raddr: str | None = None,
                        rport: int | None = None) -> Optional[Connection]:
        """Used by packet capture to attribute packets to a connection/process."""
        cur = self.current  # atomic reference read
        for conn in cur.values():
            if conn.proto == proto and conn.lport == lport and (
                    raddr is None or (conn.raddr == raddr and conn.rport == rport)):
                return conn
        return None

    def listener_pid(self, proto: str, lport: int) -> Optional[int]:
        for (pid, p, _ip, port) in list(self.listeners.keys()):
            if p == proto and port == lport:
                return pid
        return None


def interface_names() -> list[str]:
    try:
        return sorted(psutil.net_if_addrs().keys())
    except Exception:
        return []


def local_addresses() -> set[str]:
    out = set()
    try:
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    out.add(a.address.split("%")[0])
    except Exception:
        pass
    return out


class InterfaceCounters:
    """System-wide byte counters per interface (always available, no admin).
    This is ground truth for *total* traffic but cannot attribute bytes to processes."""

    def __init__(self, interface: str = ""):
        self.interface = interface
        self._prev = None
        self.total_sent = 0
        self.total_recv = 0
        self.rate_sent = 0.0
        self.rate_recv = 0.0
        self._prev_ts = None
        from collections import deque
        self.history = deque(maxlen=900)   # (ts, bytes/s sent, bytes/s recv)

    def sample(self) -> tuple[int, int]:
        now = time.time()
        try:
            per = psutil.net_io_counters(pernic=True)
        except Exception:
            return 0, 0
        if self.interface and self.interface in per:
            sent, recv = per[self.interface].bytes_sent, per[self.interface].bytes_recv
        else:
            sent = sum(v.bytes_sent for k, v in per.items() if not k.lower().startswith("loopback"))
            recv = sum(v.bytes_recv for k, v in per.items() if not k.lower().startswith("loopback"))
        d_sent = d_recv = 0
        if self._prev is not None:
            d_sent = max(0, sent - self._prev[0])
            d_recv = max(0, recv - self._prev[1])
            dt = max(1e-6, now - self._prev_ts)
            self.rate_sent, self.rate_recv = d_sent / dt, d_recv / dt
            self.total_sent += d_sent
            self.total_recv += d_recv
            self.history.append((now, self.rate_sent, self.rate_recv))
        self._prev, self._prev_ts = (sent, recv), now
        return d_sent, d_recv
