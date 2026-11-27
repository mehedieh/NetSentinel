"""Shared in-memory data structures."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class ProcessInfo:
    pid: int
    name: str = "unknown"
    exe: str = ""
    exe_note: str = ""                 # e.g. "access denied" when path is unavailable
    username: str = ""
    ppid: Optional[int] = None
    parent_name: str = ""
    create_time: float = 0.0
    sig_status: str = "pending"        # see utils.windows_api.SignatureInfo.status
    publisher: str = ""
    sig_type: str = ""
    is_os_binary: bool = False
    suspicious_dir: str = ""
    has_window: Optional[bool] = None  # None = unknown
    terminated: bool = False
    first_seen: float = 0.0
    last_seen: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Connection:
    uid: str
    pid: int
    proto: str                 # TCP | UDP
    family: int                # 4 | 6
    laddr: str
    lport: int
    raddr: str
    rport: int
    state: str
    direction: str             # outbound | inbound | listen | endpoint
    dest_class: str
    first_seen: float
    last_seen: float
    process_name: str = "unknown"
    exe: str = ""
    domain: str = ""
    repeat_count: int = 0      # earlier connections in this session from same exe to same dest
    bytes_out: Optional[int] = None
    bytes_in: Optional[int] = None
    measure_source: str = "none"   # estats | pcap | none
    risk_score: int = 0
    risk_level: str = "informational"
    risk_pending: bool = True
    closed_at: Optional[float] = None

    @property
    def key(self) -> tuple:
        return (self.pid, self.proto, self.laddr, self.lport, self.raddr, self.rport)

    @property
    def remote(self) -> str:
        if not self.raddr:
            return ""
        return f"[{self.raddr}]:{self.rport}" if ":" in self.raddr else f"{self.raddr}:{self.rport}"

    @property
    def local(self) -> str:
        return f"[{self.laddr}]:{self.lport}" if ":" in self.laddr else f"{self.laddr}:{self.lport}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["remote"] = self.remote
        d["local"] = self.local
        return d


@dataclass
class PrivacyEvent:
    ts: float
    capability: str            # microphone | webcam
    event_type: str            # access_started | access_stopped | access_session | active_at_start | historical
    app_id: str                # exe path (desktop) or package family name (packaged)
    app_kind: str              # desktop | packaged
    scope: str                 # user | machine | user:<SID>
    start_ts: Optional[float] = None
    stop_ts: Optional[float] = None
    permission: str = ""
    display_name: str = ""
    pids: list = field(default_factory=list)
    observed: str = "registry"  # source of the observation

    @property
    def duration(self) -> Optional[float]:
        if self.start_ts and self.stop_ts and self.stop_ts >= self.start_ts:
            return self.stop_ts - self.start_ts
        return None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["duration"] = self.duration
        return d


@dataclass
class DnsObservation:
    ts: float
    name: str
    qtype: str = ""
    answers: list = field(default_factory=list)
    pid: Optional[int] = None
    process_name: str = ""
    source: str = ""           # pcap | dns-client-log | dns-cache
    indicators: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CapabilityStatus:
    name: str
    status: str                # active | degraded | unavailable | disabled
    detail: str = ""
    requires_admin: bool = False
