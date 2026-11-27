"""DNS observation, domain↔IP association and DNS heuristics.

Sources (each reported with its own status):
  1. Windows DNS Client operational log (event 3008, query completed). Disabled by default
     in Windows; enabling it needs Administrator. Gives query name and results.
  2. Windows DNS client cache (Get-DnsClientCache). No admin. Gives name→IP, no process.
  3. Packet capture of UDP/53 (optional, see packet_analyzer). No process attribution beyond port.
Blind spots: DNS-over-HTTPS/TLS done inside browsers or apps bypasses all three sources.
"""
from __future__ import annotations

import logging
import re
import socket
import threading
import time
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from core.models import DnsObservation
from utils import windows_api
from utils.helpers import base_domain, parse_ip, shannon_entropy

log = logging.getLogger(__name__)
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
_IP_RX = re.compile(r"(?:::ffff:)?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,39})")
_QTYPES = {"1": "A", "28": "AAAA", "5": "CNAME", "16": "TXT", "10": "NULL", "15": "MX", "33": "SRV",
           "12": "PTR", "65": "HTTPS", "64": "SVCB"}


# ---------------------------------------------------------------- parsing
def parse_dns_client_events(xml_text: str) -> list[dict]:
    """Parse wevtutil /f:xml output for DNS-Client events into dicts."""
    if not xml_text.strip():
        return []
    root = ET.fromstring(f"<Events>{xml_text}</Events>")
    out = []
    for ev in root.findall("e:Event", NS):
        sysel = ev.find("e:System", NS)
        if sysel is None:
            continue
        rid = int(sysel.findtext("e:EventRecordID", "0", NS))
        eid = int(sysel.findtext("e:EventID", "0", NS))
        tc = sysel.find("e:TimeCreated", NS)
        ex = sysel.find("e:Execution", NS)
        data = {d.get("Name"): (d.text or "") for d in ev.findall("e:EventData/e:Data", NS)}
        ts = _parse_systime(tc.get("SystemTime") if tc is not None else "")
        answers = []
        for part in (data.get("QueryResults") or "").split(";"):
            part = part.strip()
            if not part or part.startswith("type:"):
                continue
            ip = parse_ip(part.replace("::ffff:", ""))
            if ip:
                answers.append(str(ip))
        out.append({"record_id": rid, "event_id": eid, "ts": ts,
                    "pid": int(ex.get("ProcessID")) if ex is not None and ex.get("ProcessID") else None,
                    "name": (data.get("QueryName") or "").lower().rstrip("."),
                    "qtype": _QTYPES.get(data.get("QueryType", ""), data.get("QueryType", "")),
                    "status": data.get("QueryStatus", ""), "answers": answers})
    return out


def _parse_systime(s: str) -> float:
    import datetime as dt
    if not s:
        return time.time()
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".", 1)
        s = f"{head}.{frac[:6]}"
    try:
        return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc).timestamp()
    except ValueError:
        return time.time()


# ------------------------------------------------------------- heuristics
_HEXISH = re.compile(r"^[0-9a-f]{16,}$")
_B32ISH = re.compile(r"^[a-z2-7]{24,}$")
_B64ISH = re.compile(r"^[A-Za-z0-9_-]{24,}$")


def name_indicators(name: str) -> list[str]:
    """Per-name heuristic indicators. Weak individually; reported with explanations."""
    ind = []
    name = (name or "").lower().rstrip(".")
    if not name or name.endswith(".arpa") or name.endswith(".local"):
        return ind
    labels = name.split(".")
    sub = labels[:-2] if len(labels) > 2 else []
    if len(name) > 100:
        ind.append(f"very long name ({len(name)} chars)")
    for lab in sub:
        if len(lab) > 40:
            ind.append(f"long subdomain label ({len(lab)} chars)")
            break
    for lab in sub:
        if len(lab) >= 20 and shannon_entropy(lab) > 4.0:
            ind.append(f"high-entropy label '{lab[:24]}…' (H={shannon_entropy(lab):.2f})")
            break
    for lab in sub:
        if _HEXISH.match(lab) and len(lab) >= 32:
            ind.append("hex-encoded label")
            break
        if _B32ISH.match(lab) and sum(ch.isdigit() for ch in lab) >= 4:
            ind.append("base32-like label")
            break
    reg = base_domain(name).split(".")[0]
    if len(reg) >= 12 and shannon_entropy(reg) > 3.6 and sum(ch in "aeiou" for ch in reg) / len(reg) < 0.2:
        ind.append(f"algorithmically generated-looking domain '{reg}'")
    return ind


class DnsRateTracker:
    """Tracks per-registrable-domain query rates and unique subdomain counts (tunnelling)."""

    def __init__(self, per_min_threshold: int = 60, unique_sub_threshold: int = 60):
        self.per_min_threshold = per_min_threshold
        self.unique_sub_threshold = unique_sub_threshold
        self._q: dict[str, deque] = defaultdict(lambda: deque(maxlen=5000))
        self._subs: dict[str, deque] = defaultdict(lambda: deque(maxlen=5000))
        self._txt: dict[str, int] = defaultdict(int)

    def add(self, name: str, qtype: str, ts: float) -> list[str]:
        bd = base_domain(name)
        if not bd or bd.endswith(".arpa"):
            return []
        q, s = self._q[bd], self._subs[bd]
        q.append(ts)
        s.append((ts, name))
        if qtype in ("TXT", "NULL"):
            self._txt[bd] += 1
        while q and q[0] < ts - 60:
            q.popleft()
        while s and s[0][0] < ts - 300:
            s.popleft()
        ind = []
        if len(q) > self.per_min_threshold:
            ind.append(f"{len(q)} queries/min for {bd} (threshold {self.per_min_threshold})")
        uniq = len({n for _t, n in s})
        if uniq > self.unique_sub_threshold:
            ind.append(f"{uniq} unique subdomains of {bd} in 5 min (threshold {self.unique_sub_threshold})")
        if self._txt[bd] > 30 and qtype in ("TXT", "NULL"):
            ind.append(f"{self._txt[bd]} TXT/NULL queries to {bd}")
        return ind


# ----------------------------------------------------------------- monitor
class DnsMonitor:
    def __init__(self, use_eventlog: bool = True, use_cache: bool = True, reverse_dns: bool = True,
                 per_min_threshold: int = 60, unique_sub_threshold: int = 60):
        self.use_eventlog, self.use_cache, self.reverse_dns = use_eventlog, use_cache, reverse_dns
        self.ip_domains: dict[str, dict[str, float]] = defaultdict(dict)  # ip -> {domain: last_seen}
        self.domain_ips: dict[str, set] = defaultdict(set)
        self.rdns: dict[str, str] = {}
        self.recent: deque[DnsObservation] = deque(maxlen=3000)
        self.rate = DnsRateTracker(per_min_threshold, unique_sub_threshold)
        self.eventlog_status = "not checked"
        self.cache_status = "not checked"
        self._last_record_id = 0
        self._lock = threading.RLock()
        self._rdns_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rdns")
        self._rdns_pending: set[str] = set()

    # ------------------------------------------------------------ ingest
    def ingest(self, obs: DnsObservation) -> DnsObservation:
        obs.indicators = name_indicators(obs.name) + self.rate.add(obs.name, obs.qtype, obs.ts)
        with self._lock:
            for ip in obs.answers:
                self.ip_domains[ip][obs.name] = obs.ts
                self.domain_ips[obs.name].add(ip)
            self.recent.append(obs)
        return obs

    def domains_for(self, ip: str) -> list[str]:
        with self._lock:
            d = self.ip_domains.get(ip)
            return sorted(d, key=d.get, reverse=True) if d else []

    def domain_for(self, ip: str) -> str:
        ds = self.domains_for(ip)
        return ds[0] if ds else self.rdns.get(ip, "")

    # ----------------------------------------------------------- sources
    def poll_eventlog(self) -> list[DnsObservation]:
        if not self.use_eventlog or not windows_api.IS_WINDOWS:
            self.eventlog_status = "disabled" if not self.use_eventlog else "Windows only"
            return []
        enabled = windows_api.evt_log_enabled(windows_api.DNS_LOG)
        if enabled is False:
            self.eventlog_status = "log disabled in Windows (enable in Settings; needs Administrator)"
            return []
        if self._last_record_id:
            xpath = f"*[System[(EventID=3008) and (EventRecordID > {self._last_record_id})]]"
        else:
            xpath = "*[System[(EventID=3008) and TimeCreated[timediff(@SystemTime) <= 120000]]]"
        try:
            events = parse_dns_client_events(windows_api.evt_query_xml(windows_api.DNS_LOG, xpath, 2000))
        except Exception as e:
            self.eventlog_status = f"query failed: {e}"
            return []
        self.eventlog_status = "active"
        out = []
        for ev in sorted(events, key=lambda e: e["record_id"]):
            self._last_record_id = max(self._last_record_id, ev["record_id"])
            if not ev["name"]:
                continue
            out.append(self.ingest(DnsObservation(ts=ev["ts"], name=ev["name"], qtype=ev["qtype"],
                                                  answers=ev["answers"], pid=ev["pid"],
                                                  source="dns-client-log")))
        return out

    def poll_cache(self) -> int:
        if not self.use_cache or not windows_api.IS_WINDOWS:
            self.cache_status = "disabled" if not self.use_cache else "Windows only"
            return 0
        recs = windows_api.get_dns_cache()
        now = time.time()
        n = 0
        with self._lock:
            for r in recs:
                if r["type"] in (1, 28) and parse_ip(r["data"]):
                    if r["name"] not in self.ip_domains[r["data"]]:
                        n += 1
                    self.ip_domains[r["data"]][r["name"]] = now
                    self.domain_ips[r["name"]].add(r["data"])
        self.cache_status = f"active ({len(recs)} cached records)"
        return n

    def request_rdns(self, ip: str, callback: Callable[[str, str], None] | None = None) -> None:
        if not self.reverse_dns or ip in self.rdns or ip in self._rdns_pending:
            return
        self._rdns_pending.add(ip)

        def work():
            try:
                name = socket.gethostbyaddr(ip)[0].lower()
            except (OSError, UnicodeError):
                name = ""
            self.rdns[ip] = name
            self._rdns_pending.discard(ip)
            if callback:
                callback(ip, name)
        self._rdns_pool.submit(work)

    def shutdown(self) -> None:
        self._rdns_pool.shutdown(wait=False, cancel_futures=True)
