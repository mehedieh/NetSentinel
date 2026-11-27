"""MonitorService: owns every monitoring component and background worker.

The GUI never calls monitoring code on its own thread; it reads thread-safe snapshots
from this service and drains ``self.events`` (a bounded queue) on a Tk timer.
Monitoring continues independently of which page is displayed.
"""
from __future__ import annotations

import logging
import queue
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

import psutil

from core.config import Config
from core.correlation_engine import CorrelationEngine
from core.dns_monitor import DnsMonitor, name_indicators
from core.firewall import FirewallManager
from core.models import CapabilityStatus, Connection, DnsObservation, PrivacyEvent
from core.network_monitor import InterfaceCounters, NetworkMonitor, local_addresses
from core.packet_analyzer import PacketCapture, scapy_status
from core.privacy_monitor import CAPABILITIES, PrivacyMonitor, resolve_pids
from core.process_monitor import ProcessMonitor
from core.risk_engine import (Alert, AlertManager, Assessment, Factor, RiskContext, RiskEngine,
                              build_alert, level_for, level_rank)
from core.threat_intelligence import ThreatIntel
from core.traffic_analyzer import BeaconDetector, TrafficTracker, long_lived
from database.db_manager import DatabaseManager
from utils import windows_api
from utils.helpers import DestClass, base_domain, exe_basename, fmt_bytes, fmt_ts
from utils.permissions import is_admin

log = logging.getLogger(__name__)


class _PsutilProc:
    __slots__ = ("pid", "exe")

    def __init__(self, pid, exe):
        self.pid, self.exe = pid, exe or ""


class MonitorService:
    def __init__(self, config: Config, db: DatabaseManager | None = None):
        self.config = config
        self.db = db or DatabaseManager()
        self.is_admin = is_admin()
        self.events: "queue.Queue[tuple[str, object]]" = queue.Queue(maxsize=5000)
        self.risk = RiskEngine()
        self.alert_mgr = AlertManager(config.get("alerts.dedup_minutes") * 60, config.get("alerts.min_severity"))
        self.procmon = ProcessMonitor(store_usernames=config.get("privacy.store_usernames"),
                                      on_signature=self._on_signature)
        self.netmon = NetworkMonitor()
        self.iface = InterfaceCounters(config.get("capture.interface"))
        th = lambda k: config.get(f"thresholds.{k}")  # noqa: E731
        self.tracker = TrafficTracker(th("upload_spike_mb_per_min"), th("spike_factor"))
        self.beacons = BeaconDetector(th("beacon_min_events"), th("beacon_max_cv"))
        self.dns = DnsMonitor(config.get("dns.read_dns_client_log"), config.get("dns.read_dns_cache"),
                              config.get("dns.reverse_dns"), th("dns_queries_per_min_per_domain"),
                              th("dns_unique_subdomains_5min"))
        self.privacy = PrivacyMonitor(include_other_users=self.is_admin, pid_resolver=self._resolve_privacy_pids)
        self.correlation = CorrelationEngine(config.get("correlation.window_before_sec"),
                                             config.get("correlation.window_after_sec"),
                                             config.get("correlation.expected_apps"),
                                             upload_lookup=self.tracker.bytes_between)
        self.ti = ThreatIntel(config, cache_get=self.db.get_ti, cache_put=self.db.put_ti)
        self.firewall = FirewallManager(self.db)
        self.estats = windows_api.TcpEStats() if config.get("capture.enable_estats") else None
        if self.estats and self.estats.available and not self.is_admin:
            self.estats.available, self.estats.reason = False, "Administrator rights required"
        self.pcap: Optional[PacketCapture] = None

        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._bg = ThreadPoolExecutor(max_workers=3, thread_name_prefix="svc-bg")
        self.running = False
        self.started_at: Optional[float] = None
        self.component_errors: dict[str, str] = {}
        self._meta: dict[str, dict] = {}             # conn uid -> {"new_dest": bool}
        self._alerted: set[str] = set()
        self._known_dests: set[str] = set()
        self._rate: dict[str, deque] = defaultdict(deque)
        self._logged_pids: set[tuple] = set()
        self._beacon_flagged: dict[tuple, float] = {}
        self._ti_inflight: set[str] = set()
        self.recent_alerts: deque[Alert] = deque(maxlen=1000)
        self.recent_privacy: deque[PrivacyEvent] = deque(maxlen=1000)
        self.counters = {"connections_seen": 0, "alerts": 0, "privacy_events": 0, "dns_queries": 0}
        self._last = defaultdict(float)
        self._lock = threading.RLock()

    # ============================================================ lifecycle
    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self.started_at = time.time()
        self.db.start_session(self.is_admin, {c.name: c.status for c in self.capabilities()})
        mi = lambda k: self.config.get(f"monitoring.{k}")  # noqa: E731
        loops = [("network", mi("connection_interval_sec"), self._network_tick),
                 ("privacy", mi("privacy_interval_sec"), self._privacy_tick),
                 ("dns-log", mi("dns_eventlog_interval_sec"), self._dns_log_tick),
                 ("dns-cache", mi("dns_cache_interval_sec"), self._dns_cache_tick),
                 ("maintenance", 30, self._maintenance_tick)]
        for name, interval, fn in loops:
            t = threading.Thread(target=self._loop, args=(name, float(interval), fn), name=f"mon-{name}", daemon=True)
            t.start()
            self._threads.append(t)
        if self.config.get("capture.enable_packet_capture"):
            self.pcap = PacketCapture(local_addresses(), self._on_pcap_bytes, self._on_pcap_dns,
                                      self.config.get("capture.interface"),
                                      count_tcp=not (self.estats and self.estats.available))
            if not self.pcap.start():
                log.warning("Packet capture unavailable: %s", self.pcap.error)
        self.running = True
        self.publish("status", "started")
        log.info("Monitoring started (admin=%s)", self.is_admin)

    def stop(self) -> None:
        if not self.running:
            return
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)
        self._threads.clear()
        if self.pcap:
            self.pcap.stop()
        try:
            self.db.add_traffic_rows(self.tracker.drain_hourly())
            for c in self.netmon.snapshot():
                self.db.update_connection(c)
            self.db.end_session()
        except Exception:
            log.exception("Error while flushing on stop")
        self.running = False
        self.publish("status", "stopped")
        log.info("Monitoring stopped")

    def shutdown(self) -> None:
        self.stop()
        self.procmon.stop()
        self.dns.shutdown()
        self._bg.shutdown(wait=False, cancel_futures=True)
        self.db.close()

    def _loop(self, name: str, interval: float, fn: Callable[[], None]) -> None:
        backoff = interval
        while not self._stop.is_set():
            t0 = time.time()
            try:
                fn()
                if name in self.component_errors:
                    log.info("%s recovered", name)
                self.component_errors.pop(name, None)
                backoff = interval
            except Exception as e:
                self.component_errors[name] = f"{type(e).__name__}: {e}"
                log.exception("%s tick failed", name)
                backoff = min(max(interval, 1) * 2, 30, backoff * 2)
            wait = backoff if name in self.component_errors else max(0.05, interval - (time.time() - t0))
            self._stop.wait(wait)

    def publish(self, topic: str, payload: object = None) -> None:
        try:
            self.events.put_nowait((topic, payload))
        except queue.Full:
            try:
                self.events.get_nowait()
                self.events.put_nowait((topic, payload))
            except queue.Empty:
                pass

    # ============================================================ network
    def _name_for_pid(self, pid: int) -> tuple[str, str]:
        info = self.procmon.get(pid)
        return info.name, info.exe

    def _network_tick(self) -> None:
        now = time.time()
        new, closed, current = self.netmon.poll(self._name_for_pid)
        if self.estats and self.estats.available:
            for c in current.values():
                if c.proto == "TCP" and c.raddr and c.dest_class != DestClass.LOOPBACK:
                    r = self.estats.read(c.laddr, c.lport, c.raddr, c.rport, c.state)
                    if r:
                        self.tracker.update_cumulative(c, r[0], r[1], "estats", now)
        for c in new:
            self.counters["connections_seen"] += 1
            self._on_new_connection(c, now)
        for c in closed:
            self._on_closed(c)
        for c in current.values():
            if c.risk_pending:
                self._evaluate(c)
        for spike in self.tracker.check_spikes(now):
            self._spike_alert(spike)
        if now - self._last["beacon"] > 30:
            self._last["beacon"] = now
            self._beacon_check(now)
        for res in self.correlation.evaluate(now):
            self._correlation_alert(res)
        d_sent, d_recv = self.iface.sample()
        self.db.add_interface_bytes(now, d_sent, d_recv)
        self.publish("tick", now)

    def _on_new_connection(self, c: Connection, now: float) -> None:
        info = self.procmon.get(c.pid)
        pkey = (c.pid, info.create_time)
        if pkey not in self._logged_pids:
            self._logged_pids.add(pkey)
            self.db.upsert_process(info)
        new_dest = False
        if c.raddr:
            c.domain = self.dns.domain_for(c.raddr)
        if c.dest_class == DestClass.PUBLIC:
            if c.raddr not in self._known_dests:
                new_dest = not self.db.destination_seen_before(c.raddr)
                self._known_dests.add(c.raddr)
                self.dns.request_rdns(c.raddr, self._on_rdns)
            self.db.upsert_destination(c.raddr, now, c.dest_class, self.dns.rdns.get(c.raddr, ""),
                                       self.dns.domains_for(c.raddr)[:10], exe_basename(c.exe) or c.process_name)
            if c.direction == "outbound":
                self.beacons.record(c.exe, c.process_name, c.raddr, c.rport, now)
                dq = self._rate[c.exe or c.process_name]
                dq.append(now)
                while dq and dq[0] < now - 60:
                    dq.popleft()
            self.correlation.add_connection(c)
            self._maybe_auto_ti(c.raddr)
        self._meta[c.uid] = {"new_dest": new_dest}
        self._evaluate(c)
        self.db.insert_connection(c)
        self.publish("connection", c)

    def _on_closed(self, c: Connection) -> None:
        self.tracker.forget(c)
        if self.estats:
            self.estats.forget(c.laddr, c.lport, c.raddr, c.rport)
        self._meta.pop(c.uid, None)
        self._alerted.discard(c.uid)
        self.db.update_connection(c)

    def _context_for(self, c: Connection) -> RiskContext:
        info = self.procmon.get(c.pid)
        meta = self._meta.get(c.uid, {})
        ctx = RiskContext(exe=info.exe or c.exe, process_name=info.name, sig_status=info.sig_status,
                          publisher=info.publisher, suspicious_dir=info.suspicious_dir, has_window=info.has_window,
                          remote_ip=c.raddr, remote_port=c.rport, proto=c.proto, dest_class=c.dest_class,
                          domain=c.domain, new_destination=meta.get("new_dest", False),
                          expected_app=exe_basename(info.exe or c.exe) in self.correlation.expected_apps)
        if c.raddr:
            ctx.blocklist_match = self.ti.blocklist.match_ip(c.raddr) or self.ti.blocklist.match_domain(c.domain)
            verdict, src, detail = self.ti.combine(self.ti.cached(c.raddr))
            if verdict in ("malicious", "suspicious"):
                ctx.ti_verdict, ctx.ti_source, ctx.ti_detail = verdict, src, detail
        if c.direction == "outbound" and c.dest_class == DestClass.PUBLIC:
            ctx.conn_rate = len(self._rate.get(c.exe or c.process_name, ()))
            ctx.conn_rate_threshold = self.config.get("thresholds.new_conn_per_min")
        if c.domain:
            ctx.dns_indicators = name_indicators(c.domain)
        return ctx

    def _evaluate(self, c: Connection) -> None:
        ctx = self._context_for(c)
        a = self.risk.assess(ctx)
        c.risk_score, c.risk_level = a.score, a.level
        c.risk_pending = ctx.sig_status == "pending" and time.time() - c.first_seen < 45
        if c.risk_pending or c.uid in self._alerted:
            return
        if not any(f.points >= 10 for f in a.factors) or a.level == "informational":
            return
        self._alerted.add(c.uid)
        top = max((f for f in a.factors if f.points > 0), key=lambda f: f.points)
        title = {"ti_malicious": "Connection to a known-malicious destination",
                 "blocklist": "Connection to a blocklisted destination",
                 "sig_tampered": "Executable with a broken signature is communicating",
                 "suspicious_dir": "Program in an unusual folder is communicating externally",
                 "conn_rate": "Unusually frequent outbound connections",
                 "dns_tunnel": "Connection to a suspicious-looking domain"}.get(top.code, "Unusual network activity")
        what = (f"{ctx.process_name} (PID {c.pid}) opened a {c.proto} {c.direction} connection to "
                f"{c.remote}{f' ({c.domain})' if c.domain else ''} at {fmt_ts(c.first_seen)}.")
        alert = build_alert("network", title, a, process_name=ctx.process_name, pid=c.pid, exe=ctx.exe,
                            destination=c.remote + (f" ({c.domain})" if c.domain else ""), what=what,
                            extra_evidence=[f"Connection state: {c.state}; destination class: {c.dest_class}",
                                            "Observation = socket seen in the Windows connection table; "
                                            "it does not by itself show how much data was transferred."],
                            dedup_parts=(c.raddr, top.code), ts=c.first_seen)
        self._submit_alert(alert)

    def _on_signature(self, path: str, sig) -> None:
        for info in self.procmon.all_cached():
            if info.exe and info.exe.lower() == path.lower():
                self.db.upsert_process(info)

    def _on_rdns(self, ip: str, name: str) -> None:
        if name:
            self.db.upsert_destination(ip, time.time(), DestClass.PUBLIC, rdns=name)
            for c in self.netmon.snapshot():
                if c.raddr == ip and not c.domain:
                    c.domain = name

    # ------------------------------------------------------ traffic alerts
    def _spike_alert(self, spike: dict) -> None:
        info_name = spike["name"] or exe_basename(spike["exe"])
        sig = self.procmon.cached_signature(spike["exe"]) if spike["exe"] else None
        ctx = RiskContext(exe=spike["exe"], process_name=info_name, sig_status=sig.status if sig else "",
                          publisher=sig.publisher if sig else "", dest_class=DestClass.PUBLIC,
                          upload_spike={"bytes": spike["bytes"], "baseline": spike["baseline"]},
                          expected_app=exe_basename(spike["exe"]) in self.correlation.expected_apps)
        a = self.risk.assess(ctx)
        alert = build_alert("traffic", "Unusual upload volume", a, process_name=info_name, exe=spike["exe"],
                            what=f"{info_name} uploaded {fmt_bytes(spike['bytes'])} in the minute starting "
                                 f"{fmt_ts(spike['minute'])}.",
                            extra_evidence=[f"Measurement: {', '.join(sorted(self.tracker.sources_active))}"],
                            dedup_parts=("spike",))
        self._submit_alert(alert)

    def _beacon_check(self, now: float) -> None:
        for b in self.beacons.analyze():
            key = (b.exe, b.raddr, b.rport)
            if now - self._beacon_flagged.get(key, 0) < 3600:
                continue
            self._beacon_flagged[key] = now
            sig = self.procmon.cached_signature(b.exe) if b.exe else None
            domain = self.dns.domain_for(b.raddr)
            ctx = RiskContext(exe=b.exe, process_name=b.process_name, sig_status=sig.status if sig else "",
                              publisher=sig.publisher if sig else "", remote_ip=b.raddr, remote_port=b.rport,
                              dest_class=DestClass.PUBLIC, domain=domain, beacon=b.as_dict())
            ctx.blocklist_match = self.ti.blocklist.match_ip(b.raddr)
            a = self.risk.assess(ctx)
            alert = build_alert("beaconing", "Periodic connection pattern (possible beaconing)", a,
                                process_name=b.process_name, exe=b.exe,
                                destination=f"{b.raddr}:{b.rport}" + (f" ({domain})" if domain else ""),
                                what=f"{b.process_name} reconnected to {b.raddr}:{b.rport} {b.count} times at "
                                     f"~{b.mean_interval:.0f}s intervals between {fmt_ts(b.first)} and {fmt_ts(b.last)}.",
                                dedup_parts=(b.raddr, b.rport))
            self._submit_alert(alert)

    # ============================================================ privacy
    def _resolve_privacy_pids(self, record) -> list[int]:
        procs = []
        for p in psutil.process_iter(["pid", "exe"]):
            try:
                procs.append(_PsutilProc(p.info["pid"], p.info.get("exe")))
            except Exception:
                continue
        return resolve_pids(record, procs)

    def _privacy_tick(self) -> None:
        for ev in self.privacy.poll():
            self.counters["privacy_events"] += 1
            self.recent_privacy.append(ev)
            self.db.insert_privacy_event(ev)
            self.correlation.add_privacy_event(ev)
            self.publish("privacy", ev)
            if ev.event_type in ("access_started", "access_session"):
                self._privacy_access_alert(ev)

    def _privacy_access_alert(self, ev: PrivacyEvent) -> None:
        """Flag device access by unsigned / unusually located desktop programs."""
        if ev.app_kind != "desktop":
            return
        from utils.helpers import suspicious_location
        sig = self.procmon.cached_signature(ev.app_id)
        if sig is None:
            sig = windows_api.check_signatures([ev.app_id]).get(ev.app_id) if windows_api.IS_WINDOWS else None
        f = []
        label = CAPABILITIES.get(ev.capability, ev.capability)
        if sig and sig.status in ("unsigned", "tampered", "untrusted"):
            f.append(Factor("unsigned" if sig.status == "unsigned" else "sig_tampered" if sig.status == "tampered"
                            else "sig_untrusted", f"{label} used by a program whose signature is {sig.status}",
                            15 if sig.status == "unsigned" else 30, ev.app_id))
        loc = suspicious_location(ev.app_id)
        if loc:
            f.append(Factor("suspicious_dir", f"{label} used by a program in the {loc}", 20, ev.app_id))
        if not f:
            return
        score = sum(x.points for x in f)
        a = Assessment(score, level_for(score, False), f)
        alert = build_alert("privacy", f"{label} accessed by an unverified program", a,
                            process_name=ev.display_name, exe=ev.app_id,
                            what=f"Windows recorded {label.lower()} access by {ev.display_name} starting "
                                 f"{fmt_ts(ev.start_ts, True)}.",
                            extra_evidence=[f"Source: CapabilityAccessManager ConsentStore ({ev.scope})",
                                            f"Permission value: {ev.permission or 'not set'}"],
                            extra_uncertainty="Windows confirms the device was opened; it does not show what was recorded.",
                            dedup_parts=(ev.capability,), ts=ev.start_ts or ev.ts)
        self._submit_alert(alert)

    def _correlation_alert(self, res) -> None:
        first = min(res.connections, key=lambda c: c.first_seen)
        info = self.procmon.get(first.pid)
        thr = self.config.get("thresholds.correlation_upload_mb") * 1024 * 1024
        big = res.upload_measured and (res.upload_bytes or 0) >= thr
        ctx = RiskContext(exe=info.exe or first.exe, process_name=info.name, sig_status=info.sig_status,
                          publisher=info.publisher, suspicious_dir=info.suspicious_dir, remote_ip=first.raddr,
                          remote_port=first.rport, proto=first.proto, dest_class=first.dest_class,
                          domain=first.domain, expected_app=res.expected_app,
                          privacy_correlation={"capability_label": res.capability_label, "summary": res.summary()},
                          upload_spike={"bytes": res.upload_bytes, "baseline": 0} if big else None)
        ctx.blocklist_match = self.ti.blocklist.match_ip(first.raddr) or self.ti.blocklist.match_domain(first.domain)
        verdict, src, detail = self.ti.combine(self.ti.cached(first.raddr))
        if verdict in ("malicious", "suspicious"):
            ctx.ti_verdict, ctx.ti_source, ctx.ti_detail = verdict, src, detail
        a = self.risk.assess(ctx)
        if res.upload_measured:
            traffic = f"{fmt_bytes(res.upload_bytes)} uploaded by this app during the observation window ({res.measure_note})"
        else:
            traffic = f"Not measured — {res.measure_note}"
        assessment = ("Expected: this is a known communication/browser app." if res.expected_app
                      else "Requires investigation.")
        what = "\n".join([
            "PRIVACY CORRELATION DETECTED",
            f"Application: {info.name} ({ctx.exe or res.app_id})",
            f"{res.capability_label} activity: Observed at {fmt_ts(res.privacy_ts)}",
            f"Outbound connection: Observed at {fmt_ts(first.first_seen)}",
            f"Destination: {first.remote}{f' ({first.domain})' if first.domain else ''}",
            f"Traffic: {traffic}",
            f"Assessment: {assessment}"])
        ev_lines = [f"{c.remote} ({c.proto}) first seen {fmt_ts(c.first_seen)}" for c in res.connections[:10]]
        alert = build_alert("privacy-correlation", "Privacy correlation detected", a, process_name=info.name,
                            pid=first.pid, exe=ctx.exe, destination=first.remote, what=what,
                            extra_evidence=[f"Correlation window: {fmt_ts(res.window_start)} – {fmt_ts(res.window_end)}"] + ev_lines,
                            extra_uncertainty=("A temporal correlation is not proof that microphone or camera "
                                               "content was transmitted. Encrypted traffic contents are not, and "
                                               "cannot be, inspected. Connection times are poll-based (± one interval)."),
                            dedup_parts=(res.capability, first.raddr), ts=first.first_seen)
        self._submit_alert(alert)

    # ================================================================ DNS
    def _dns_log_tick(self) -> None:
        for o in self.dns.poll_eventlog():
            self._handle_dns(o)

    def _dns_cache_tick(self) -> None:
        if self.dns.poll_cache():
            for c in self.netmon.snapshot():
                if c.raddr and not c.domain:
                    c.domain = self.dns.domain_for(c.raddr)

    def _handle_dns(self, o: DnsObservation) -> None:
        self.counters["dns_queries"] += 1
        if o.pid and not o.process_name:
            try:
                o.process_name = psutil.Process(o.pid).name()
            except (psutil.Error, OSError):
                o.process_name = ""
        self.db.insert_dns(o)
        self.publish("dns", o)
        if o.indicators:
            ctx = RiskContext(process_name=o.process_name, domain=o.name, dns_indicators=o.indicators,
                              dest_class=DestClass.PUBLIC)
            ctx.blocklist_match = self.ti.blocklist.match_domain(o.name)
            a = self.risk.assess(ctx)
            alert = build_alert("dns", "Suspicious DNS activity", a, process_name=o.process_name or "unknown",
                                pid=o.pid, destination=o.name,
                                what=f"DNS {o.qtype} query for {o.name} observed via {o.source} at {fmt_ts(o.ts)}.",
                                extra_uncertainty=("Process attribution for DNS is best-effort: the PID in DNS "
                                                   "Client events can be the DNS Client service."),
                                dedup_parts=(base_domain(o.name),), ts=o.ts)
            self._submit_alert(alert)

    def _on_pcap_dns(self, o: DnsObservation) -> None:
        self._handle_dns(self.dns.ingest(o))

    def _on_pcap_bytes(self, proto, lport, raddr, rport, d_out, d_in) -> None:
        conn = self.netmon.lookup_by_tuple(proto, lport, raddr, rport)
        if conn is None and proto == "UDP":
            conn = self.netmon.lookup_by_tuple(proto, lport)
        if conn is not None:
            self.tracker.add_delta(conn, conn.exe, conn.process_name, raddr, proto, d_out, d_in, "pcap")
            return
        pid = self.netmon.listener_pid(proto, lport)
        if pid is not None:
            info = self.procmon.get(pid)
            self.tracker.add_delta(None, info.exe, info.name, raddr, proto, d_out, d_in, "pcap")
        else:
            self.tracker.add_delta(None, "", "(unattributed)", raddr, proto, d_out, d_in, "pcap")

    # ===================================================== threat intel
    def _maybe_auto_ti(self, ip: str) -> None:
        if self.config.get("threat_intel.mode") != "auto" or not self.config.get("threat_intel.auto_consent"):
            return
        if ip in self._ti_inflight or self.ti.cached(ip) or not self.ti.configured_providers():
            return
        self._ti_inflight.add(ip)
        self._bg.submit(self._ti_job, ip, False)

    def _ti_job(self, ind: str, user: bool):
        try:
            res = self.ti.lookup(ind, user_initiated=user)
        finally:
            self._ti_inflight.discard(ind)
        verdict, _s, _d = self.ti.combine(res)
        if verdict in ("malicious", "suspicious"):
            for c in self.netmon.snapshot():
                if c.raddr == ind:
                    self._alerted.discard(c.uid)
                    self._evaluate(c)
        self.publish("ti", (ind, res))
        return res

    def lookup_indicator(self, ind: str, callback: Callable | None = None) -> None:
        """User-initiated lookup (runs in background, result via callback and 'ti' event)."""
        fut = self._bg.submit(self._ti_job, ind.strip(), True)
        if callback:
            fut.add_done_callback(lambda f: callback(f.result() if not f.exception() else []))

    # ======================================================== maintenance
    def _maintenance_tick(self) -> None:
        now = time.time()
        self.db.add_traffic_rows(self.tracker.drain_hourly())
        if now - self._last["conn_update"] > 60:
            self._last["conn_update"] = now
            for c in self.netmon.snapshot():
                if c.dest_class != DestClass.LOOPBACK:
                    self.db.update_connection(c)
        self.procmon.prune()
        hours = self.config.get("retention.cleanup_interval_hours")
        if now - self._last["cleanup"] > hours * 3600:
            self._last["cleanup"] = now
            self.db.cleanup(self.config.get("retention.days"))
        if len(self._known_dests) > 200000:
            self._known_dests.clear()

    def _submit_alert(self, alert: Alert) -> None:
        a, is_new = self.alert_mgr.submit(alert)
        if a is None:
            return
        self.db.upsert_alert(a)
        if is_new:
            self.counters["alerts"] += 1
            self.recent_alerts.appendleft(a)
            self.publish("alert", a)

    # =================================================== GUI snapshots
    def connections(self) -> list[Connection]:
        return self.netmon.snapshot()

    def listeners(self) -> list[dict]:
        out = []
        for v in list(self.netmon.listeners.values()):
            info = self.procmon.get(v["pid"])
            out.append({**v, "process_name": info.name, "exe": info.exe})
        return out

    def applications(self) -> list[dict]:
        apps: dict[int, dict] = {}
        for c in self.netmon.snapshot():
            a = apps.get(c.pid)
            if a is None:
                info = self.procmon.get(c.pid)
                a = apps[c.pid] = {"info": info, "connections": 0, "external": 0, "destinations": set(),
                                   "max_level": "informational", "max_score": 0}
            a["connections"] += 1
            if c.dest_class == DestClass.PUBLIC:
                a["external"] += 1
                a["destinations"].add(c.domain or c.raddr)
            if c.risk_score > a["max_score"]:
                a["max_score"], a["max_level"] = c.risk_score, c.risk_level
        out = []
        for pid, a in apps.items():
            info = a["info"]
            tot = self.tracker.app_totals(info.exe or info.name)
            out.append({**info.to_dict(), "connections": a["connections"], "external": a["external"],
                        "destinations": sorted(a["destinations"]), "risk_level": a["max_level"],
                        "risk_score": a["max_score"], "bytes_out": tot[0] if tot else None,
                        "bytes_in": tot[1] if tot else None})
        return sorted(out, key=lambda x: (-level_rank(x["risk_level"]), -x["external"]))

    def overview(self) -> dict:
        conns = self.netmon.snapshot()
        states, _recs = self.privacy.snapshot()
        att_out, att_in = self.tracker.totals()
        return {
            "running": self.running, "admin": self.is_admin, "started_at": self.started_at,
            "active": len(conns), "external": sum(c.dest_class == DestClass.PUBLIC for c in conns),
            "suspicious": sum(level_rank(c.risk_level) >= 2 for c in conns),
            "listeners": len(self.netmon.listeners),
            "iface_sent": self.iface.total_sent, "iface_recv": self.iface.total_recv,
            "rate_sent": self.iface.rate_sent, "rate_recv": self.iface.rate_recv,
            "attributed_out": att_out, "attributed_in": att_in,
            "measurement": self.measurement_note(),
            "privacy": states, "alerts_total": self.counters["alerts"],
            "errors": dict(self.component_errors), **self.counters}

    def measurement_note(self) -> str:
        parts = []
        if self.estats and self.estats.available:
            parts.append("TCP per-connection byte counters (since monitoring started)")
        if self.pcap and self.pcap.status == "running":
            parts.append("packet-header capture" + ("" if not (self.estats and self.estats.available) else " for UDP"))
        if not parts:
            return ("Per-application traffic NOT measured (run as Administrator to enable TCP counters). "
                    "Totals shown are system-wide interface counters.")
        return "Per-application traffic: " + " + ".join(parts) + ". UDP/QUIC without capture is not measured."

    def capabilities(self) -> list[CapabilityStatus]:
        caps = []
        err = self.component_errors
        caps.append(CapabilityStatus("Connection monitoring", "degraded" if "network" in err else "active",
                                     err.get("network", "psutil / Windows TCP & UDP tables")))
        caps.append(CapabilityStatus("Process attribution", "active" if self.is_admin else "degraded",
                                     "full" if self.is_admin else "protected/system processes may hide their path",
                                     requires_admin=True))
        caps.append(CapabilityStatus("Code-signing verification",
                                     "active" if windows_api.IS_WINDOWS else "unavailable",
                                     "Get-AuthenticodeSignature (embedded + catalog)" if windows_api.IS_WINDOWS else "Windows only"))
        if self.estats is None:
            caps.append(CapabilityStatus("Per-app TCP traffic (EStats)", "disabled", "turned off in Settings", True))
        else:
            caps.append(CapabilityStatus("Per-app TCP traffic (EStats)", "active" if self.estats.available else "unavailable",
                                         "counts from monitoring start" if self.estats.available else self.estats.reason, True))
        if not self.config.get("capture.enable_packet_capture"):
            ok, msg = scapy_status()
            caps.append(CapabilityStatus("Packet capture (Npcap)", "disabled",
                                         "off in Settings" + ("" if ok else f" — {msg}"), True))
        else:
            st = self.pcap.status if self.pcap else "stopped"
            caps.append(CapabilityStatus("Packet capture (Npcap)", "active" if st == "running" else "unavailable",
                                         (self.pcap.error if self.pcap and self.pcap.error else st), True))
        caps.append(CapabilityStatus("Interface traffic totals", "active", "system-wide, not per app"))
        pst, _ = self.privacy.snapshot()
        mic = pst.get("microphone")
        caps.append(CapabilityStatus("Microphone / camera monitor",
                                     "active" if self.privacy.available and mic and mic.telemetry != "unavailable" else "unavailable",
                                     "CapabilityAccessManager ConsentStore" if self.privacy.available else "Windows only"))
        caps.append(CapabilityStatus("DNS client event log", "active" if self.dns.eventlog_status == "active" else
                                     "disabled" if self.dns.eventlog_status == "disabled" else "unavailable",
                                     self.dns.eventlog_status, True))
        caps.append(CapabilityStatus("DNS cache association", "active" if self.dns.cache_status.startswith("active") else
                                     "disabled" if self.dns.cache_status == "disabled" else "unavailable", self.dns.cache_status))
        provs = self.ti.configured_providers()
        mode = self.config.get("threat_intel.mode")
        caps.append(CapabilityStatus("Threat intelligence", "active" if provs and mode != "off" else "disabled",
                                     f"mode={mode}; providers: {', '.join(provs) or 'none'}; local blocklist entries: "
                                     f"{len(self.ti.blocklist.nets) + len(self.ti.blocklist.domains)}"))
        caps.append(CapabilityStatus("Firewall blocking", "active" if self.is_admin and windows_api.IS_WINDOWS else "unavailable",
                                     "reversible rules via netsh" if self.is_admin else "requires Administrator", True))
        return caps

    def investigate_process(self, pid: int) -> dict:
        info = self.procmon.get(pid)
        conns = [c for c in self.netmon.snapshot() if c.pid == pid]
        tot = self.tracker.app_totals(info.exe or info.name)
        hist = self.db.query_dicts("SELECT raddr, rport, proto, domain, COUNT(*) AS n, MIN(first_seen) AS first, "
                                   "MAX(last_seen) AS last FROM connections WHERE exe=? AND raddr!='' "
                                   "GROUP BY raddr, rport, proto ORDER BY n DESC LIMIT 200",
                                   (info.exe,)) if info.exe else []
        assessments = []
        for c in conns:
            a = self.risk.assess(self._context_for(c))
            if a.factors:
                assessments.append((c, a))
        return {"info": info, "connections": conns, "bytes": tot, "history": hist, "assessments": assessments,
                "measurement": self.measurement_note()}

    def investigate_ip(self, ip: str) -> dict:
        from utils.helpers import classify_ip
        conns = [c for c in self.netmon.snapshot() if c.raddr == ip]
        rows = self.db.query_dicts("SELECT * FROM destinations WHERE ip=?", (ip,))
        hist = self.db.query_dicts("SELECT process_name, exe, rport, proto, COUNT(*) AS n, MIN(first_seen) AS first, "
                                   "MAX(last_seen) AS last FROM connections WHERE raddr=? GROUP BY exe, rport, proto "
                                   "ORDER BY n DESC", (ip,))
        return {"ip": ip, "class": classify_ip(ip), "domains": self.dns.domains_for(ip),
                "rdns": self.dns.rdns.get(ip, ""), "record": rows[0] if rows else None,
                "connections": conns, "history": hist, "ti": self.ti.cached(ip),
                "blocklist": self.ti.blocklist.match_ip(ip), "geo": self.ti.geo(ip)}

    def long_lived(self) -> list[Connection]:
        return long_lived(self.netmon.snapshot(), self.config.get("thresholds.long_lived_minutes"))
