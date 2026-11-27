"""Integration tests with controlled local connections and simulated events."""
import os
import socket
import threading
import time

from core.config import Config
from core.models import PrivacyEvent
from core.network_monitor import NetworkMonitor
from core.process_monitor import ProcessMonitor
from core.reports import export_report
from database.db_manager import DatabaseManager
from utils.helpers import DestClass
from utils.windows_api import SignatureInfo


def _local_pair():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    accepted = []
    t = threading.Thread(target=lambda: accepted.append(srv.accept()[0]), daemon=True)
    t.start()
    cli = socket.create_connection(("127.0.0.1", port))
    t.join(2)
    return srv, cli, accepted[0], port


def test_tcp_detection_direction_and_process_attribution():
    srv, cli, acc, port = _local_pair()
    try:
        pm = ProcessMonitor(signature_checker=lambda paths: {p: SignatureInfo("valid") for p in paths})
        nm = NetworkMonitor()
        new, _closed, cur = nm.poll(lambda pid: (pm.get(pid).name, pm.get(pid).exe))
        mine = [c for c in cur.values() if c.pid == os.getpid() and port in (c.lport, c.rport)]
        out = [c for c in mine if c.rport == port]
        inb = [c for c in mine if c.lport == port]
        assert out and out[0].direction == "outbound" and out[0].dest_class == DestClass.LOOPBACK
        assert inb and inb[0].direction == "inbound"
        assert out[0].exe and out[0].process_name != "unknown"
        cli.close()
        acc.close()
        time.sleep(0.2)
        _new, closed, _cur = nm.poll(lambda pid: ("x", ""))
        assert any(c.uid == out[0].uid for c in closed)
        pm.stop()
    finally:
        srv.close()


def test_repeated_connection_counter():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    nm = NetworkMonitor()
    counts = []
    for _ in range(2):
        c = socket.create_connection(("127.0.0.1", port))
        a, _ = srv.accept()
        _n, _cl, cur = nm.poll(lambda pid: ("me", "/me"))
        counts += [x.repeat_count for x in cur.values() if x.rport == port and x.pid == os.getpid()]
        c.close()
        a.close()
        time.sleep(0.1)
        nm.poll(lambda pid: ("me", "/me"))
    srv.close()
    assert counts[:1] == [0] and max(counts) >= 1


def test_database_logging_migrations_and_reports(tmp_path):
    db = DatabaseManager(tmp_path / "t.db")
    assert db.schema_version() == 2
    db.start_session(False, {})
    from core.models import Connection
    from core.risk_engine import RiskContext, RiskEngine, build_alert
    c = Connection(uid="u1", pid=1, proto="TCP", family=4, laddr="10.0.0.2", lport=5000, raddr="198.51.100.5",
                   rport=443, state="ESTABLISHED", direction="outbound", dest_class="public",
                   first_seen=time.time(), last_seen=time.time(), process_name="app.exe", exe=r"C:\app.exe")
    db.insert_connection(c)
    db.upsert_destination("198.51.100.5", time.time(), "public", domains=["x.example"], app="app.exe")
    db.insert_privacy_event(PrivacyEvent(ts=time.time(), capability="microphone", event_type="access_started",
                                         app_id=r"C:\app.exe", app_kind="desktop", scope="user", start_ts=time.time()))
    a = RiskEngine().assess(RiskContext(exe="app.exe", sig_status="unsigned", remote_ip="198.51.100.5",
                                        remote_port=6667, dest_class="public"))
    db.upsert_alert(build_alert("network", "Test alert", a, process_name="app.exe", destination="198.51.100.5:6667"))
    db.flush()
    assert db.search_connections("app.exe")[0]["uid"] == "u1"
    assert db.destination_seen_before("198.51.100.5")
    assert db.alerts()[0]["evidence"]
    for kind in ("alerts", "connections", "privacy", "full"):
        for fmt in ("csv", "json"):
            p = export_report(db, kind, fmt, path=tmp_path / f"r-{kind}.{fmt}")
            assert p.stat().st_size > 20
    txt = (tmp_path / "r-full.json").read_text()
    assert "Test alert" in txt and "payload" in txt.lower()   # metadata-only note present
    db.cleanup(1)
    db.close()


def test_service_end_to_end_with_simulated_privacy_event(tmp_path):
    from core.monitor_service import MonitorService
    cfg = Config(tmp_path / "s.json")
    cfg.set("monitoring.connection_interval_sec", 0.25)
    cfg.set("correlation.window_after_sec", 1)
    cfg.set("alerts.min_severity", "informational")
    svc = MonitorService(cfg, DatabaseManager(tmp_path / "svc.db"))
    svc.start()
    try:
        srv, cli, acc, port = _local_pair()
        time.sleep(1.0)
        assert any(c.pid == os.getpid() for c in svc.connections())
        assert svc.overview()["active"] >= 2
        assert svc.investigate_process(os.getpid())["info"].pid == os.getpid()
        # simulated correlation: our own process "accessed the mic", then a public connection appears
        me = svc.procmon.get(os.getpid())
        now = time.time()
        svc.correlation.add_privacy_event(PrivacyEvent(ts=now, capability="microphone", event_type="access_started",
                                                       app_id=me.exe, app_kind="desktop", scope="user",
                                                       start_ts=now, display_name=me.name))
        from core.models import Connection
        fake = Connection(uid="sim", pid=os.getpid(), proto="TCP", family=4, laddr="10.0.0.2", lport=1,
                          raddr="198.51.100.20", rport=443, state="ESTABLISHED", direction="outbound",
                          dest_class=DestClass.PUBLIC, first_seen=now + 0.2, last_seen=now + 0.2,
                          process_name=me.name, exe=me.exe)
        svc.correlation.add_connection(fake)
        time.sleep(2.0)
        titles = [a.title for a in svc.recent_alerts]
        assert "Privacy correlation detected" in titles
        alert = next(a for a in svc.recent_alerts if a.category == "privacy-correlation")
        assert "PRIVACY CORRELATION DETECTED" in alert.what and "not proof" in alert.uncertainty
        assert "Not measured" in alert.what   # no admin traffic source here -> stated honestly
        cli.close(); acc.close(); srv.close()
        caps = {c.name: c.status for c in svc.capabilities()}
        assert caps["Connection monitoring"] == "active"
    finally:
        svc.shutdown()
