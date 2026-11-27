"""Unit tests for platform-independent logic (simulated events only — no malware needed)."""
import json
import time

import pytest

from core.config import Config
from core.correlation_engine import CorrelationEngine
from core.dns_monitor import DnsRateTracker, name_indicators, parse_dns_client_events
from core.models import Connection, PrivacyEvent
from core.privacy_monitor import PrivacyMonitor, app_matches_exe, read_capability
from core.risk_engine import AlertManager, RiskContext, RiskEngine, build_alert, level_for
from core.threat_intelligence import LocalBlocklist, ThreatIntel
from core.traffic_analyzer import BeaconDetector, TrafficTracker
from utils.helpers import (DestClass, base_domain, classify_ip, epoch_to_filetime, filetime_to_epoch,
                           suspicious_location)
from utils.windows_api import parse_ipconfig_displaydns, parse_signature_json, publisher_from_subject


# ----------------------------------------------------------- classification
@pytest.mark.parametrize("ip,cls", [
    ("127.0.0.1", DestClass.LOOPBACK), ("::1", DestClass.LOOPBACK), ("192.168.1.10", DestClass.PRIVATE),
    ("10.0.0.5", DestClass.PRIVATE), ("100.64.1.1", DestClass.PRIVATE), ("fd00::1", DestClass.PRIVATE),
    ("169.254.3.3", DestClass.LINK_LOCAL), ("fe80::1", DestClass.LINK_LOCAL), ("224.0.0.251", DestClass.MULTICAST),
    ("8.8.8.8", DestClass.PUBLIC), ("2606:4700::1111", DestClass.PUBLIC), ("::ffff:1.1.1.1", DestClass.PUBLIC),
    ("203.0.113.10", DestClass.RESERVED), ("0.0.0.0", DestClass.RESERVED), ("255.255.255.255", DestClass.RESERVED),
    ("not-an-ip", DestClass.UNKNOWN), ("", DestClass.UNKNOWN)])
def test_classify_ip(ip, cls):
    assert classify_ip(ip) == cls


def test_public_ip_alone_is_not_suspicious():
    a = RiskEngine().assess(RiskContext(exe=r"C:\Program Files\App\app.exe", sig_status="valid",
                                        remote_ip="8.8.8.8", remote_port=443, dest_class=DestClass.PUBLIC, proto="TCP"))
    assert a.level == "informational" and a.score == 0


def test_filetime_roundtrip():
    ts = 1_760_000_000.5
    assert abs(filetime_to_epoch(epoch_to_filetime(ts)) - ts) < 1e-3
    assert filetime_to_epoch(0) is None


def test_suspicious_location():
    assert suspicious_location(r"C:\Users\a\AppData\Local\Temp\x\run.exe")
    assert suspicious_location(r"C:\Users\a\Downloads\tool.exe")
    assert suspicious_location(r"C:\Program Files\Mozilla Firefox\firefox.exe") is None
    assert suspicious_location(r"C:\Users\a\AppData\Local\Programs\Microsoft VS Code\Code.exe") is None


def test_base_domain():
    assert base_domain("a.b.example.com") == "example.com"
    assert base_domain("www.bbc.co.uk") == "bbc.co.uk"
    assert base_domain("x.prothomalo.com.bd") == "prothomalo.com.bd"


# --------------------------------------------------------------- risk engine
def test_unsigned_is_low_not_malicious():
    a = RiskEngine().assess(RiskContext(exe=r"C:\Tools\x.exe", sig_status="unsigned", remote_ip="8.8.8.8",
                                        remote_port=443, dest_class=DestClass.PUBLIC))
    assert a.level == "low"


def test_heuristics_capped_at_high_without_verified():
    ctx = RiskContext(exe=r"C:\Users\a\AppData\Local\Temp\x.exe", sig_status="tampered",
                      suspicious_dir="user temporary folder", remote_ip="8.8.8.8", remote_port=4444,
                      dest_class=DestClass.PUBLIC, beacon={"count": 10, "mean_interval": 60, "cv": 0.05})
    a = RiskEngine().assess(ctx)
    assert a.score >= 70 and a.level == "high"
    ctx.blocklist_match = "8.8.8.8/32"
    assert RiskEngine().assess(ctx).level == "critical"


def test_every_alert_has_five_sections():
    a = RiskEngine().assess(RiskContext(exe="x.exe", sig_status="unsigned", remote_ip="8.8.8.8", remote_port=6667,
                                        dest_class=DestClass.PUBLIC, suspicious_dir="Downloads folder"))
    al = build_alert("network", "t", a, process_name="x.exe", destination="8.8.8.8:6667", what="w")
    assert al.what and al.why and al.evidence and al.uncertainty and al.recommendations
    assert "heuristics only" in al.uncertainty


def test_alert_dedup():
    m = AlertManager(dedup_seconds=60, min_severity="low")
    a = RiskEngine().assess(RiskContext(exe="x.exe", sig_status="unsigned", remote_ip="8.8.8.8", remote_port=6667,
                                        dest_class=DestClass.PUBLIC))
    a1 = build_alert("network", "t", a, exe="x.exe", dedup_parts=("8.8.8.8",))
    a2 = build_alert("network", "t", a, exe="x.exe", dedup_parts=("8.8.8.8",))
    assert m.submit(a1)[1] is True
    r, new = m.submit(a2)
    assert new is False and r.count == 2
    assert level_for(5, False) == "informational"


# ------------------------------------------------------------------ privacy
class FakeReg:
    def __init__(self, tree):
        self.tree = tree

    def _node(self, hive, path):
        node = self.tree.get(hive)
        if node is None:
            raise OSError("no hive")
        for part in path.split("\\"):
            if part not in node:
                raise OSError("not found")
            node = node[part]
        return node

    def subkeys(self, hive, path):
        return [k for k, v in self._node(hive, path).items() if isinstance(v, dict)]

    def values(self, hive, path):
        return {k: v for k, v in self._node(hive, path).items() if not isinstance(v, dict)}


def _store(mic_apps, cam_apps=None):
    def cap(apps):
        return {"Value": "Allow", "NonPackaged": {k: v for k, v in apps.items() if "#" in k},
                **{k: v for k, v in apps.items() if "#" not in k}}
    root = {"Software": {"Microsoft": {"Windows": {"CurrentVersion": {"CapabilityAccessManager": {"ConsentStore": {
        "microphone": cap(mic_apps), "webcam": cap(cam_apps or {})}}}}}}}
    return {"HKCU": root, "HKLM": json.loads(json.dumps(root))}


def test_privacy_detects_start_stop_and_short_sessions():
    t0 = time.time()
    exe_key = "C:#Tools#Recorder#rec.exe"
    apps = {exe_key: {"Value": "Allow", "LastUsedTimeStart": epoch_to_filetime(t0 - 3600),
                      "LastUsedTimeStop": epoch_to_filetime(t0 - 3500)}}
    reg = FakeReg(_store(apps))
    pm = PrivacyMonitor(source=reg)
    ev = pm.poll()
    assert [e.event_type for e in ev if e.scope == "user"] == ["historical"]
    # access starts (stop = 0 while in use)
    apps[exe_key]["LastUsedTimeStart"], apps[exe_key]["LastUsedTimeStop"] = epoch_to_filetime(t0), 0
    reg.tree = _store(apps)
    ev = [e for e in pm.poll() if e.scope == "user"]
    assert ev[0].event_type == "access_started" and ev[0].app_id == r"C:\Tools\Recorder\rec.exe"
    st, _ = pm.snapshot()
    assert st["microphone"].active_apps == ["rec.exe"] and st["microphone"].telemetry == "available"
    apps[exe_key]["LastUsedTimeStop"] = epoch_to_filetime(t0 + 20)
    reg.tree = _store(apps)
    ev = [e for e in pm.poll() if e.scope == "user"]
    assert ev[0].event_type == "access_stopped" and abs(ev[0].duration - 20) < 0.01
    # start and stop between two polls
    apps[exe_key]["LastUsedTimeStart"], apps[exe_key]["LastUsedTimeStop"] = epoch_to_filetime(t0 + 60), epoch_to_filetime(t0 + 61)
    reg.tree = _store(apps)
    assert [e.event_type for e in pm.poll() if e.scope == "user"] == ["access_session"]


def test_privacy_unavailable_is_reported_not_faked():
    pm = PrivacyMonitor(source=None)
    pm.source = None
    assert pm.poll() == []
    st, _ = pm.snapshot()
    assert st["microphone"].telemetry == "unavailable"


def test_packaged_app_matching():
    perm, recs = read_capability(FakeReg(_store({"Microsoft.WindowsCamera_8wekyb3d8bbwe": {"Value": "Allow"}})),
                                 "HKCU", "microphone")
    assert recs[0].app_kind == "packaged" and recs[0].display_name == "Microsoft.WindowsCamera"
    assert app_matches_exe("Microsoft.WindowsCamera_8wekyb3d8bbwe", "packaged",
                           r"C:\Program Files\WindowsApps\Microsoft.WindowsCamera_2024.1_x64__8wekyb3d8bbwe\WindowsCamera.exe")


# --------------------------------------------------------------- correlation
def _conn(exe, raddr="198.51.100.7", t=None, uid="c1"):
    t = t or time.time()
    return Connection(uid=uid, pid=1234, proto="TCP", family=4, laddr="192.168.1.2", lport=50000, raddr=raddr,
                      rport=443, state="ESTABLISHED", direction="outbound", dest_class=DestClass.PUBLIC,
                      first_seen=t, last_seen=t, process_name=exe.rsplit("\\", 1)[-1], exe=exe)


def test_correlation_alert_and_wording():
    exe = r"C:\Tools\Recorder\rec.exe"
    t0 = 1_000_000.0
    eng = CorrelationEngine(5, 30, ["teams.exe"], upload_lookup=lambda e, a, b: (2_400_000, True, "TCP counters"))
    eng.add_privacy_event(PrivacyEvent(ts=t0, capability="microphone", event_type="access_started", app_id=exe,
                                       app_kind="desktop", scope="user", start_ts=t0, display_name="rec.exe"))
    eng.add_connection(_conn(exe, t=t0 + 2))
    eng.add_connection(_conn(r"C:\Other\other.exe", t=t0 + 3, uid="c2"))   # different app: ignored
    eng.add_connection(_conn(exe, t=t0 + 100, uid="c3"))                    # outside window: ignored
    assert eng.evaluate(t0 + 10) == []          # window still open
    res = eng.evaluate(t0 + 31)
    assert len(res) == 1 and len(res[0].connections) == 1
    assert "2.3 MB uploaded" in res[0].summary() and not res[0].expected_app
    a = RiskEngine().assess(RiskContext(exe=exe, sig_status="unsigned", remote_ip="198.51.100.7", remote_port=443,
                                        dest_class=DestClass.PUBLIC,
                                        privacy_correlation={"capability_label": "Microphone", "summary": res[0].summary()}))
    al = build_alert("privacy-correlation", "Privacy correlation detected", a, exe=exe,
                     extra_uncertainty="A temporal correlation is not proof that microphone or camera content was transmitted.")
    assert "not proof" in al.uncertainty and a.level in ("medium", "high")


def test_expected_app_scores_lower():
    eng = RiskEngine()
    pc = {"capability_label": "Microphone", "summary": "s"}
    base = dict(sig_status="valid", remote_ip="8.8.8.8", remote_port=443, dest_class=DestClass.PUBLIC, privacy_correlation=pc)
    assert eng.assess(RiskContext(expected_app=True, **base)).score < eng.assess(RiskContext(expected_app=False, **base)).score


# -------------------------------------------------------------------- traffic
def test_traffic_deltas_and_spike():
    tr = TrafficTracker(spike_mb_per_min=1, spike_factor=3)
    c = _conn(r"C:\a\up.exe")
    t = (time.time() // 60) * 60 + 1
    tr.update_cumulative(c, 1000, 500, "estats", t)
    tr.update_cumulative(c, 3_000_000, 600, "estats", t + 1)
    assert tr.app_totals(r"C:\a\up.exe") == (3_000_000, 600)
    assert tr.bytes_between(r"C:\a\up.exe", t - 1, t + 2)[0] == 3_000_000
    tr._minute_start = int(t // 60) * 60
    spikes = tr.check_spikes(t + 61)
    assert spikes and spikes[0]["bytes"] == 3_000_000


def test_unmeasured_traffic_is_reported_as_such():
    b, measured, note = TrafficTracker().bytes_between("x", 0, 1)
    assert b is None and measured is False and "Administrator" in note


def test_beaconing_regular_vs_irregular():
    bd = BeaconDetector(min_events=6, max_cv=0.2)
    for i in range(8):
        bd.record("mal.exe", "mal.exe", "198.51.100.9", 8443, 1000 + i * 60 + (i % 2))
    for i, t in enumerate([0, 7, 50, 51, 140, 300, 302, 700]):
        bd.record("browser.exe", "browser.exe", "198.51.100.10", 443, 1000 + t)
    found = bd.analyze()
    assert [(f.exe, f.rport) for f in found] == [("mal.exe", 8443)]


# ------------------------------------------------------------------------ DNS
def test_dns_heuristics():
    assert name_indicators("www.google.com") == []
    assert name_indicators("a3f9e1c0b7d24e6f8a1b2c3d4e5f6a7b8c9d0e1f.evil-example.com")
    tr = DnsRateTracker(per_min_threshold=1000, unique_sub_threshold=20)
    ind = []
    for i in range(30):
        ind = tr.add(f"x{i}q.tunnel-example.net", "TXT", 100 + i)
    assert any("unique subdomains" in s for s in ind)


def test_parse_dns_client_event_xml():
    xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>3008</EventID>
    <EventRecordID>42</EventRecordID><TimeCreated SystemTime='2026-11-27T10:00:00.1234567Z'/>
    <Execution ProcessID='1234' ThreadID='1'/></System><EventData><Data Name='QueryName'>example.com</Data>
    <Data Name='QueryType'>1</Data><Data Name='QueryStatus'>0</Data>
    <Data Name='QueryResults'>type: 5 cdn.example.net;::ffff:93.184.216.34;</Data></EventData></Event>"""
    ev = parse_dns_client_events(xml)[0]
    assert ev["name"] == "example.com" and ev["answers"] == ["93.184.216.34"] and ev["pid"] == 1234
    assert ev["qtype"] == "A" and ev["record_id"] == 42


def test_parse_ipconfig_displaydns():
    text = """
    example.com
    ----------------------------------------
    Record Name . . . . . : example.com
    Record Type . . . . . : 1
    Time To Live  . . . . : 300
    Data Length . . . . . : 4
    Section . . . . . . . : Answer
    A (Host) Record . . . : 93.184.216.34
"""
    assert parse_ipconfig_displaydns(text) == [{"name": "example.com", "type": 1, "data": "93.184.216.34"}]


# ------------------------------------------------------------ signatures/TI
def test_signature_json_parsing():
    out = json.dumps([{"Path": r"C:\a.exe", "Status": "Valid", "Signer": 'CN="Contoso, Ltd", O=Contoso', "Type": "Authenticode",
                       "IsOS": False, "Msg": ""},
                      {"Path": r"C:\b.exe", "Status": "NotSigned", "Signer": "", "Type": "", "IsOS": False, "Msg": ""},
                      {"Path": r"C:\c.exe", "Status": "HashMismatch", "Signer": "CN=X", "Type": "", "IsOS": False, "Msg": ""}])
    r = parse_signature_json(out)
    assert r[r"C:\a.exe"].status == "valid" and r[r"C:\a.exe"].publisher == "Contoso, Ltd"
    assert r[r"C:\b.exe"].status == "unsigned" and r[r"C:\c.exe"].status == "tampered"
    assert publisher_from_subject("CN=Microsoft Windows, O=Microsoft Corporation") == "Microsoft Windows"


def test_blocklist(tmp_path):
    p = tmp_path / "bl.txt"
    p.write_text("198.51.100.0/24\nbad-example.org # comment\n")
    bl = LocalBlocklist(p)
    assert bl.match_ip("198.51.100.77") == "198.51.100.0/24" and not bl.match_ip("8.8.8.8")
    assert bl.match_domain("cdn.bad-example.org") == "bad-example.org"


def test_ti_never_sends_private_or_without_consent(tmp_path):
    cfg = Config(tmp_path / "s.json")
    ti = ThreatIntel(cfg)
    assert not ti.allowed_indicator("192.168.1.1")[0]
    assert not ti.allowed_indicator("printer.local")[0]
    assert ti.allowed_indicator("8.8.8.8")[0]
    assert ti.lookup("8.8.8.8", user_initiated=False) == []    # manual mode: no automatic lookups


# --------------------------------------------------------------------- config
def test_config_validation(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"monitoring": {"connection_interval_sec": -5}, "threat_intel": {"mode": "auto"}}))
    cfg = Config(p)
    assert cfg.get("monitoring.connection_interval_sec") == 1.0
    assert cfg.get("threat_intel.mode") == "manual"       # auto requires explicit consent
    assert len(cfg.errors) == 2
    with pytest.raises(ValueError):
        cfg.set("retention.days", 0)


def test_auto_install_requests_missing_and_outdated(monkeypatch):
    from utils import deps
    calls = []
    real_version = deps.metadata.version

    def fake_version(name):
        if name == "customtkinter":
            raise deps.metadata.PackageNotFoundError(name)
        if name == "psutil":
            return "5.9.0"   # outdated
        return real_version(name)
    monkeypatch.setattr(deps.metadata, "version", fake_version)
    monkeypatch.setattr(deps, "pip_install", lambda specs, upgrade=True: (calls.append(specs), (True, ""))[1])
    deps.ensure(include_gui=True, echo=lambda m: None)
    assert calls and "customtkinter>=5.2.2,<6" in calls[0] and "psutil>=6.1,<8" in calls[0]
