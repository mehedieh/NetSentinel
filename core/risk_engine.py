"""Transparent, explainable risk scoring.

Every point added to a score comes from a named Factor carrying the telemetry that
triggered it. Heuristic-only findings are capped at HIGH; CRITICAL requires at least
one *verified* factor (threat-intelligence hit or local blocklist match).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Optional

from utils.helpers import EXPECTED_EXTERNAL_PORTS, DestClass, fmt_bytes, port_service, short_id

LEVELS = ["informational", "low", "medium", "high", "critical"]
THRESHOLDS = [(70, "critical"), (45, "high"), (25, "medium"), (10, "low"), (0, "informational")]


def level_for(score: int, has_verified: bool) -> str:
    for th, lvl in THRESHOLDS:
        if score >= th:
            if lvl == "critical" and not has_verified:
                return "high"
            return lvl
    return "informational"


def level_rank(level: str) -> int:
    try:
        return LEVELS.index(level)
    except ValueError:
        return 0


@dataclass
class Factor:
    code: str
    label: str
    points: int
    evidence: str
    verified: bool = False   # True only for threat intel / blocklist matches


@dataclass
class Assessment:
    score: int
    level: str
    factors: list[Factor] = field(default_factory=list)

    @property
    def has_verified(self) -> bool:
        return any(f.verified for f in self.factors)

    def explain(self) -> str:
        return "; ".join(f"{f.label} ({f.points:+d})" for f in self.factors) or "no risk factors"


@dataclass
class RiskContext:
    """Everything known about one observation. All fields optional."""
    exe: str = ""
    process_name: str = ""
    sig_status: str = ""           # valid|unsigned|tampered|untrusted|expired|error|unavailable|pending|os
    publisher: str = ""
    suspicious_dir: str = ""
    has_window: Optional[bool] = None
    remote_ip: str = ""
    remote_port: int = 0
    proto: str = ""
    dest_class: str = ""
    domain: str = ""
    ti_verdict: str = ""           # malicious | suspicious | clean | unknown
    ti_source: str = ""
    ti_detail: str = ""
    blocklist_match: str = ""
    new_destination: bool = False
    beacon: Optional[dict] = None
    upload_spike: Optional[dict] = None
    conn_rate: Optional[int] = None
    conn_rate_threshold: Optional[int] = None
    dns_indicators: list = field(default_factory=list)
    privacy_correlation: Optional[dict] = None
    expected_app: bool = False


UNCERTAINTY = {
    "ti_malicious": "Reputation feeds can be outdated; shared hosting/CDN IPs can be listed because of other tenants.",
    "ti_suspicious": "A low reputation score or community pulse is not confirmation of malicious activity.",
    "blocklist": "Accuracy depends entirely on the quality of your local blocklist.",
    "sig_tampered": "A hash mismatch can also result from an incomplete update or a corrupted file.",
    "sig_untrusted": "Self-signed or enterprise-signed software is legitimate in managed environments.",
    "unsigned": "Many legitimate open-source and small-vendor programs are not code-signed.",
    "suspicious_dir": "Installers and portable apps legitimately run from Downloads or Temp.",
    "unusual_port": "Games, VPNs, P2P and developer tools commonly use non-standard ports.",
    "new_destination": "New destinations are normal after updates or when visiting new sites/services.",
    "beaconing": "Update checkers, telemetry, sync clients and keep-alives also connect periodically.",
    "upload_spike": "Backups, cloud sync, video calls and uploads cause legitimate spikes.",
    "conn_rate": "Browsers, torrent clients and scanners open many connections legitimately.",
    "dns_tunnel": "CDNs, anti-virus cloud lookups and telemetry use long, random-looking subdomains.",
    "privacy_correlation": "Timing alone does not show what data was sent; the app may simply be syncing or checking for updates.",
    "background_unsigned": "Tray apps and services often run without visible windows.",
    "no_exe": "The path may be hidden only because the process is protected and NetSentinel lacks rights.",
}

RECOMMEND = {
    "ti_malicious": "Look up the destination yourself on the provider's site; consider blocking it with a reversible firewall rule; scan the executable with Microsoft Defender.",
    "ti_suspicious": "Check which domain resolved to this IP and whether the app is expected to use it.",
    "blocklist": "Review why the indicator is on your blocklist; block or investigate the process.",
    "sig_tampered": "Do not trust this file. Scan it with Defender, reinstall the software from the vendor.",
    "sig_untrusted": "Inspect the certificate (file Properties > Digital Signatures).",
    "unsigned": "Confirm where the program came from and whether you installed it.",
    "suspicious_dir": "Check whether you started this program; inspect its parent process and file origin.",
    "unusual_port": "Identify what service runs on that port; check the app's documentation.",
    "new_destination": "Investigate the IP/domain owner if the app is unfamiliar.",
    "beaconing": "Identify the destination owner; compare with the vendor's documented endpoints.",
    "upload_spike": "Check whether a backup/sync/upload was expected at that time.",
    "conn_rate": "Check whether the process is expected to open many connections.",
    "dns_tunnel": "Inspect the queried domain; unusual long random subdomains to one domain warrant review.",
    "privacy_correlation": "Confirm you were using the app's microphone/camera features at that time; review the app's privacy settings and destination owner.",
    "background_unsigned": "Find out what installed the process and whether it should run in the background.",
    "no_exe": "Restart NetSentinel as Administrator to see the full process details.",
}


class RiskEngine:
    def assess(self, ctx: RiskContext) -> Assessment:
        f: list[Factor] = []
        ext = ctx.dest_class == DestClass.PUBLIC

        if ctx.blocklist_match:
            f.append(Factor("blocklist", "Destination is on your local blocklist", 50,
                            f"Matched entry: {ctx.blocklist_match}", verified=True))
        if ctx.ti_verdict == "malicious":
            f.append(Factor("ti_malicious", f"Threat intelligence: malicious ({ctx.ti_source})", 60,
                            ctx.ti_detail, verified=True))
        elif ctx.ti_verdict == "suspicious":
            f.append(Factor("ti_suspicious", f"Threat intelligence: suspicious ({ctx.ti_source})", 20,
                            ctx.ti_detail, verified=True))

        sig = ctx.sig_status
        if sig == "tampered":
            f.append(Factor("sig_tampered", "Digital signature verification FAILED (hash mismatch)", 35,
                            f"{ctx.exe}: signature present but file contents do not match"))
        elif sig in ("untrusted", "expired"):
            f.append(Factor("sig_untrusted", f"Signature {sig}", 12, f"{ctx.exe}: certificate {sig}"))
        elif sig == "unsigned" and ext:
            f.append(Factor("unsigned", "Unsigned executable communicating externally", 10,
                            f"{ctx.exe} has no Authenticode or catalog signature"))
        if ctx.suspicious_dir and ext:
            f.append(Factor("suspicious_dir", "Executable runs from an unusual location", 20,
                            f"{ctx.exe} is in the {ctx.suspicious_dir}"))
        if not ctx.exe and ext and sig not in ("os",):
            f.append(Factor("no_exe", "Executable path could not be determined", 5,
                            f"Process '{ctx.process_name}' path unavailable"))
        if ctx.has_window is False and sig in ("unsigned", "untrusted", "tampered") and ext:
            f.append(Factor("background_unsigned", "Background process without a visible window", 8,
                            "No visible top-level window was found for this process"))

        if ext and ctx.remote_port and ctx.remote_port not in EXPECTED_EXTERNAL_PORTS:
            svc = port_service(ctx.remote_port)
            f.append(Factor("unusual_port", "Uncommon destination port", 8,
                            f"{ctx.proto} port {ctx.remote_port}{f' ({svc})' if svc else ''}"))
        if ctx.new_destination and ext:
            f.append(Factor("new_destination", "First time this destination was observed", 3,
                            f"{ctx.remote_ip}{f' ({ctx.domain})' if ctx.domain else ''} not seen before"))
        if ctx.beacon:
            b = ctx.beacon
            f.append(Factor("beaconing", "Periodic (beacon-like) connection pattern", 22,
                            f"{b['count']} connections, mean interval {b['mean_interval']:.0f}s, "
                            f"variation {b['cv']:.2f}"))
        if ctx.upload_spike:
            u = ctx.upload_spike
            f.append(Factor("upload_spike", "Unusual upload volume", 18,
                            f"{fmt_bytes(u['bytes'])} uploaded in 1 minute (baseline {fmt_bytes(u['baseline'])}/min)"))
        if ctx.conn_rate and ctx.conn_rate_threshold and ctx.conn_rate > ctx.conn_rate_threshold:
            f.append(Factor("conn_rate", "Unusually frequent outbound connections", 12,
                            f"{ctx.conn_rate} new connections in the last minute "
                            f"(threshold {ctx.conn_rate_threshold})"))
        if ctx.dns_indicators:
            f.append(Factor("dns_tunnel", "DNS tunnelling / DGA indicators", 20,
                            "; ".join(ctx.dns_indicators)[:400]))
        if ctx.privacy_correlation:
            pc = ctx.privacy_correlation
            pts = 25 if not ctx.expected_app else 8
            f.append(Factor("privacy_correlation",
                            f"{pc['capability_label']} use followed by outbound connection", pts,
                            pc["summary"]))

        # trust reductions (shown as negative factors for transparency)
        score = sum(x.points for x in f)
        if score > 0 and sig in ("valid", "os") and not any(x.verified for x in f):
            reduction = -10 if score >= 10 else -score
            f.append(Factor("signed", f"Validly signed{f' by {ctx.publisher}' if ctx.publisher else ''}",
                            reduction, "Signature verified by Windows"))
        if score > 0 and ctx.expected_app and ctx.privacy_correlation is None and not any(x.verified for x in f):
            f.append(Factor("expected_app", "Known communication/browser app", -5,
                            "Listed in Settings > Correlation > expected apps"))
        score = max(0, sum(x.points for x in f))
        has_ver = any(x.verified for x in f)
        return Assessment(score=score, level=level_for(score, has_ver), factors=f)


@dataclass
class Alert:
    id: str
    ts: float
    severity: str
    score: int
    category: str
    title: str
    process_name: str
    pid: Optional[int]
    exe: str
    destination: str
    what: str
    why: str
    evidence: list[str]
    uncertainty: str
    recommendations: list[str]
    factors: list[dict]
    dedup_key: str
    count: int = 1
    acknowledged: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    def as_text(self) -> str:
        lines = [f"{self.title}", f"Severity: {self.severity.upper()} (score {self.score})",
                 f"Application: {self.process_name} (PID {self.pid})", f"Executable: {self.exe or 'unavailable'}"]
        if self.destination:
            lines.append(f"Destination: {self.destination}")
        lines += ["", "1. What was detected", self.what, "", "2. Why it was flagged", self.why, "",
                  "3. Supporting evidence"] + [f"  • {e}" for e in self.evidence]
        lines += ["", "4. What remains uncertain", self.uncertainty, "", "5. Recommended investigation steps"]
        lines += [f"  • {r}" for r in self.recommendations]
        if self.count > 1:
            lines += ["", f"(Seen {self.count} times; repeated alerts are grouped.)"]
        return "\n".join(lines)


def build_alert(category: str, title: str, assessment: Assessment, *, process_name: str = "",
                pid: Optional[int] = None, exe: str = "", destination: str = "", what: str = "",
                extra_evidence: list[str] | None = None, extra_uncertainty: str = "",
                dedup_parts: tuple = (), ts: float | None = None) -> Alert:
    import time as _t
    codes = [f.code for f in assessment.factors if f.points > 0]
    evidence = [f"{f.label}: {f.evidence}" for f in assessment.factors] + list(extra_evidence or [])
    unc = " ".join(UNCERTAINTY[c] for c in codes if c in UNCERTAINTY)
    if extra_uncertainty:
        unc = (extra_uncertainty + " " + unc).strip()
    if not assessment.has_verified:
        unc = ("This alert is based on heuristics only; no verified threat-intelligence match exists. " + unc).strip()
    recs = [RECOMMEND[c] for c in codes if c in RECOMMEND] or ["No action required unless the activity is unexpected."]
    why = f"Score {assessment.score} → {assessment.level}. Factors: {assessment.explain()}."
    key_src = json.dumps([category, (exe or process_name).lower(), *dedup_parts], default=str)
    return Alert(id=short_id(), ts=ts or _t.time(), severity=assessment.level, score=assessment.score,
                 category=category, title=title, process_name=process_name, pid=pid, exe=exe,
                 destination=destination, what=what, why=why, evidence=evidence,
                 uncertainty=unc or "—", recommendations=recs,
                 factors=[asdict(f) for f in assessment.factors],
                 dedup_key=hashlib.sha1(key_src.encode()).hexdigest()[:16])


class AlertManager:
    """Deduplicates alerts: identical dedup_key within the window increments a counter."""

    def __init__(self, dedup_seconds: int = 1800, min_severity: str = "low"):
        self.dedup_seconds = dedup_seconds
        self.min_severity = min_severity
        self._recent: dict[str, Alert] = {}

    def submit(self, alert: Alert) -> tuple[Optional[Alert], bool]:
        """Return (alert, is_new). alert is None if below the minimum severity."""
        if level_rank(alert.severity) < level_rank(self.min_severity):
            return None, False
        prev = self._recent.get(alert.dedup_key)
        if prev and alert.ts - prev.ts < self.dedup_seconds:
            prev.count += 1
            if level_rank(alert.severity) > level_rank(prev.severity):
                prev.severity, prev.score = alert.severity, alert.score
            return prev, False
        self._recent[alert.dedup_key] = alert
        if len(self._recent) > 5000:
            cutoff = alert.ts - self.dedup_seconds
            self._recent = {k: v for k, v in self._recent.items() if v.ts >= cutoff}
        return alert, True
