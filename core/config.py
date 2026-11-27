"""Configuration: embedded defaults, user overrides (JSON) and validation."""
from __future__ import annotations

import copy
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from utils.paths import user_config_path

log = logging.getLogger(__name__)

SEVERITIES = ["informational", "low", "medium", "high", "critical"]

DEFAULTS: dict[str, Any] = {
    "monitoring": {
        "connection_interval_sec": 1.0,
        "privacy_interval_sec": 1.0,
        "dns_cache_interval_sec": 30,
        "dns_eventlog_interval_sec": 5,
        "autostart_monitoring": True,
    },
    "capture": {
        "enable_estats": True,          # per-connection TCP byte counters (admin)
        "enable_packet_capture": False, # Scapy + Npcap (admin); header metadata only
        "interface": "",                # "" = all / default
    },
    "dns": {
        "reverse_dns": True,
        "read_dns_client_log": True,
        "read_dns_cache": True,
    },
    "correlation": {
        "window_before_sec": 5,
        "window_after_sec": 30,
        "expected_apps": ["teams.exe", "ms-teams.exe", "zoom.exe", "discord.exe", "skype.exe",
                          "slack.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
                          "opera.exe", "whatsapp.exe", "telegram.exe", "webex.exe", "obs64.exe"],
    },
    "thresholds": {
        "upload_spike_mb_per_min": 25.0,
        "spike_factor": 5.0,
        "new_conn_per_min": 120,
        "beacon_min_events": 6,
        "beacon_max_cv": 0.2,
        "long_lived_minutes": 120,
        "dns_queries_per_min_per_domain": 60,
        "dns_unique_subdomains_5min": 60,
        "correlation_upload_mb": 1.0,
    },
    "retention": {"days": 30, "cleanup_interval_hours": 6},
    "threat_intel": {
        "mode": "manual",               # off | manual | auto
        "auto_consent": False,          # must be explicitly enabled for "auto"
        "providers": {"virustotal": False, "abuseipdb": False, "otx": False},
        "cache_hours": 24,
        "rdap_lookups": False,          # network ownership via rdap.org (opt-in)
        "blocklist_path": "",           # "" -> <data dir>/blocklist.txt
        "geoip_mmdb_path": "",          # optional MaxMind GeoLite2 .mmdb
    },
    "alerts": {"min_severity": "low", "dedup_minutes": 30},
    "ui": {"refresh_ms": 1000, "start_page": "Overview"},
    "privacy": {"store_usernames": True},
}

# dotted key -> (type, min, max | choices)
SCHEMA: dict[str, tuple] = {
    "monitoring.connection_interval_sec": (float, 0.25, 60),
    "monitoring.privacy_interval_sec": (float, 0.25, 60),
    "monitoring.dns_cache_interval_sec": (int, 5, 3600),
    "monitoring.dns_eventlog_interval_sec": (int, 1, 600),
    "monitoring.autostart_monitoring": (bool,),
    "capture.enable_estats": (bool,),
    "capture.enable_packet_capture": (bool,),
    "capture.interface": (str,),
    "dns.reverse_dns": (bool,),
    "dns.read_dns_client_log": (bool,),
    "dns.read_dns_cache": (bool,),
    "correlation.window_before_sec": (int, 0, 300),
    "correlation.window_after_sec": (int, 1, 3600),
    "correlation.expected_apps": (list,),
    "thresholds.upload_spike_mb_per_min": (float, 0.1, 100000),
    "thresholds.spike_factor": (float, 1.5, 1000),
    "thresholds.new_conn_per_min": (int, 5, 100000),
    "thresholds.beacon_min_events": (int, 4, 1000),
    "thresholds.beacon_max_cv": (float, 0.01, 1.0),
    "thresholds.long_lived_minutes": (int, 1, 100000),
    "thresholds.dns_queries_per_min_per_domain": (int, 5, 100000),
    "thresholds.dns_unique_subdomains_5min": (int, 5, 100000),
    "thresholds.correlation_upload_mb": (float, 0.01, 100000),
    "retention.days": (int, 1, 3650),
    "retention.cleanup_interval_hours": (int, 1, 168),
    "threat_intel.mode": ("choice", ["off", "manual", "auto"]),
    "threat_intel.auto_consent": (bool,),
    "threat_intel.providers.virustotal": (bool,),
    "threat_intel.providers.abuseipdb": (bool,),
    "threat_intel.providers.otx": (bool,),
    "threat_intel.cache_hours": (int, 1, 720),
    "threat_intel.rdap_lookups": (bool,),
    "threat_intel.blocklist_path": (str,),
    "threat_intel.geoip_mmdb_path": (str,),
    "alerts.min_severity": ("choice", SEVERITIES),
    "alerts.dedup_minutes": (int, 1, 1440),
    "ui.refresh_ms": (int, 250, 10000),
    "ui.start_page": (str,),
    "privacy.store_usernames": (bool,),
}


def _deep_merge(base: dict, override: dict) -> dict:
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def _get(d: dict, dotted: str, default=None):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _set(d: dict, dotted: str, value) -> None:
    parts = dotted.split(".")
    cur = d
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def coerce(key: str, value):
    """Coerce/validate one value. Raises ValueError with a readable message."""
    spec = SCHEMA.get(key)
    if spec is None:
        return value
    typ = spec[0]
    if typ is bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.lower() in ("true", "false", "1", "0", "yes", "no"):
            return value.lower() in ("true", "1", "yes")
        raise ValueError(f"{key}: expected true/false")
    if typ in (int, float):
        try:
            v = typ(value)
        except (TypeError, ValueError):
            raise ValueError(f"{key}: expected a number") from None
        lo, hi = spec[1], spec[2]
        if not (lo <= v <= hi):
            raise ValueError(f"{key}: must be between {lo} and {hi}")
        return v
    if typ == "choice":
        if value not in spec[1]:
            raise ValueError(f"{key}: must be one of {', '.join(spec[1])}")
        return value
    if typ is list:
        if isinstance(value, str):
            value = [x.strip() for x in value.split(",") if x.strip()]
        if not isinstance(value, list):
            raise ValueError(f"{key}: expected a list")
        return [str(x).lower() for x in value]
    if typ is str:
        return "" if value is None else str(value)
    return value


class Config:
    def __init__(self, path: str | os.PathLike | None = None):
        self.path = Path(path) if path else user_config_path()
        self._lock = threading.RLock()
        self.data: dict = copy.deepcopy(DEFAULTS)
        self.errors: list[str] = []
        self.load()

    def load(self) -> None:
        with self._lock:
            self.data = copy.deepcopy(DEFAULTS)
            self.errors = []
            if self.path.exists():
                try:
                    user = json.loads(self.path.read_text(encoding="utf-8"))
                    if isinstance(user, dict):
                        _deep_merge(self.data, user)
                    else:
                        self.errors.append("settings.json root must be an object; using defaults")
                except (OSError, json.JSONDecodeError) as e:
                    self.errors.append(f"Could not read settings.json ({e}); using defaults")
            self.errors += self.validate(fix=True)
            for e in self.errors:
                log.warning("Config: %s", e)

    def validate(self, fix: bool = True) -> list[str]:
        errs = []
        for key in SCHEMA:
            val = _get(self.data, key, _get(DEFAULTS, key))
            try:
                _set(self.data, key, coerce(key, val))
            except ValueError as e:
                errs.append(f"{e} (reset to default)")
                if fix:
                    _set(self.data, key, copy.deepcopy(_get(DEFAULTS, key)))
        if self.data["threat_intel"]["mode"] == "auto" and not self.data["threat_intel"]["auto_consent"]:
            errs.append("threat_intel.mode=auto requires auto_consent=true; using manual")
            if fix:
                self.data["threat_intel"]["mode"] = "manual"
        return errs

    def get(self, dotted: str, default=None):
        with self._lock:
            v = _get(self.data, dotted, default)
            return copy.deepcopy(v) if isinstance(v, (dict, list)) else v

    def set(self, dotted: str, value) -> None:
        with self._lock:
            _set(self.data, dotted, coerce(dotted, value))

    def save(self) -> list[str]:
        with self._lock:
            errs = self.validate(fix=True)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
            os.replace(tmp, self.path)
            return errs
