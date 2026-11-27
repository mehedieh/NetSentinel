"""Optional threat-intelligence and ownership lookups.

Rules enforced here:
  * Only an indicator (public IP address or domain name) is ever sent; never logs,
    files, payloads or process details.
  * Private/loopback/link-local addresses are never sent.
  * Nothing is sent unless mode=manual (user clicks "Look up") or mode=auto AND the
    user explicitly consented (threat_intel.auto_consent).
  * API keys are stored encrypted with Windows DPAPI (current user) in the data dir.
  * Results are labelled VERIFIED (provider verdict) vs heuristic elsewhere.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from utils import windows_api
from utils.helpers import DestClass, classify_ip
from utils.paths import data_dir

log = logging.getLogger(__name__)


@dataclass
class TIResult:
    provider: str
    indicator: str
    verdict: str        # malicious | suspicious | clean | unknown | error
    score: Optional[float]
    detail: str
    ts: float
    owner: str = ""
    country: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------- secrets
class SecretStore:
    def __init__(self, path: Path | None = None):
        self.path = path or (data_dir() / "secrets.bin")
        self._mem: dict[str, str] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        if not self.path.exists() or not windows_api.IS_WINDOWS:
            return
        try:
            self._mem = json.loads(windows_api.dpapi_unprotect(self.path.read_bytes()).decode())
        except Exception as e:
            log.warning("Could not decrypt stored API keys: %s", e)

    @property
    def persistent(self) -> bool:
        return windows_api.IS_WINDOWS

    def get(self, name: str) -> str:
        return self._mem.get(name, "")

    def set(self, name: str, value: str) -> None:
        with self._lock:
            if value:
                self._mem[name] = value
            else:
                self._mem.pop(name, None)
            if windows_api.IS_WINDOWS:
                self.path.write_bytes(windows_api.dpapi_protect(json.dumps(self._mem).encode()))
            # On other platforms keys are kept in memory only (never written in clear text).

    def masked(self, name: str) -> str:
        v = self.get(name)
        return (v[:4] + "…" + v[-2:]) if len(v) > 8 else ("set" if v else "")


# ------------------------------------------------------------- blocklist
class LocalBlocklist:
    """Plain text file: one IP, CIDR or domain per line; '#' comments."""

    def __init__(self, path: Path | None = None):
        self.path = path or (data_dir() / "blocklist.txt")
        self.nets: list = []
        self.domains: set[str] = set()
        self.loaded_at = 0.0
        self.load()

    def load(self) -> int:
        self.nets, self.domains = [], set()
        if not self.path.exists():
            self.path.write_text("# NetSentinel local blocklist: one IP, CIDR or domain per line\n", encoding="utf-8")
        for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.split("#", 1)[0].strip().lower()
            if not line:
                continue
            try:
                self.nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                self.domains.add(line.lstrip("*.").rstrip("."))
        self.loaded_at = time.time()
        return len(self.nets) + len(self.domains)

    def match_ip(self, ip: str) -> str:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return ""
        for n in self.nets:
            if a.version == n.version and a in n:
                return str(n)
        return ""

    def match_domain(self, name: str) -> str:
        name = (name or "").lower().rstrip(".")
        parts = name.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in self.domains:
                return cand
        return ""


# ------------------------------------------------------------- providers
class _Bucket:
    def __init__(self, per_minute: int):
        self.per_minute, self.ts = per_minute, []

    def take(self) -> bool:
        now = time.time()
        self.ts = [t for t in self.ts if now - t < 60]
        if len(self.ts) >= self.per_minute:
            return False
        self.ts.append(now)
        return True


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


class Provider:
    name = "base"
    per_minute = 4

    def __init__(self, key: str, session):
        self.key, self.session, self.bucket = key, session, _Bucket(self.per_minute)

    def lookup(self, indicator: str) -> TIResult:
        raise NotImplementedError

    def _res(self, ind, verdict, score, detail, **kw) -> TIResult:
        return TIResult(self.name, ind, verdict, score, detail, time.time(), **kw)


class VirusTotal(Provider):
    name, per_minute = "VirusTotal", 4

    def lookup(self, ind: str) -> TIResult:
        kind = "ip_addresses" if _is_ip(ind) else "domains"
        r = self.session.get(f"https://www.virustotal.com/api/v3/{kind}/{ind}",
                             headers={"x-apikey": self.key}, timeout=15)
        if r.status_code == 404:
            return self._res(ind, "unknown", None, "not present in VirusTotal")
        r.raise_for_status()
        a = r.json().get("data", {}).get("attributes", {})
        st = a.get("last_analysis_stats", {})
        mal, sus = int(st.get("malicious", 0)), int(st.get("suspicious", 0))
        total = sum(int(v) for v in st.values()) or 1
        verdict = "malicious" if mal >= 3 else "suspicious" if (mal + sus) >= 1 else "clean"
        return self._res(ind, verdict, mal / total * 100,
                         f"{mal} malicious / {sus} suspicious of {total} engines",
                         owner=a.get("as_owner", ""), country=a.get("country", ""))


class AbuseIPDB(Provider):
    name, per_minute = "AbuseIPDB", 30

    def lookup(self, ind: str) -> TIResult:
        if not _is_ip(ind):
            return self._res(ind, "unknown", None, "AbuseIPDB supports IP addresses only")
        r = self.session.get("https://api.abuseipdb.com/api/v2/check",
                             params={"ipAddress": ind, "maxAgeInDays": 90},
                             headers={"Key": self.key, "Accept": "application/json"}, timeout=15)
        r.raise_for_status()
        d = r.json().get("data", {})
        s = int(d.get("abuseConfidenceScore", 0))
        verdict = "malicious" if s >= 75 else "suspicious" if s >= 25 else "clean"
        return self._res(ind, verdict, s, f"abuse confidence {s}%, {d.get('totalReports', 0)} reports; "
                                          f"usage: {d.get('usageType') or 'n/a'}",
                         owner=d.get("isp", ""), country=d.get("countryCode", ""))


class OTX(Provider):
    name, per_minute = "AlienVault OTX", 30

    def lookup(self, ind: str) -> TIResult:
        if _is_ip(ind):
            sect = "IPv6" if ":" in ind else "IPv4"
        else:
            sect = "domain"
        r = self.session.get(f"https://otx.alienvault.com/api/v1/indicators/{sect}/{ind}/general",
                             headers={"X-OTX-API-KEY": self.key}, timeout=15)
        r.raise_for_status()
        d = r.json()
        n = int(d.get("pulse_info", {}).get("count", 0))
        # Popular benign infrastructure appears in many pulses; never "malicious" from OTX alone.
        verdict = "suspicious" if n >= 3 else "clean" if n == 0 else "unknown"
        return self._res(ind, verdict, n, f"referenced in {n} OTX pulses (community data)",
                         owner=d.get("asn", ""), country=d.get("country_name", ""))


PROVIDERS = {"virustotal": VirusTotal, "abuseipdb": AbuseIPDB, "otx": OTX}


class ThreatIntel:
    def __init__(self, config, secrets: SecretStore | None = None, cache_get=None, cache_put=None):
        self.config = config
        self.secrets = secrets or SecretStore()
        self.blocklist = LocalBlocklist(Path(config.get("threat_intel.blocklist_path")) if
                                        config.get("threat_intel.blocklist_path") else None)
        self._cache_get, self._cache_put = cache_get, cache_put
        self._mem: dict[tuple, TIResult] = {}
        self._session = None
        self._providers: dict[str, Provider] = {}
        self._geo = None
        self._load_geo()

    def _sess(self):
        if self._session is None:
            import requests
            self._session = requests.Session()
            self._session.headers["User-Agent"] = "NetSentinel/1.0 (defensive host monitor)"
        return self._session

    def _provider(self, name: str) -> Optional[Provider]:
        key = self.secrets.get(name)
        if not key or not self.config.get(f"threat_intel.providers.{name}"):
            return None
        p = self._providers.get(name)
        if p is None or p.key != key:
            p = self._providers[name] = PROVIDERS[name](key, self._sess())
        return p

    def configured_providers(self) -> list[str]:
        return [n for n in PROVIDERS if self.secrets.get(n) and self.config.get(f"threat_intel.providers.{n}")]

    @staticmethod
    def allowed_indicator(ind: str) -> tuple[bool, str]:
        if _is_ip(ind):
            c = classify_ip(ind)
            if c != DestClass.PUBLIC:
                return False, f"{ind} is a {c} address and is never sent to third parties"
            return True, ""
        if "." not in ind or ind.endswith((".local", ".lan", ".home", ".internal", ".arpa")):
            return False, "local/internal names are never sent to third parties"
        return True, ""

    def cached(self, ind: str) -> list[TIResult]:
        out = [v for (i, _p), v in self._mem.items() if i == ind]
        if not out and self._cache_get:
            try:
                out = self._cache_get(ind, self.config.get("threat_intel.cache_hours") * 3600)
                for r in out:
                    self._mem[(ind, r.provider)] = r
            except Exception:
                log.debug("TI cache read failed", exc_info=True)
        return out

    def lookup(self, ind: str, user_initiated: bool) -> list[TIResult]:
        """Query enabled providers. user_initiated=True means the user clicked Look up."""
        mode = self.config.get("threat_intel.mode")
        if mode == "off":
            return []
        if not user_initiated and not (mode == "auto" and self.config.get("threat_intel.auto_consent")):
            return []
        ok, why = self.allowed_indicator(ind)
        if not ok:
            return [TIResult("policy", ind, "unknown", None, why, time.time())]
        results = []
        ttl = self.config.get("threat_intel.cache_hours") * 3600
        for name in PROVIDERS:
            p = self._provider(name)
            if not p:
                continue
            c = self._mem.get((ind, p.name))
            if c and time.time() - c.ts < ttl:
                results.append(c)
                continue
            if not p.bucket.take():
                results.append(TIResult(p.name, ind, "unknown", None, "rate limit reached; try later", time.time()))
                continue
            try:
                r = p.lookup(ind)
            except Exception as e:
                r = TIResult(p.name, ind, "error", None, f"lookup failed: {e}", time.time())
            if r.verdict != "error":
                self._mem[(ind, p.name)] = r
                if self._cache_put:
                    try:
                        self._cache_put(r)
                    except Exception:
                        log.debug("TI cache write failed", exc_info=True)
            results.append(r)
        return results

    @staticmethod
    def combine(results: list[TIResult]) -> tuple[str, str, str]:
        """(verdict, source, detail) — most severe provider verdict wins."""
        order = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0, "error": -1}
        best = max(results, key=lambda r: order.get(r.verdict, -1), default=None)
        if not best or order.get(best.verdict, -1) < 2:
            return ("clean" if best and best.verdict == "clean" else "", "", "")
        return best.verdict, best.provider, best.detail

    # --------------------------------------------------- ownership / geo
    def rdap(self, ip: str) -> dict:
        if not self.config.get("threat_intel.rdap_lookups"):
            return {"error": "RDAP lookups disabled in Settings"}
        ok, why = self.allowed_indicator(ip)
        if not ok:
            return {"error": why}
        try:
            r = self._sess().get(f"https://rdap.org/ip/{ip}", timeout=15)
            r.raise_for_status()
            d = r.json()
            org = ""
            for ent in d.get("entities", []):
                for item in (ent.get("vcardArray") or [None, []])[1]:
                    if item and item[0] == "fn":
                        org = item[3]
                        break
                if org:
                    break
            return {"name": d.get("name", ""), "org": org, "country": d.get("country", ""),
                    "range": f"{d.get('startAddress', '')} – {d.get('endAddress', '')}",
                    "handle": d.get("handle", "")}
        except Exception as e:
            return {"error": str(e)}

    def _load_geo(self) -> None:
        path = self.config.get("threat_intel.geoip_mmdb_path")
        if not path:
            return
        try:
            import maxminddb
            self._geo = maxminddb.open_database(path)
        except Exception as e:
            log.info("GeoIP database not loaded: %s", e)

    def geo(self, ip: str) -> dict:
        """Offline, approximate. Requires a user-supplied MaxMind GeoLite2 database."""
        if not self._geo:
            return {}
        try:
            rec = self._geo.get(ip) or {}
            return {"country": (rec.get("country") or {}).get("iso_code", ""),
                    "asn": rec.get("autonomous_system_number", ""),
                    "asn_org": rec.get("autonomous_system_organization", "")}
        except Exception:
            return {}
