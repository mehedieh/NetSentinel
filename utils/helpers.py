"""Pure helper functions (platform independent, fully unit-tested)."""
from __future__ import annotations

import datetime as _dt
import ipaddress
import math
import re
import time
from collections import Counter
from typing import Optional


# ---------------------------------------------------------------- IP classes
class DestClass:
    LOOPBACK = "loopback"
    PRIVATE = "private"
    LINK_LOCAL = "link-local"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    PUBLIC = "public"
    UNKNOWN = "unknown"

    ALL = (LOOPBACK, PRIVATE, LINK_LOCAL, MULTICAST, RESERVED, PUBLIC, UNKNOWN)


_DOC_NETS = [ipaddress.ip_network(n) for n in
             ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def parse_ip(addr: str | None):
    if not addr:
        return None
    try:
        ip = ipaddress.ip_address(addr.split("%")[0].strip("[]"))
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip


def classify_ip(addr: str | None, *, treat_documentation_as_public: bool = False) -> str:
    """Classify an address. Public addresses are *not* suspicious by themselves."""
    ip = parse_ip(addr)
    if ip is None:
        return DestClass.UNKNOWN
    if ip.is_unspecified:
        return DestClass.RESERVED
    if ip.is_loopback:
        return DestClass.LOOPBACK
    if ip.is_link_local:
        return DestClass.LINK_LOCAL
    if ip.is_multicast:
        return DestClass.MULTICAST
    if any(ip.version == n.version and ip in n for n in _DOC_NETS):
        # RFC 5737 / 3849 documentation ranges. Tests may treat them as public
        # so that example addresses (203.0.113.x) behave like internet hosts.
        return DestClass.PUBLIC if treat_documentation_as_public else DestClass.RESERVED
    if ip.version == 4 and ip in _CGNAT:
        return DestClass.PRIVATE
    if ip.version == 4 and str(ip) == "255.255.255.255":
        return DestClass.RESERVED
    if ip.is_private:
        return DestClass.PRIVATE
    if ip.is_reserved:
        return DestClass.RESERVED
    if ip.is_global:
        return DestClass.PUBLIC
    return DestClass.RESERVED


def is_external(dest_class: str) -> bool:
    return dest_class == DestClass.PUBLIC


# ------------------------------------------------------------------- ports
COMMON_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE", 587: "SMTP-submission",
    853: "DNS-over-TLS", 993: "IMAPS", 995: "POP3S", 1900: "SSDP", 3389: "RDP",
    3478: "STUN/TURN", 3479: "STUN/TURN", 3480: "STUN/TURN", 3481: "STUN/TURN",
    4500: "IPsec NAT-T", 5222: "XMPP", 5223: "Apple push", 5228: "Google push",
    5353: "mDNS", 5355: "LLMNR", 7680: "Delivery Optimization", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 19302: "Google STUN",
}
# Ports that are ordinary for a desktop talking to the internet.
EXPECTED_EXTERNAL_PORTS = {80, 443, 53, 853, 123, 993, 995, 465, 587, 143, 5222, 5223, 5228,
                           3478, 3479, 3480, 3481, 19302, 8080, 8443, 4500, 500, 7680}


def port_service(port: int | None) -> str:
    if not port:
        return ""
    return COMMON_PORTS.get(int(port), "")


# ---------------------------------------------------------------- formatting
def fmt_bytes(n: Optional[float]) -> str:
    if n is None:
        return "n/a"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_ts(ts: Optional[float], with_date: bool = False) -> str:
    if not ts:
        return "—"
    d = _dt.datetime.fromtimestamp(ts)
    return d.strftime("%Y-%m-%d %H:%M:%S" if with_date else "%H:%M:%S")


def iso(ts: Optional[float]) -> Optional[str]:
    if not ts:
        return None
    return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).isoformat()


def fmt_duration(sec: Optional[float]) -> str:
    if sec is None:
        return "—"
    sec = int(sec)
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m {sec % 60}s"
    return f"{sec // 3600}h {(sec % 3600) // 60}m"


def now() -> float:
    return time.time()


# Windows FILETIME = 100ns intervals since 1601-01-01 UTC
_FILETIME_EPOCH_DIFF = 116444736000000000


def filetime_to_epoch(ft: int | None) -> Optional[float]:
    if not ft or ft <= _FILETIME_EPOCH_DIFF:
        return None
    return (ft - _FILETIME_EPOCH_DIFF) / 10_000_000


def epoch_to_filetime(ts: float) -> int:
    return int(ts * 10_000_000) + _FILETIME_EPOCH_DIFF


# ---------------------------------------------------------------- strings
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp",
    "co.in", "net.in", "com.bd", "net.bd", "org.bd", "gov.bd", "edu.bd", "ac.bd", "com.br",
    "com.cn", "net.cn", "co.nz", "co.za", "com.sg", "com.my", "com.pk", "com.tr", "co.kr",
    "github.io", "blogspot.com", "cloudfront.net", "azurewebsites.net", "herokuapp.com",
    "amazonaws.com", "appspot.com", "web.app", "firebaseapp.com", "duckdns.org", "ngrok.io",
}


def base_domain(name: str) -> str:
    """Approximate registrable domain (no full Public Suffix List; documented limitation)."""
    name = (name or "").strip(".").lower()
    labels = name.split(".")
    if len(labels) <= 2:
        return name
    last2 = ".".join(labels[-2:])
    if last2 in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last2


def normalize_path(p: str | None) -> str:
    if not p:
        return ""
    return p.replace("/", "\\").strip().lower()


# --------------------------------------------------- executable locations
_SUSPICIOUS_DIRS = [
    (re.compile(r"\\appdata\\local\\temp\\"), "user temporary folder (%TEMP%)"),
    (re.compile(r"\\windows\\temp\\"), "Windows temporary folder"),
    (re.compile(r"\\downloads\\"), "Downloads folder"),
    (re.compile(r"\\users\\public\\"), "Public user folder"),
    (re.compile(r"\\\$recycle\.bin\\"), "Recycle Bin"),
    (re.compile(r"^[a-z]:\\programdata\\[^\\]+\.exe$"), "root of ProgramData"),
    (re.compile(r"\\appdata\\roaming\\[^\\]+\.exe$"), "root of AppData\\Roaming"),
    (re.compile(r"\\appdata\\local\\[^\\]+\.exe$"), "root of AppData\\Local"),
    (re.compile(r"\\windows\\(debug|fonts|help|tasks)\\"), "unusual Windows subfolder"),
    (re.compile(r"\\content\.ie5\\|\\inetcache\\"), "browser cache folder"),
]


def suspicious_location(path: str | None) -> Optional[str]:
    """Return a human-readable reason if the executable lives somewhere unusual."""
    p = normalize_path(path)
    if not p:
        return None
    for rx, label in _SUSPICIOUS_DIRS:
        if rx.search(p):
            return label
    return None


def exe_basename(path: str | None) -> str:
    if not path:
        return ""
    return normalize_path(path).rsplit("\\", 1)[-1]


def short_id() -> str:
    import uuid
    return uuid.uuid4().hex[:12]
