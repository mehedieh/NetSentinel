"""Thin, defensive wrappers around Windows APIs used by NetSentinel.

Only documented APIs and built-in tools are used:
  * iphlpapi  SetPerTcpConnectionEStats / GetPerTcpConnectionEStats (+ IPv6 variants)
  * crypt32   CryptProtectData / CryptUnprotectData (DPAPI, current-user scope)
  * wintrust  WinVerifyTrust (fallback signature check)
  * user32    EnumWindows / IsWindowVisible / GetWindowThreadProcessId
  * powershell Get-AuthenticodeSignature / Get-DnsClientCache (read-only cmdlets)
  * wevtutil  query/configure event logs

Every function degrades gracefully on non-Windows systems so the rest of the
code base (and its tests) can import this module anywhere.
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import re
import socket
import struct
import subprocess
from dataclasses import dataclass
from typing import Iterable, Optional

log = logging.getLogger(__name__)
IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000


# ------------------------------------------------------------ subprocess
def run_hidden(args: list[str], input_text: str | None = None, timeout: float = 30) -> subprocess.CompletedProcess:
    """Run a console tool without flashing a window. Never uses a shell."""
    kwargs = dict(capture_output=True, text=True, timeout=timeout, input=input_text,
                  encoding="utf-8", errors="replace")
    if IS_WINDOWS:
        kwargs["creationflags"] = CREATE_NO_WINDOW
    return subprocess.run(args, **kwargs)


def powershell(script: str, input_text: str | None = None, timeout: float = 60) -> str:
    r = run_hidden(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                   input_text=input_text, timeout=timeout)
    if r.returncode != 0 and not r.stdout:
        raise RuntimeError(r.stderr.strip()[:500] or f"powershell exit {r.returncode}")
    return r.stdout


# ------------------------------------------------------------------ DPAPI
if IS_WINDOWS:
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_protect(data: bytes) -> bytes:
    if not IS_WINDOWS:
        raise OSError("DPAPI is only available on Windows")
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(blob_in), "NetSentinel", None, None, None, 0x1,
                                    ctypes.byref(blob_out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def dpapi_unprotect(data: bytes) -> bytes:
    if not IS_WINDOWS:
        raise OSError("DPAPI is only available on Windows")
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0x1,
                                      ctypes.byref(blob_out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


# ----------------------------------------------------- TCP EStats (bytes)
_MIB_STATE = {"CLOSE": 1, "CLOSED": 1, "LISTEN": 2, "SYN_SENT": 3, "SYN_RECV": 4,
              "ESTABLISHED": 5, "FIN_WAIT1": 6, "FIN_WAIT2": 7, "CLOSE_WAIT": 8,
              "CLOSING": 9, "LAST_ACK": 10, "TIME_WAIT": 11, "DELETE_TCB": 12}
TcpConnectionEstatsData = 1
ERROR_ACCESS_DENIED = 5
ERROR_NOT_FOUND = 1168


class MIB_TCPROW(ctypes.Structure):
    _fields_ = [("dwState", ctypes.c_uint32), ("dwLocalAddr", ctypes.c_uint32),
                ("dwLocalPort", ctypes.c_uint32), ("dwRemoteAddr", ctypes.c_uint32),
                ("dwRemotePort", ctypes.c_uint32)]


class MIB_TCP6ROW(ctypes.Structure):
    _fields_ = [("State", ctypes.c_uint32), ("LocalAddr", ctypes.c_ubyte * 16),
                ("dwLocalScopeId", ctypes.c_uint32), ("dwLocalPort", ctypes.c_uint32),
                ("RemoteAddr", ctypes.c_ubyte * 16), ("dwRemoteScopeId", ctypes.c_uint32),
                ("dwRemotePort", ctypes.c_uint32)]


class TCP_ESTATS_DATA_RW_v0(ctypes.Structure):
    _fields_ = [("EnableCollection", ctypes.c_ubyte)]


class TCP_ESTATS_DATA_ROD_v0(ctypes.Structure):
    _fields_ = [("DataBytesOut", ctypes.c_uint64), ("DataSegsOut", ctypes.c_uint64),
                ("DataBytesIn", ctypes.c_uint64), ("DataSegsIn", ctypes.c_uint64),
                ("SegsOut", ctypes.c_uint64), ("SegsIn", ctypes.c_uint64),
                ("SoftErrors", ctypes.c_uint32), ("SoftErrorReason", ctypes.c_uint32),
                ("SndUna", ctypes.c_uint32), ("SndNxt", ctypes.c_uint32),
                ("SndMax", ctypes.c_uint32), ("ThruBytesAcked", ctypes.c_uint64),
                ("RcvNxt", ctypes.c_uint32), ("ThruBytesReceived", ctypes.c_uint64)]


def _port_dword(port: int) -> int:
    return socket.htons(int(port) & 0xFFFF)


def build_tcp_row(laddr: str, lport: int, raddr: str, rport: int, state: str):
    """Return (row, is_v6) for the iphlpapi EStats functions."""
    st = _MIB_STATE.get((state or "").upper(), 5)
    if ":" in laddr or ":" in raddr:
        row = MIB_TCP6ROW()
        row.State = st
        row.LocalAddr[:] = socket.inet_pton(socket.AF_INET6, laddr.split("%")[0])
        row.RemoteAddr[:] = socket.inet_pton(socket.AF_INET6, raddr.split("%")[0])
        row.dwLocalPort, row.dwRemotePort = _port_dword(lport), _port_dword(rport)
        return row, True
    row = MIB_TCPROW()
    row.dwState = st
    # in_addr is stored in network byte order; read those 4 bytes as a little-endian DWORD
    row.dwLocalAddr = struct.unpack("<I", socket.inet_aton(laddr))[0]
    row.dwRemoteAddr = struct.unpack("<I", socket.inet_aton(raddr))[0]
    row.dwLocalPort, row.dwRemotePort = _port_dword(lport), _port_dword(rport)
    return row, False


class TcpEStats:
    """Per-connection TCP byte counters maintained by the Windows TCP stack.

    Limitations (shown in the UI):
      * requires Administrator rights;
      * counting starts when NetSentinel enables collection for a connection,
        so bytes exchanged before that moment are not included;
      * TCP only (no UDP/QUIC equivalent exists).
    """

    def __init__(self) -> None:
        self.available = False
        self.reason = ""
        self._enabled: set[tuple] = set()
        if not IS_WINDOWS:
            self.reason = "Windows only"
            return
        try:
            self._ip = ctypes.windll.iphlpapi
            self._set4, self._get4 = self._ip.SetPerTcpConnectionEStats, self._ip.GetPerTcpConnectionEStats
            self._set6, self._get6 = self._ip.SetPerTcp6ConnectionEStats, self._ip.GetPerTcp6ConnectionEStats
            self.available = True
        except (AttributeError, OSError) as e:
            self.reason = f"iphlpapi unavailable: {e}"

    def read(self, laddr: str, lport: int, raddr: str, rport: int, state: str) -> Optional[tuple[int, int]]:
        """Return (bytes_out, bytes_in) since collection was enabled, or None."""
        if not self.available or not raddr:
            return None
        key = (laddr, lport, raddr, rport)
        try:
            row, v6 = build_tcp_row(laddr, lport, raddr, rport, state)
        except OSError:
            return None
        setf, getf = (self._set6, self._get6) if v6 else (self._set4, self._get4)
        if key not in self._enabled:
            rw = TCP_ESTATS_DATA_RW_v0(1)
            rc = setf(ctypes.byref(row), TcpConnectionEstatsData, ctypes.byref(rw), 0,
                      ctypes.sizeof(rw), 0)
            if rc == ERROR_ACCESS_DENIED:
                self.available = False
                self.reason = "Administrator rights required"
                return None
            if rc != 0:
                return None
            self._enabled.add(key)
        rod = TCP_ESTATS_DATA_ROD_v0()
        rc = getf(ctypes.byref(row), TcpConnectionEstatsData, None, 0, 0, None, 0, 0,
                  ctypes.byref(rod), 0, ctypes.sizeof(rod))
        if rc != 0:
            if rc == ERROR_NOT_FOUND:
                self._enabled.discard(key)
            return None
        return int(rod.DataBytesOut), int(rod.DataBytesIn)

    def forget(self, laddr: str, lport: int, raddr: str, rport: int) -> None:
        self._enabled.discard((laddr, lport, raddr, rport))


# --------------------------------------------------- code-signing checks
@dataclass
class SignatureInfo:
    status: str            # valid | unsigned | tampered | untrusted | expired | error | unavailable | pending
    publisher: str = ""
    sig_type: str = ""     # Authenticode | Catalog | ""
    is_os_binary: bool = False
    detail: str = ""

    @property
    def trusted(self) -> bool:
        return self.status == "valid"


_PS_SIG_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$paths = [Console]::In.ReadToEnd() | ConvertFrom-Json
$out = foreach ($p in $paths) {
  $s = Get-AuthenticodeSignature -LiteralPath $p
  [pscustomobject]@{
    Path   = $p
    Status = if ($s) { $s.Status.ToString() } else { 'Error' }
    Signer = if ($s -and $s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }
    Type   = if ($s -and $s.SignatureType) { $s.SignatureType.ToString() } else { '' }
    IsOS   = if ($s) { [bool]$s.IsOSBinary } else { $false }
    Msg    = if ($s) { $s.StatusMessage } else { 'no result' }
  }
}
ConvertTo-Json -InputObject @($out) -Compress
"""

_STATUS_MAP = {"Valid": "valid", "NotSigned": "unsigned", "HashMismatch": "tampered",
               "NotTrusted": "untrusted", "UnknownError": "error",
               "NotSupportedFileFormat": "unsigned", "Incompatible": "error"}


def publisher_from_subject(subject: str) -> str:
    for attr in ("CN", "O"):
        m = re.search(rf'(?:^|,\s*){attr}=(?:"([^"]+)"|([^,]+))', subject or "")
        if m:
            return (m.group(1) or m.group(2)).strip()
    return ""


def parse_signature_json(text: str) -> dict[str, SignatureInfo]:
    data = json.loads(text) if text.strip() else []
    if isinstance(data, dict):
        data = [data]
    out: dict[str, SignatureInfo] = {}
    for item in data:
        status = _STATUS_MAP.get(item.get("Status", ""), "error")
        msg = item.get("Msg") or ""
        if status == "untrusted" and "expired" in msg.lower():
            status = "expired"
        out[item.get("Path", "")] = SignatureInfo(
            status=status, publisher=publisher_from_subject(item.get("Signer", "")),
            sig_type=item.get("Type", ""), is_os_binary=bool(item.get("IsOS")), detail=msg[:300])
    return out


def check_signatures(paths: Iterable[str]) -> dict[str, SignatureInfo]:
    """Verify Authenticode/catalog signatures for many files in one PowerShell call.
    Get-AuthenticodeSignature understands catalog-signed Windows binaries, which a plain
    WinVerifyTrust(file) call reports as unsigned."""
    paths = [p for p in paths if p]
    if not paths:
        return {}
    if not IS_WINDOWS:
        return {p: SignatureInfo("unavailable", detail="Windows only") for p in paths}
    try:
        out = powershell(_PS_SIG_SCRIPT, input_text=json.dumps(paths), timeout=90)
        res = parse_signature_json(out)
        for p in paths:
            res.setdefault(p, SignatureInfo("error", detail="no result returned"))
        return res
    except Exception as e:  # PowerShell missing/blocked -> WinVerifyTrust fallback
        log.warning("Get-AuthenticodeSignature failed (%s); using WinVerifyTrust fallback", e)
        return {p: winverifytrust(p) for p in paths}


def winverifytrust(path: str) -> SignatureInfo:
    """Embedded-signature check only (no catalog lookup, no network revocation)."""
    if not IS_WINDOWS:
        return SignatureInfo("unavailable", detail="Windows only")
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                    ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)), ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                    ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    action = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    fi = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
    wd = WINTRUST_DATA()
    wd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    wd.dwUIChoice, wd.fdwRevocationChecks, wd.dwUnionChoice = 2, 0, 1
    wd.pFile = ctypes.pointer(fi)
    wd.dwStateAction, wd.dwProvFlags = 1, 0x1000 | 0x80  # cache-only URL retrieval, no revocation
    fn = ctypes.windll.wintrust.WinVerifyTrust
    fn.restype = ctypes.c_long
    rc = fn(None, ctypes.byref(action), ctypes.byref(wd)) & 0xFFFFFFFF
    wd.dwStateAction = 2
    fn(None, ctypes.byref(action), ctypes.byref(wd))
    mapping = {0: "valid", 0x800B0100: "unsigned", 0x800B0003: "unsigned", 0x800B0001: "unsigned",
               0x80096010: "tampered", 0x800B0101: "expired", 0x800B0109: "untrusted",
               0x800B0111: "untrusted", 0x80092026: "error"}
    status = mapping.get(rc, "error")
    return SignatureInfo(status, detail=f"WinVerifyTrust 0x{rc:08X} (embedded signatures only; "
                                        "catalog-signed files may appear unsigned)")


# ------------------------------------------------------ visible windows
def pids_with_visible_windows() -> set[int]:
    if not IS_WINDOWS:
        return set()
    from ctypes import wintypes
    user32 = ctypes.windll.user32
    pids: set[int] = set()
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def cb(hwnd, _lp):
        if user32.IsWindowVisible(hwnd):
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pids.add(pid.value)
        return True

    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return pids


# ---------------------------------------------------------- DNS cache
def get_dns_cache() -> list[dict]:
    """Return [{'name':..., 'type':int, 'data':...}] from the Windows DNS client cache."""
    if not IS_WINDOWS:
        return []
    try:
        out = powershell("Get-DnsClientCache | Select-Object Entry,Name,Type,Data | "
                         "ConvertTo-Json -Compress", timeout=30)
        data = json.loads(out) if out.strip() else []
        if isinstance(data, dict):
            data = [data]
        return [{"name": (d.get("Entry") or d.get("Name") or "").lower(),
                 "type": int(d.get("Type") or 0), "data": d.get("Data") or ""} for d in data]
    except Exception as e:
        log.debug("Get-DnsClientCache failed (%s); falling back to ipconfig", e)
    try:
        return parse_ipconfig_displaydns(run_hidden(["ipconfig", "/displaydns"]).stdout)
    except Exception as e:
        log.debug("ipconfig /displaydns failed: %s", e)
        return []


def parse_ipconfig_displaydns(text: str) -> list[dict]:
    """Locale-tolerant parser: associates every IP value with the record name of its block."""
    import ipaddress
    records, current, after_dash = [], "", False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if set(line) == {"-"}:
            after_dash = True
            continue
        if ":" not in line or ". :" not in raw and " : " not in raw:
            continue
        label, _, value = line.partition(" : ") if " : " in line else line.rpartition(":")
        value = value.strip()
        if after_dash or "record name" in label.lower():
            current = value.lower().rstrip(".")
            after_dash = False
            continue
        try:
            ip = ipaddress.ip_address(value)
            records.append({"name": current, "type": 28 if ip.version == 6 else 1, "data": str(ip)})
        except ValueError:
            pass
    return records


# ------------------------------------------------------------ event log
DNS_LOG = "Microsoft-Windows-DNS-Client/Operational"


def evt_query_xml(log_name: str, xpath: str, max_events: int = 500) -> str:
    r = run_hidden(["wevtutil", "qe", log_name, f"/q:{xpath}", "/f:xml", f"/c:{max_events}"], timeout=30)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[:300])
    return r.stdout


def evt_log_enabled(log_name: str) -> Optional[bool]:
    if not IS_WINDOWS:
        return None
    r = run_hidden(["wevtutil", "gl", log_name], timeout=15)
    if r.returncode != 0:
        return None
    m = re.search(r"enabled:\s*(true|false)", r.stdout, re.I)
    return (m.group(1).lower() == "true") if m else None


def evt_set_log_enabled(log_name: str, enabled: bool) -> tuple[bool, str]:
    """Requires Administrator. The change is visible in Event Viewer and fully reversible."""
    r = run_hidden(["wevtutil", "sl", log_name, f"/e:{'true' if enabled else 'false'}"], timeout=15)
    return r.returncode == 0, (r.stderr or r.stdout).strip()
