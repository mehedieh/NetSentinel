"""Optional packet-header capture with Scapy + Npcap.

Privacy guarantees:
  * Only header fields are read (IP addresses, ports, protocol, length) and, for DNS,
    the queried name and returned A/AAAA addresses.
  * No payload bytes are stored or logged. TLS traffic is never decrypted or inspected.
  * Capture runs only when the user enables it in Settings.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional

from core.models import DnsObservation

log = logging.getLogger(__name__)


def scapy_status() -> tuple[bool, str]:
    try:
        import scapy  # noqa: F401
    except ImportError:
        return False, "Scapy is not installed (pip install scapy)"
    try:
        from scapy.all import conf
        if hasattr(conf, "use_pcap") and not conf.use_pcap and __import__("os").name == "nt":
            return False, "Npcap not detected. Install Npcap from https://npcap.com (WinPcap-compatible mode not required)."
    except Exception as e:
        return False, f"Scapy failed to initialise: {e}"
    return True, "ready"


class PacketCapture:
    def __init__(self, local_addrs: set[str], on_bytes: Callable[..., None],
                 on_dns: Callable[[DnsObservation], None], interface: str = "",
                 count_tcp: bool = True):
        self.local_addrs = local_addrs
        self.on_bytes = on_bytes      # (proto, lport, raddr, rport, d_out, d_in)
        self.on_dns = on_dns
        self.interface = interface or None
        self.count_tcp = count_tcp    # False when EStats already measures TCP (avoid double counting)
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.status = "stopped"
        self.error = ""
        self.packets = 0

    def start(self) -> bool:
        ok, msg = scapy_status()
        if not ok:
            self.status, self.error = "unavailable", msg
            return False
        try:
            from scapy.all import AsyncSniffer
            self._sniffer = AsyncSniffer(prn=self._handle, store=False, iface=self.interface,
                                         filter="tcp or udp")
            self._sniffer.start()
            time.sleep(0.5)
            if not getattr(self._sniffer, "running", True):
                raise RuntimeError("sniffer exited immediately (permissions or interface)")
        except Exception as e:  # permission denied / Npcap missing / bad interface
            self.status, self.error = "failed", str(e)
            log.warning("Packet capture could not start: %s", e)
            return False
        self.status = "running"
        return True

    def stop(self) -> None:
        sn = getattr(self, "_sniffer", None)
        if sn is not None:
            try:
                sn.stop()
            except Exception:
                pass
        self.status = "stopped"

    def _handle(self, pkt) -> None:
        from scapy.all import DNS, IP, TCP, UDP, IPv6
        try:
            ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
            if ip is None:
                return
            if TCP in pkt:
                proto, l4 = "TCP", pkt[TCP]
            elif UDP in pkt:
                proto, l4 = "UDP", pkt[UDP]
            else:
                return
            self.packets += 1
            length = int(getattr(ip, "len", None) or getattr(ip, "plen", 0) + 40 or len(ip))
            src, dst = ip.src, ip.dst
            if src in self.local_addrs:
                lport, raddr, rport, d_out, d_in = l4.sport, dst, l4.dport, length, 0
            elif dst in self.local_addrs:
                lport, raddr, rport, d_out, d_in = l4.dport, src, l4.sport, 0, length
            else:
                return
            if proto == "UDP" and DNS in pkt and (l4.sport == 53 or l4.dport == 53):
                self._dns(pkt[DNS])
            if proto == "TCP" and not self.count_tcp:
                return
            self.on_bytes(proto, int(lport), raddr, int(rport), d_out, d_in)
        except Exception:
            log.debug("packet parse error", exc_info=True)

    def _dns(self, dns) -> None:
        try:
            if not dns.qr or not dns.qd:
                return
            qd = dns.qd[0] if hasattr(dns.qd, "__getitem__") else dns.qd
            name = qd.qname.decode(errors="replace").rstrip(".").lower()
            answers = []
            for i in range(int(dns.ancount or 0)):
                rr = dns.an[i]
                if getattr(rr, "type", 0) in (1, 28):
                    answers.append(str(rr.rdata))
            qtype = {1: "A", 28: "AAAA", 16: "TXT", 5: "CNAME", 10: "NULL", 15: "MX"}.get(int(qd.qtype), str(qd.qtype))
            self.on_dns(DnsObservation(ts=time.time(), name=name, qtype=qtype, answers=answers, source="pcap"))
        except Exception:
            log.debug("dns parse error", exc_info=True)
