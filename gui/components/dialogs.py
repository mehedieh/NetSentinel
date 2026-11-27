"""Investigation and confirmation dialogs."""
from __future__ import annotations

import os
import subprocess
from tkinter import messagebox

import customtkinter as ctk

from gui import theme
from gui.components.widgets import TextPanel, button
from utils.helpers import fmt_bytes, fmt_ts, port_service


class _Dialog(ctk.CTkToplevel):
    def __init__(self, app, title: str, size: str = "860x640"):
        super().__init__(app)
        self.app = app
        self.title(title)
        self.geometry(size)
        self.configure(fg_color=theme.BG)
        self.transient(app)
        self.after(150, self.lift)
        self.body = TextPanel(self, font=(theme.MONO, 12))
        self.body.pack(fill="both", expand=True, padx=16, pady=(16, 8))
        self.bar = ctk.CTkFrame(self, fg_color="transparent")
        self.bar.pack(fill="x", padx=16, pady=(0, 14))
        button(self.bar, "Close", self.destroy, "ghost", 100).pack(side="right")


class ProcessDialog(_Dialog):
    def __init__(self, app, pid: int):
        super().__init__(app, f"Investigate process — PID {pid}")
        self.pid = pid
        self.data = app.svc.investigate_process(pid)
        info = self.data["info"]
        if info.exe and os.name == "nt":
            button(self.bar, "Open file location", self._open_location, "ghost", 150).pack(side="left")
            button(self.bar, "File properties (signature)", self._props, "ghost", 190).pack(side="left", padx=8)
        self.body.set_text(self._render())

    def _render(self) -> str:
        d = self.data
        i = d["info"]
        sig = {"valid": "VERIFIED", "os": "Windows component", "pending": "checking…"}.get(i.sig_status, i.sig_status.upper())
        lines = [
            f"{i.name}  (PID {i.pid})", "=" * 72,
            f"Executable      : {i.exe or '(unavailable) ' + i.exe_note}",
            f"Owner           : {i.username or 'unavailable'}",
            f"Parent          : {i.parent_name or 'unknown'} (PPID {i.ppid})",
            f"Started         : {fmt_ts(i.create_time, True) if i.create_time else 'unknown'}",
            f"Signature       : {sig}{' — ' + i.publisher if i.publisher else ''}{' [' + i.sig_type + ']' if i.sig_type else ''}",
            f"Location check  : {('UNUSUAL — ' + i.suspicious_dir) if i.suspicious_dir else 'normal'}",
            f"Visible window  : {'yes' if i.has_window else 'no' if i.has_window is False else 'unknown'}",
            f"Process state   : {'terminated' if i.terminated else 'running'}",
            "",
            "Traffic (measured since monitoring started)",
            "-" * 72,
        ]
        if d["bytes"]:
            lines.append(f"Uploaded {fmt_bytes(d['bytes'][0])}, downloaded {fmt_bytes(d['bytes'][1])}")
        else:
            lines.append("Not measured for this process.")
        lines += [f"Note: {d['measurement']}", "", f"Active connections ({len(d['connections'])})", "-" * 72]
        for c in d["connections"]:
            lines.append(f"{c.proto:4s} {c.direction:9s} {c.local:>24s} -> {c.remote:<28s} {c.state:12s} "
                         f"{c.dest_class:9s} {c.domain}")
        if d["assessments"]:
            lines += ["", "Risk factors", "-" * 72]
            for c, a in d["assessments"]:
                lines.append(f"{c.remote}: {a.level.upper()} ({a.score})")
                for f in a.factors:
                    lines.append(f"   {f.points:+3d}  {f.label} — {f.evidence}{'  [VERIFIED]' if f.verified else ''}")
        if d["history"]:
            lines += ["", "Destination history for this executable (database)", "-" * 72]
            for h in d["history"][:60]:
                svc = port_service(h["rport"])
                lines.append(f"{h['raddr']:>39s}:{h['rport']:<5d} {h['proto']:4s} x{h['n']:<4d} "
                             f"{fmt_ts(h['first'], True)} → {fmt_ts(h['last'], True)} {svc} {h['domain'] or ''}")
        return "\n".join(lines)

    def _open_location(self):
        subprocess.Popen(["explorer.exe", "/select,", self.data["info"].exe])

    def _props(self):
        import ctypes
        ctypes.windll.shell32.ShellExecuteW(None, "properties", self.data["info"].exe, None, None, 1)


class IPDialog(_Dialog):
    def __init__(self, app, ip: str):
        super().__init__(app, f"Investigate destination — {ip}")
        self.ip = ip
        button(self.bar, "Threat-intel lookup…", self._lookup, "primary", 170).pack(side="left")
        button(self.bar, "Ownership (RDAP)", self._rdap, "ghost", 150).pack(side="left", padx=8)
        self._extra = []
        self._render()

    def _render(self):
        d = self.app.svc.investigate_ip(self.ip)
        lines = [f"Destination {self.ip}", "=" * 72,
                 f"Address class   : {d['class']}",
                 f"Domains (DNS)   : {', '.join(d['domains'][:10]) or 'none observed'}",
                 f"Reverse DNS     : {d['rdns'] or 'none / not resolved'}",
                 f"Local blocklist : {('MATCH ' + d['blocklist']) if d['blocklist'] else 'no match'}"]
        if d["geo"]:
            lines.append(f"GeoIP (approx.) : {d['geo'].get('country', '')} AS{d['geo'].get('asn', '')} {d['geo'].get('asn_org', '')}")
        rec = d["record"]
        if rec:
            lines.append(f"First seen      : {fmt_ts(rec['first_seen'], True)}   last seen {fmt_ts(rec['last_seen'], True)}")
            lines.append(f"Applications    : {rec['apps']}")
        lines += ["", "Threat intelligence (VERIFIED provider data, cached)", "-" * 72]
        if d["ti"]:
            for r in d["ti"]:
                lines.append(f"{r.provider:16s} {r.verdict.upper():10s} {r.detail}  owner={r.owner} country={r.country} "
                             f"({fmt_ts(r.ts, True)})")
        else:
            lines.append("No lookups yet. Use 'Threat-intel lookup…' (sends only this IP, after confirmation).")
        lines += self._extra
        lines += ["", f"Active connections ({len(d['connections'])})", "-" * 72]
        for c in d["connections"]:
            lines.append(f"{c.process_name} (PID {c.pid}) {c.proto} {c.local} -> {c.remote} {c.state}")
        lines += ["", "History (database)", "-" * 72]
        for h in d["history"]:
            lines.append(f"{h['process_name']:24s} port {h['rport']:<5d} {h['proto']} x{h['n']} "
                         f"{fmt_ts(h['first'], True)} → {fmt_ts(h['last'], True)}  {h['exe'] or ''}")
        self.body.set_text("\n".join(lines))

    def _lookup(self):
        ok, why = self.app.svc.ti.allowed_indicator(self.ip)
        if not ok:
            messagebox.showinfo("Not sent", why, parent=self)
            return
        provs = self.app.svc.ti.configured_providers()
        if not provs:
            messagebox.showinfo("No providers", "Configure an API key in Threat Intelligence first.", parent=self)
            return
        if not messagebox.askyesno("Confirm lookup", f"Send the IP address {self.ip} to:\n  " + "\n  ".join(provs) +
                                   "\n\nNothing else (no logs, files or process names) is sent. Continue?", parent=self):
            return
        self.app.svc.lookup_indicator(self.ip, lambda _r: self.after(0, self._render))

    def _rdap(self):
        if not self.app.svc.config.get("threat_intel.rdap_lookups"):
            messagebox.showinfo("RDAP disabled", "Enable 'RDAP ownership lookups' in Threat Intelligence first.\n"
                                "It sends the IP address to rdap.org.", parent=self)
            return

        def work():
            r = self.app.svc.ti.rdap(self.ip)
            self._extra = ["", "Network ownership (RDAP)", "-" * 72] + [f"{k:10s}: {v}" for k, v in r.items()]
            self.after(0, self._render)
        import threading
        threading.Thread(target=work, daemon=True).start()


def confirm_block(app, exe: str, ip: str) -> None:
    fw = app.svc.firewall
    plan = fw.plan(exe, ip)
    if not plan.allowed:
        messagebox.showwarning("Cannot block", plan.reason)
        return
    text = (f"Program:     {exe}\nDestination: {ip}\nRule name:   {plan.rule_name}\n\n" +
            "\n".join(f"• {c}" for c in plan.consequences) + "\n\nCreate this firewall rule?")
    if not messagebox.askyesno("Block connection — confirm", text, icon="warning"):
        return
    ok, msg = fw.block(plan)
    (messagebox.showinfo if ok else messagebox.showerror)("Firewall", msg)
