"""DNS & Destinations page."""
from __future__ import annotations

import json
import threading
import time
from tkinter import messagebox

import customtkinter as ctk

from gui import theme
from gui.components.dialogs import IPDialog
from gui.components.widgets import DataTable, Page, button, toolbar
from utils import windows_api
from utils.helpers import fmt_ts
from utils.permissions import is_admin


class DnsPage(Page):
    title = "DNS & Destinations"

    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("DNS & Destinations", "Domain resolution and every external endpoint contacted")
        tb = toolbar(self)
        self.search = ctk.CTkEntry(tb, placeholder_text="Filter domain / IP / app…", width=280)
        self.search.pack(side="left")
        self.search.bind("<KeyRelease>", lambda _e: self.refresh(force=True))
        self.src = ctk.CTkLabel(tb, text="", text_color=theme.MUTED, font=theme.font(11), justify="left")
        self.src.pack(side="left", padx=12)
        button(tb, "Enable DNS log…", self._enable_log, "ghost", 140).pack(side="right")
        self.tabs = ctk.CTkTabview(self, fg_color=theme.CARD, segmented_button_selected_color=theme.ACCENT,
                                   segmented_button_fg_color=theme.CARD_HI)
        self.tabs.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        self.tabs.add("DNS queries")
        self.tabs.add("Destinations")
        dq = self.tabs.tab("DNS queries")
        self.dns = DataTable(dq, [("ts", "Time", 80), ("name", "Domain", 320), ("type", "Type", 60),
                                  ("ans", "Answers", 260), ("proc", "Process (best effort)", 150),
                                  ("src", "Source", 110), ("ind", "Heuristic indicators", 300)], height=20)
        self.dns.pack(fill="both", expand=True)
        dt = self.tabs.tab("Destinations")
        bar = ctk.CTkFrame(dt, fg_color="transparent")
        bar.pack(fill="x", pady=(0, 6))
        button(bar, "Investigate", self._investigate, "primary", 110).pack(side="left")
        button(bar, "Export", lambda: self.dest.export("netsentinel-destinations"), "ghost", 90).pack(side="left", padx=6)
        self.new_only = ctk.CTkSwitch(bar, text="First seen in last 24 h", command=lambda: self.refresh(force=True))
        self.new_only.pack(side="left", padx=12)
        self.dest = DataTable(dt, [("ip", "IP address", 150), ("class", "Class", 70), ("dom", "Domains", 280),
                                   ("rdns", "Reverse DNS", 220), ("apps", "Applications", 200),
                                   ("first", "First seen", 140), ("last", "Last seen", 140), ("ti", "Threat intel", 120)],
                              height=18, on_double=lambda _i: self._investigate(),
                              menu=[("Investigate", lambda _i: self._investigate())])
        self.dest.pack(fill="both", expand=True)
        self._t = 0.0

    def refresh(self, force: bool = False):
        d = self.svc.dns
        self.src.configure(text=f"DNS Client log: {d.eventlog_status}   ·   DNS cache: {d.cache_status}   ·   "
                                f"Packet capture: {'on' if self.svc.pcap and self.svc.pcap.status == 'running' else 'off'}")
        q = self.search.get().strip().lower()
        rows = []
        for i, o in enumerate(list(d.recent)[-1500:]):
            vals = (fmt_ts(o.ts), o.name, o.qtype, ", ".join(o.answers[:4]), o.process_name or (f"PID {o.pid}" if o.pid else ""),
                    o.source, "; ".join(o.indicators))
            if q and q not in " ".join(map(str, vals)).lower():
                continue
            rows.append((f"{o.ts}-{i}", vals, "medium" if o.indicators else ""))
        self.dns.set_rows(rows[::-1])
        if force or time.time() - self._t > 5:
            self._t = time.time()
            since = time.time() - 86400 if self.new_only.get() else 0
            recs = self.svc.db.query_dicts("SELECT * FROM destinations WHERE first_seen >= ? ORDER BY last_seen DESC LIMIT 3000",
                                           (since,))
            drows = []
            for r in recs:
                ti = self.svc.ti.cached(r["ip"])
                verdict = self.svc.ti.combine(ti)[0] if ti else ""
                apps = ", ".join(json.loads(r["apps"] or "[]"))
                doms = ", ".join(json.loads(r["domains"] or "[]")[:4]) or ", ".join(d.domains_for(r["ip"])[:4])
                vals = (r["ip"], r["dest_class"], doms, r["rdns"] or d.rdns.get(r["ip"], ""), apps,
                        fmt_ts(r["first_seen"], True), fmt_ts(r["last_seen"], True), verdict or "not checked")
                if q and q not in " ".join(map(str, vals)).lower():
                    continue
                drows.append((r["ip"], vals, {"malicious": "critical", "suspicious": "medium"}.get(verdict, "")))
            self.dest.set_rows(drows)

    def _investigate(self):
        iid = self.dest.selected()
        if iid:
            IPDialog(self.app, iid)

    def _enable_log(self):
        if not windows_api.IS_WINDOWS:
            messagebox.showinfo("Windows only", "The DNS Client log exists only on Windows.")
            return
        if not is_admin():
            messagebox.showinfo("Administrator required",
                                "Enabling the Microsoft-Windows-DNS-Client/Operational log requires Administrator rights.\n"
                                "Restart NetSentinel as Administrator, or run in an elevated PowerShell:\n\n"
                                "wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true")
            return
        if not messagebox.askyesno("Enable DNS Client log",
                                   "This turns on Windows' own DNS Client operational event log (visible in Event Viewer). "
                                   "It records domain lookups locally. You can disable it again at any time with:\n"
                                   "wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:false\n\nEnable now?"):
            return
        ok, msg = windows_api.evt_set_log_enabled(windows_api.DNS_LOG, True)
        (messagebox.showinfo if ok else messagebox.showerror)("DNS Client log", "Enabled." if ok else msg)
