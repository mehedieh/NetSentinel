"""Activity History page: searchable database of past activity."""
from __future__ import annotations

import time
from tkinter import messagebox

import customtkinter as ctk

from core.reports import export_report
from gui import theme
from gui.components.dialogs import IPDialog
from gui.components.widgets import DataTable, Page, button, toolbar
from utils.helpers import fmt_bytes, fmt_ts

RANGES = {"Last hour": 3600, "Last 24 hours": 86400, "Last 7 days": 7 * 86400, "Last 30 days": 30 * 86400, "All": None}
LEVELS = {"Any risk": None, "Low+": "low", "Medium+": "medium", "High+": "high"}


class HistoryPage(Page):
    title = "Activity History"

    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Activity History", "Search every connection recorded in the local database")
        tb = toolbar(self)
        self.q = ctk.CTkEntry(tb, placeholder_text="Application, path, IP, domain or port", width=320)
        self.q.pack(side="left")
        self.q.bind("<Return>", lambda _e: self.search())
        self.range = ctk.CTkOptionMenu(tb, values=list(RANGES), width=140, fg_color=theme.CARD_HI, button_color=theme.BORDER)
        self.range.set("Last 24 hours")
        self.range.pack(side="left", padx=8)
        self.level = ctk.CTkOptionMenu(tb, values=list(LEVELS), width=120, fg_color=theme.CARD_HI, button_color=theme.BORDER)
        self.level.pack(side="left")
        button(tb, "Search", self.search, "primary", 90).pack(side="left", padx=8)
        self.info_lbl = ctk.CTkLabel(tb, text="", text_color=theme.MUTED, font=theme.font(11))
        self.info_lbl.pack(side="left", padx=8)
        button(tb, "Full report (JSON)", lambda: self._report("full", "json"), "ghost", 150).pack(side="right")
        button(tb, "Export results", lambda: self.table.export("netsentinel-history"), "ghost", 120).pack(side="right", padx=6)
        self.table = DataTable(self, [("ts", "First seen", 140), ("app", "Application", 150), ("pid", "PID", 55),
                                      ("proto", "Proto", 50), ("dir", "Direction", 75), ("remote", "Remote", 220),
                                      ("dom", "Domain", 220), ("class", "Class", 65), ("dur", "Last seen", 140),
                                      ("bytes", "↑/↓ (measured)", 130), ("risk", "Risk", 80)], height=22,
                               on_double=self._ip, menu=[("Investigate destination", self._ip)])
        self.table.pack(fill="both", expand=True, padx=24, pady=(0, 8))
        self.stats = ctk.CTkLabel(self, text="", text_color=theme.MUTED, font=theme.font(11), anchor="w")
        self.stats.pack(fill="x", padx=24, pady=(0, 16))
        self._rows = {}

    def on_show(self):
        self.search()

    def search(self):
        self.svc.db.flush(1.0)
        span = RANGES[self.range.get()]
        since = time.time() - span if span else 0
        rows = self.svc.db.search_connections(self.q.get().strip(), since, None, LEVELS[self.level.get()], 5000)
        self._rows = {r["uid"]: r for r in rows}
        self.table.set_rows([(r["uid"], (fmt_ts(r["first_seen"], True), r["process_name"], r["pid"], r["proto"],
                                         r["direction"], f"{r['raddr']}:{r['rport']}" if r["raddr"] else "",
                                         r["domain"] or "", r["dest_class"], fmt_ts(r["last_seen"], True),
                                         f"{fmt_bytes(r['bytes_out'])} / {fmt_bytes(r['bytes_in'])}" if r["bytes_out"] is not None else "not measured",
                                         (r["risk_level"] or "").capitalize()),
                               r["risk_level"] if r["risk_level"] not in (None, "informational") else "")
                              for r in rows])
        self.info_lbl.configure(text=f"{len(rows)} records" + (" (limit reached)" if len(rows) >= 5000 else ""))
        s = self.svc.db.stats()
        self.stats.configure(text=f"Database: {fmt_bytes(s['size_bytes'])} · {s['connections']} connections · "
                                  f"{s['dns_queries']} DNS records · {s['privacy_events']} privacy events · "
                                  f"{s['alerts']} alerts · retention {self.svc.config.get('retention.days')} days")

    def _ip(self, iid):
        r = self._rows.get(iid)
        if r and r["raddr"]:
            IPDialog(self.app, r["raddr"])

    def _report(self, kind, fmt):
        span = RANGES[self.range.get()]
        p = export_report(self.svc.db, kind, fmt, since=time.time() - span if span else 0)
        messagebox.showinfo("Report exported", f"Saved to\n{p}")
