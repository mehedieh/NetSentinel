"""Overview page."""
from __future__ import annotations

import customtkinter as ctk

from gui import theme
from gui.components.charts import RateChart
from gui.components.widgets import Card, DataTable, Page, Pill, StatCard, button
from utils.helpers import fmt_bytes, fmt_ts
from utils.permissions import relaunch_as_admin


class DashboardPage(Page):
    title = "Overview"

    def __init__(self, master, app):
        super().__init__(master, app)
        h = self.header("Security Overview", "Real-time visibility into network and device-privacy activity")
        self.toggle = button(h, "Stop monitoring", self._toggle, "ghost", 140)
        self.toggle.pack(side="right")
        if not self.svc.is_admin:
            button(h, "Restart as Administrator", self._elevate, "ghost", 190).pack(side="right", padx=8)
        self.admin_pill = Pill(h)
        self.admin_pill.pack(side="right", padx=8)
        self.status_pill = Pill(h)
        self.status_pill.pack(side="right")

        grid = ctk.CTkFrame(self, fg_color="transparent")
        grid.pack(fill="x", padx=24, pady=8)
        self.c_conn = StatCard(grid, "Active connections")
        self.c_up = StatCard(grid, "Uploaded (all interfaces)", accent="#60a5fa")
        self.c_down = StatCard(grid, "Downloaded (all interfaces)", accent="#34d399")
        self.c_susp = StatCard(grid, "Suspicious connections", accent=theme.WARN)
        self.c_mic = StatCard(grid, "Microphone", accent=theme.MUTED)
        self.c_cam = StatCard(grid, "Camera", accent=theme.MUTED)
        for i, c in enumerate([self.c_conn, self.c_up, self.c_down, self.c_susp, self.c_mic, self.c_cam]):
            c.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            grid.grid_columnconfigure(i, weight=1, uniform="cards")

        mid = ctk.CTkFrame(self, fg_color="transparent")
        mid.pack(fill="both", expand=True, padx=24, pady=8)
        mid.grid_columnconfigure(0, weight=3)
        mid.grid_columnconfigure(1, weight=2)
        mid.grid_rowconfigure(0, weight=1)
        chart_card = Card(mid)
        chart_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.chart = RateChart(chart_card, "Network activity timeline (system-wide interface rate)")
        self.chart.widget.pack(fill="both", expand=True, padx=8, pady=8)
        self.measure_lbl = ctk.CTkLabel(chart_card, text="", font=theme.font(11), text_color=theme.MUTED,
                                        wraplength=640, justify="left", anchor="w")
        self.measure_lbl.pack(fill="x", padx=12, pady=(0, 8))

        cap_card = Card(mid)
        cap_card.grid(row=0, column=1, sticky="nsew")
        ctk.CTkLabel(cap_card, text="Monitoring capabilities", font=theme.font(13, "bold"),
                     text_color=theme.TEXT, anchor="w").pack(fill="x", padx=14, pady=(12, 4))
        self.cap_table = DataTable(cap_card, [("name", "Capability", 190), ("status", "Status", 90),
                                              ("detail", "Detail", 260)], height=11)
        self.cap_table.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        al = Card(self)
        al.pack(fill="both", expand=True, padx=24, pady=(8, 20))
        top = ctk.CTkFrame(al, fg_color="transparent")
        top.pack(fill="x", padx=14, pady=(10, 4))
        ctk.CTkLabel(top, text="Recent alerts", font=theme.font(13, "bold"), text_color=theme.TEXT).pack(side="left")
        button(top, "View all", lambda: app.show("Security Alerts"), "ghost", 90).pack(side="right")
        self.alerts = DataTable(al, [("time", "Time", 80), ("sev", "Severity", 90), ("title", "Alert", 320),
                                     ("app", "Application", 160), ("dest", "Destination", 220)], height=6,
                                on_double=lambda _i: app.show("Security Alerts"))
        self.alerts.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._cap_tick = 0

    def _toggle(self):
        if self.svc.running:
            self.svc.stop()
        else:
            self.svc.start()
        self.refresh()

    def _elevate(self):
        if relaunch_as_admin():
            self.app.on_close()

    def refresh(self):
        o = self.svc.overview()
        self.status_pill.set("● Monitoring active" if o["running"] else "○ Monitoring paused",
                             theme.OK if o["running"] else theme.WARN)
        self.admin_pill.set("Administrator" if o["admin"] else "Standard user (limited)",
                            theme.OK if o["admin"] else theme.WARN)
        self.toggle.configure(text="Stop monitoring" if o["running"] else "Start monitoring")
        self.c_conn.set(str(o["active"]), f"{o['external']} to the internet · {o['listeners']} listening sockets")
        self.c_up.set(fmt_bytes(o["iface_sent"]), f"{fmt_bytes(o['rate_sent'])}/s now · since start")
        self.c_down.set(fmt_bytes(o["iface_recv"]), f"{fmt_bytes(o['rate_recv'])}/s now · since start")
        self.c_susp.set(str(o["suspicious"]), f"medium risk or higher · {o['alerts_total']} alerts this session",
                        theme.DANGER if o["suspicious"] else theme.OK)
        for card, cap in ((self.c_mic, "microphone"), (self.c_cam, "webcam")):
            st = o["privacy"].get(cap)
            if not st or st.telemetry != "available":
                card.set("Unavailable", (st.reason if st else "") or "Windows telemetry not accessible", theme.MUTED)
            elif st.active_apps:
                card.set("IN USE", "by " + ", ".join(st.active_apps[:3]), theme.DANGER)
            else:
                last = st.last_access
                card.set("Not in use", f"last: {last.display_name} {fmt_ts(last.last_start, True)}" if last else
                         "no recorded access", theme.OK)
        self.chart.update(list(self.svc.iface.history)[-600:])
        self.measure_lbl.configure(text=o["measurement"] + (f"   ⚠ Errors: {o['errors']}" if o["errors"] else ""))
        self._cap_tick += 1
        if self._cap_tick % 3 == 1:
            self.cap_table.set_rows([(c.name, (c.name, c.status, c.detail),
                                      {"active": "ok", "degraded": "medium", "unavailable": "high"}.get(c.status, "muted"))
                                     for c in self.svc.capabilities()])
        self.alerts.set_rows([(a.id, (fmt_ts(a.ts), a.severity.upper(), a.title, a.process_name, a.destination),
                               a.severity) for a in list(self.svc.recent_alerts)[:30]])
