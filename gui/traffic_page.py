"""Traffic Analysis page."""
from __future__ import annotations

import time

import customtkinter as ctk

from gui import theme
from gui.components.charts import BarChart, HourlyChart
from gui.components.widgets import Card, DataTable, Page
from utils.helpers import exe_basename, fmt_bytes, fmt_duration, fmt_ts


class TrafficPage(Page):
    title = "Traffic Analysis"

    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Traffic Analysis", "Measured volume, patterns and long-lived connections")
        self.note = ctk.CTkLabel(self, text="", font=theme.font(12), text_color=theme.WARN, anchor="w",
                                 justify="left", wraplength=1100)
        self.note.pack(fill="x", padx=24, pady=(0, 6))
        charts = ctk.CTkFrame(self, fg_color="transparent")
        charts.pack(fill="both", expand=True, padx=24)
        for i in range(3):
            charts.grid_columnconfigure(i, weight=1, uniform="c")
        charts.grid_rowconfigure(0, weight=1)
        c1, c2, c3 = Card(charts), Card(charts), Card(charts)
        for i, c in enumerate((c1, c2, c3)):
            c.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
        self.apps = BarChart(c1, "Top applications (measured)", 2.8)
        self.apps.widget.pack(fill="both", expand=True, padx=6, pady=6)
        self.proto = BarChart(c2, "By protocol (measured)", 2.8)
        self.proto.widget.pack(fill="both", expand=True, padx=6, pady=6)
        self.hourly = HourlyChart(c3, "Hourly system traffic (last 24 h, all interfaces)", 2.8)
        self.hourly.widget.pack(fill="both", expand=True, padx=6, pady=6)

        self.tabs = ctk.CTkTabview(self, fg_color=theme.CARD, segmented_button_selected_color=theme.ACCENT,
                                   segmented_button_fg_color=theme.CARD_HI, height=300)
        self.tabs.pack(fill="both", expand=True, padx=24, pady=(8, 20))
        for t in ("Top destinations", "Beaconing indicators", "Long-lived connections", "Daily totals"):
            self.tabs.add(t)
        self.dest = DataTable(self.tabs.tab("Top destinations"), [("r", "Destination", 260), ("dom", "Domain", 260),
                                                                  ("up", "Uploaded", 110), ("down", "Downloaded", 110)], height=8)
        self.dest.pack(fill="both", expand=True)
        self.beacon = DataTable(self.tabs.tab("Beaconing indicators"),
                                [("app", "Application", 180), ("dest", "Destination", 220), ("n", "Connections", 90),
                                 ("iv", "Mean interval", 100), ("cv", "Regularity (CV)", 110), ("span", "Observed", 200)], height=8)
        self.beacon.pack(fill="both", expand=True)
        self.longl = DataTable(self.tabs.tab("Long-lived connections"),
                               [("app", "Application", 180), ("dest", "Destination", 260), ("dom", "Domain", 220),
                                ("age", "Open for", 100), ("up", "↑", 90), ("down", "↓", 90)], height=8)
        self.longl.pack(fill="both", expand=True)
        self.daily = DataTable(self.tabs.tab("Daily totals"), [("d", "Day", 140), ("s", "Sent", 120), ("r", "Received", 120)], height=8)
        self.daily.pack(fill="both", expand=True)
        self._t = 0

    def refresh(self):
        self.note.configure(text="ⓘ " + self.svc.measurement_note() +
                            " HTTPS/QUIC contents are encrypted and never inspected.")
        tr = self.svc.tracker
        self.apps.update([(n or exe_basename(e) or e, o, i) for e, n, o, i in tr.top_apps(8)],
                         "No per-application measurements.\nRun as Administrator to enable TCP counters.")
        self.proto.update([(k, v[0], v[1]) for k, v in sorted(tr.protocols().items())], "No measurements")
        self.dest.set_rows([(r, (r, self.svc.dns.domain_for(r), fmt_bytes(o), fmt_bytes(i)), "")
                            for r, o, i in tr.top_remotes(50)])
        self.beacon.set_rows([(f"{b.exe}|{b.raddr}|{b.rport}",
                               (b.process_name or exe_basename(b.exe), f"{b.raddr}:{b.rport}", b.count,
                                f"{b.mean_interval:.0f}s", f"{b.cv:.2f}", f"{fmt_ts(b.first)} – {fmt_ts(b.last)}"), "medium")
                              for b in self.svc.beacons.analyze()])
        now = time.time()
        self.longl.set_rows([(c.uid, (c.process_name, c.remote, c.domain, fmt_duration(now - c.first_seen),
                                      fmt_bytes(c.bytes_out), fmt_bytes(c.bytes_in)), "")
                             for c in self.svc.long_lived()])
        if now - self._t > 30:
            self._t = now
            rows = self.svc.db.hourly_interface(now - 86400)
            self.hourly.update([(r["hour_ts"], r["bytes_sent"], r["bytes_recv"]) for r in rows])
            self.daily.set_rows([(r["day_ts"], (fmt_ts(r["day_ts"], True)[:10], fmt_bytes(r["bytes_sent"]),
                                                fmt_bytes(r["bytes_recv"])), "")
                                 for r in self.svc.db.daily_traffic(now - 30 * 86400)])
