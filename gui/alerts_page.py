"""Security Alerts page."""
from __future__ import annotations

import json
import time
from tkinter import messagebox

import customtkinter as ctk

from core.reports import export_report
from gui import theme
from gui.components.dialogs import IPDialog
from gui.components.widgets import DataTable, Page, TextPanel, button, toolbar
from utils.helpers import fmt_ts

SEV_FILTER = {"All": None, "Critical": ["critical"], "High+": ["critical", "high"],
              "Medium+": ["critical", "high", "medium"], "Low": ["low"], "Info": ["informational"]}


class AlertsPage(Page):
    title = "Security Alerts"

    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Security Alerts", "Every alert shows what, why, evidence, uncertainty and next steps")
        tb = toolbar(self)
        self.sev = ctk.CTkSegmentedButton(tb, values=list(SEV_FILTER), command=lambda _v: self.refresh(force=True),
                                          selected_color=theme.ACCENT)
        self.sev.set("All")
        self.sev.pack(side="left")
        self.range = ctk.CTkOptionMenu(tb, values=["This session", "24 hours", "7 days", "All time"], width=140,
                                       command=lambda _v: self.refresh(force=True), fg_color=theme.CARD_HI,
                                       button_color=theme.BORDER)
        self.range.pack(side="left", padx=8)
        self.hide_ack = ctk.CTkSwitch(tb, text="Hide acknowledged", command=lambda: self.refresh(force=True))
        self.hide_ack.pack(side="left", padx=8)
        button(tb, "Export JSON", lambda: self._export("json"), "ghost", 110).pack(side="right")
        button(tb, "Export CSV", lambda: self._export("csv"), "ghost", 100).pack(side="right", padx=6)
        button(tb, "Acknowledge", self._ack, "primary", 110).pack(side="right")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)
        self.table = DataTable(body, [("ts", "Time", 130), ("sev", "Severity", 85), ("cat", "Category", 120),
                                      ("title", "Alert", 280), ("app", "Application", 140), ("dest", "Destination", 200),
                                      ("n", "Count", 55), ("ack", "Ack", 40)], height=22, on_select=self._select,
                               menu=[("Investigate destination", lambda i: self._ip(i)), ("Acknowledge", lambda _i: self._ack())])
        self.table.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.detail = TextPanel(body, font=(theme.MONO, 11))
        self.detail.grid(row=0, column=1, sticky="nsew")
        self._alerts: dict[str, dict] = {}
        self._t = 0.0
        self._seen_count = -1

    def _since(self) -> float:
        r = self.range.get()
        now = time.time()
        return {"This session": self.svc.started_at or now, "24 hours": now - 86400, "7 days": now - 7 * 86400}.get(r, 0)

    def refresh(self, force: bool = False):
        if not force and self._seen_count == self.svc.counters["alerts"] and time.time() - self._t < 10:
            return
        if not force and time.time() - self._t < 2:
            return  # let the DB writer commit the newest alert first (avoids blocking the UI)
        self._seen_count, self._t = self.svc.counters["alerts"], time.time()
        rows = self.svc.db.alerts(SEV_FILTER[self.sev.get()], self._since(), 3000)
        self._alerts = {r["id"]: r for r in rows}
        self.table.set_rows([(r["id"], (fmt_ts(r["ts"], True), r["severity"].upper(), r["category"], r["title"],
                                        r["process_name"], r["destination"], r["count"], "✔" if r["acknowledged"] else ""),
                              "muted" if r["acknowledged"] else r["severity"])
                             for r in rows if not (self.hide_ack.get() and r["acknowledged"])])

    def _select(self, iid):
        a = self._alerts.get(iid)
        if not a:
            return
        lines = [a["title"], "═" * 60, f"Severity   : {a['severity'].upper()}  (score {a['score']})",
                 f"Time       : {fmt_ts(a['ts'], True)}", f"Category   : {a['category']}",
                 f"Application: {a['process_name']} (PID {a['pid']})", f"Executable : {a['exe'] or 'unavailable'}",
                 f"Destination: {a['destination'] or '—'}", "",
                 "1. WHAT WAS DETECTED", a["what"], "", "2. WHY IT WAS FLAGGED", a["why"], "",
                 "3. SUPPORTING EVIDENCE"]
        lines += [f" • {e}" for e in a["evidence"]]
        lines += ["", "4. WHAT REMAINS UNCERTAIN", a["uncertainty"], "", "5. RECOMMENDED INVESTIGATION STEPS"]
        lines += [f" • {r}" for r in a["recommendations"]]
        lines += ["", "Score breakdown"]
        lines += [f"   {f['points']:+3d}  {f['label']}{'  [VERIFIED]' if f['verified'] else '  [heuristic]'}" for f in a["factors"]]
        if a["count"] > 1:
            lines += ["", f"Grouped: seen {a['count']} times within the de-duplication window."]
        self.detail.set_text("\n".join(lines))

    def _ack(self):
        iid = self.table.selected()
        if not iid:
            return
        self.svc.db.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (iid,))
        for a in self.svc.recent_alerts:
            if a.id == iid:
                a.acknowledged = True
        self.svc.db.flush(1.0)
        self.refresh(force=True)

    def _ip(self, iid):
        a = self._alerts.get(iid)
        if a and a["destination"]:
            host = a["destination"].split(" ")[0]
            ip = host.rsplit(":", 1)[0].strip("[]") if host.count(":") == 1 or host.startswith("[") else host
            IPDialog(self.app, ip)

    def _export(self, fmt):
        p = export_report(self.svc.db, "alerts", fmt, since=self._since())
        messagebox.showinfo("Report exported", f"Saved to\n{p}")
