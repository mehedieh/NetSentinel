"""Applications page: per-process network activity."""
from __future__ import annotations

import customtkinter as ctk

from gui import theme
from gui.components.dialogs import ProcessDialog
from gui.components.widgets import DataTable, Page, TextPanel, button, toolbar
from utils.helpers import fmt_bytes, fmt_ts

SIG_LABEL = {"valid": "✔ Verified", "os": "✔ Windows", "pending": "… checking", "unsigned": "Unsigned",
             "tampered": "✖ INVALID", "untrusted": "Untrusted", "expired": "Expired",
             "unavailable": "n/a", "error": "Error"}


class ApplicationsPage(Page):
    title = "Applications"

    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Applications", "Processes with network sockets, their identity and measured traffic")
        tb = toolbar(self)
        self.search = ctk.CTkEntry(tb, placeholder_text="Filter applications…", width=280)
        self.search.pack(side="left")
        self.search.bind("<KeyRelease>", lambda _e: self.refresh())
        self.only_ext = ctk.CTkSwitch(tb, text="Internet-connected only", command=self.refresh)
        self.only_ext.pack(side="left", padx=12)
        button(tb, "Export", lambda: self.table.export("netsentinel-applications"), "ghost", 90).pack(side="right")
        button(tb, "Investigate", self._investigate, "primary", 110).pack(side="right", padx=6)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)
        self.table = DataTable(body, [("app", "Application", 160), ("pid", "PID", 60), ("sig", "Signature", 100),
                                      ("pub", "Publisher", 160), ("conns", "Conns", 55), ("ext", "External", 65),
                                      ("up", "Uploaded", 85), ("down", "Downloaded", 90), ("first", "First seen", 80),
                                      ("last", "Last seen", 80), ("risk", "Risk", 85)], height=22,
                               on_select=self._select, on_double=lambda _i: self._investigate())
        self.table.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.detail = TextPanel(body, font=(theme.MONO, 11))
        self.detail.grid(row=0, column=1, sticky="nsew")
        self.detail.set_text("Select an application.\n\nUnsigned does not mean malicious: many legitimate "
                             "open-source tools are unsigned. NetSentinel combines several signals before raising alerts.")
        self._apps = {}

    def refresh(self):
        q = self.search.get().strip().lower()
        rows = []
        self._apps = {}
        for a in self.svc.applications():
            if self.only_ext.get() and not a["external"]:
                continue
            if q and q not in (a["name"] + a["exe"] + a["publisher"]).lower():
                continue
            self._apps[str(a["pid"])] = a
            measured = a["bytes_out"] is not None
            rows.append((a["pid"], (a["name"], a["pid"], SIG_LABEL.get(a["sig_status"], a["sig_status"]),
                                    a["publisher"], a["connections"], a["external"],
                                    fmt_bytes(a["bytes_out"]) if measured else "—",
                                    fmt_bytes(a["bytes_in"]) if measured else "—",
                                    fmt_ts(a["first_seen"]), fmt_ts(a["last_seen"]), a["risk_level"].capitalize()),
                         a["risk_level"] if a["risk_level"] != "informational" else
                         ("high" if a["sig_status"] == "tampered" else "")))
        self.table.set_rows(rows)
        sel = self.table.selected()
        if sel:
            self._select(sel)

    def _select(self, iid):
        a = self._apps.get(iid)
        if not a:
            return
        lines = [a["name"], "─" * 44,
                 f"PID        {a['pid']}", f"Path       {a['exe'] or a['exe_note'] or 'unavailable'}",
                 f"Owner      {a['username'] or 'unavailable'}",
                 f"Parent     {a['parent_name'] or '?'} ({a['ppid']})",
                 f"Signature  {SIG_LABEL.get(a['sig_status'], a['sig_status'])} {a['publisher']} {a['sig_type']}",
                 f"Location   {'⚠ ' + a['suspicious_dir'] if a['suspicious_dir'] else 'normal'}",
                 f"Window     {'visible' if a['has_window'] else 'background' if a['has_window'] is False else 'unknown'}",
                 f"Traffic    ↑ {fmt_bytes(a['bytes_out'])}  ↓ {fmt_bytes(a['bytes_in'])}",
                 f"Risk       {a['risk_level']} ({a['risk_score']})", "",
                 f"External destinations ({len(a['destinations'])})"]
        lines += [f"  • {d}" for d in a["destinations"][:40]]
        self.detail.set_text("\n".join(lines))

    def _investigate(self):
        iid = self.table.selected()
        if iid:
            ProcessDialog(self.app, int(iid))
