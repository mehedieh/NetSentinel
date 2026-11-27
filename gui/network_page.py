"""Live Network page."""
from __future__ import annotations

import customtkinter as ctk

from gui import theme
from gui.components.dialogs import IPDialog, ProcessDialog, confirm_block
from gui.components.widgets import DataTable, Page, TextPanel, button, toolbar
from core.risk_engine import level_rank
from utils.helpers import DestClass, fmt_bytes, fmt_ts, port_service

FILTERS = ["All connections", "Internet only", "Outbound", "Inbound", "TCP", "UDP",
           "Medium risk or higher", "Listening sockets"]


class NetworkPage(Page):
    title = "Live Network"

    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Live Network", "Sockets observed in the Windows connection tables")
        tb = toolbar(self)
        self.search = ctk.CTkEntry(tb, placeholder_text="Search app, IP, domain, port…", width=300)
        self.search.pack(side="left")
        self.search.bind("<KeyRelease>", lambda _e: self.refresh())
        self.filter = ctk.CTkOptionMenu(tb, values=FILTERS, command=lambda _v: self.refresh(), width=200,
                                        fg_color=theme.CARD_HI, button_color=theme.BORDER)
        self.filter.pack(side="left", padx=8)
        self.count = ctk.CTkLabel(tb, text="", text_color=theme.MUTED, font=theme.font(11))
        self.count.pack(side="left", padx=8)
        button(tb, "Export", lambda: self.table.export("netsentinel-live-connections"), "ghost", 90).pack(side="right")
        button(tb, "Block…", self._block, "danger", 90).pack(side="right", padx=6)
        button(tb, "Investigate IP", self._ip, "ghost", 120).pack(side="right")
        button(tb, "Investigate process", self._proc, "ghost", 150).pack(side="right", padx=6)

        self.table = DataTable(self, [("time", "Time", 70), ("app", "Application", 170), ("pid", "PID", 60),
                                      ("proto", "Protocol", 65), ("local", "Local Address", 170),
                                      ("remote", "Remote Address", 250), ("port", "Port", 90),
                                      ("state", "Connection State", 110), ("traffic", "Traffic ↑/↓", 140),
                                      ("risk", "Risk Level", 100)], height=20,
                               on_select=self._select, on_double=lambda _i: self._proc(),
                               menu=[("Investigate process", lambda _i: self._proc()),
                                     ("Investigate IP", lambda _i: self._ip()),
                                     ("Block with firewall…", lambda _i: self._block())])
        self.table.pack(fill="both", expand=True, padx=24, pady=(0, 8))
        self.detail = TextPanel(self, height=120)
        self.detail.pack(fill="x", padx=24, pady=(0, 20))
        self.detail.set_text("Select a connection to see why it was scored. Traffic shows 'not measured' when "
                             "no per-connection byte source is active (see Overview > capabilities).")
        self._conns = {}

    def _rows(self):
        f = self.filter.get()
        q = self.search.get().strip().lower()
        if f == "Listening sockets":
            rows = []
            for l in self.svc.listeners():
                iid = f"L{l['pid']}-{l['proto']}-{l['laddr']}-{l['lport']}"
                vals = ("—", l["process_name"], l["pid"], l["proto"], f"{l['laddr']}:{l['lport']}", "(listening)",
                        f"{l['lport']} {port_service(l['lport'])}", "LISTEN" if l["proto"] == "TCP" else "BOUND", "", "")
                if not q or q in " ".join(map(str, vals)).lower():
                    rows.append((iid, vals, "muted"))
            return rows
        rows = []
        self._conns = {}
        for c in self.svc.connections():
            if f == "Internet only" and c.dest_class != DestClass.PUBLIC:
                continue
            if f == "Outbound" and c.direction != "outbound":
                continue
            if f == "Inbound" and c.direction != "inbound":
                continue
            if f in ("TCP", "UDP") and c.proto != f:
                continue
            if f == "Medium risk or higher" and level_rank(c.risk_level) < 2:
                continue
            remote = c.remote.rsplit(":", 1)[0] if c.raddr else ""
            if c.domain:
                remote += f"  ({c.domain})"
            elif c.dest_class != DestClass.PUBLIC and c.raddr:
                remote += f"  [{c.dest_class}]"
            traffic = (f"{fmt_bytes(c.bytes_out)} / {fmt_bytes(c.bytes_in)}" if c.bytes_out is not None
                       else "not measured")
            svc = port_service(c.rport)
            vals = (fmt_ts(c.first_seen), c.process_name, c.pid, c.proto, c.local, remote,
                    f"{c.rport} {svc}".strip(), c.state, traffic,
                    ("…" if c.risk_pending else "") + c.risk_level.capitalize())
            if q and q not in " ".join(map(str, vals)).lower() and q not in c.exe.lower():
                continue
            self._conns[c.uid] = c
            tag = c.risk_level if level_rank(c.risk_level) >= 1 else ("muted" if c.dest_class != DestClass.PUBLIC else "")
            rows.append((c.uid, vals, tag))
        return rows

    def refresh(self):
        rows = self._rows()
        self.table.set_rows(rows)
        self.count.configure(text=f"{len(rows)} shown")

    def _current(self):
        iid = self.table.selected()
        return self._conns.get(iid) if iid else None

    def _select(self, iid):
        c = self._conns.get(iid)
        if not c:
            return
        ctx = self.svc._context_for(c)
        a = self.svc.risk.assess(ctx)
        lines = [f"{c.process_name} (PID {c.pid})  {c.exe or ''}",
                 f"{c.proto} {c.direction}  {c.local} → {c.remote}  [{c.dest_class}]  state {c.state}  "
                 f"first seen {fmt_ts(c.first_seen, True)}  repeat #{c.repeat_count}",
                 f"Signature: {ctx.sig_status} {ctx.publisher}   Traffic source: {c.measure_source}",
                 f"Risk: {a.level.upper()} (score {a.score})"]
        for f in a.factors:
            lines.append(f"   {f.points:+3d}  {f.label} — {f.evidence}{'  [VERIFIED]' if f.verified else '  [heuristic]'}")
        if not a.factors:
            lines.append("   No risk factors. Public destinations are not suspicious by themselves.")
        self.detail.set_text("\n".join(lines))

    def _proc(self):
        c = self._current()
        if c:
            ProcessDialog(self.app, c.pid)

    def _ip(self):
        c = self._current()
        if c and c.raddr:
            IPDialog(self.app, c.raddr)

    def _block(self):
        c = self._current()
        if c and c.raddr:
            confirm_block(self.app, c.exe, c.raddr)
