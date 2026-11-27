"""Threat Intelligence page."""
from __future__ import annotations

import os
import subprocess
from tkinter import messagebox

import customtkinter as ctk

from core.threat_intelligence import PROVIDERS
from gui import theme
from gui.components.widgets import Card, DataTable, Page, button
from utils.helpers import fmt_ts

LABELS = {"virustotal": ("VirusTotal", "https://www.virustotal.com/gui/my-apikey"),
          "abuseipdb": ("AbuseIPDB", "https://www.abuseipdb.com/account/api"),
          "otx": ("AlienVault OTX", "https://otx.alienvault.com/settings")}


class ThreatPage(Page):
    title = "Threat Intelligence"

    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Threat Intelligence", "Optional reputation lookups — only an IP or domain is ever sent, and only with your consent")
        cfg, ti = self.svc.config, self.svc.ti
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=24)
        self.entries, self.switches = {}, {}
        for i, name in enumerate(PROVIDERS):
            label, url = LABELS[name]
            c = Card(top)
            c.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            top.grid_columnconfigure(i, weight=1, uniform="p")
            ctk.CTkLabel(c, text=label, font=theme.font(14, "bold"), text_color=theme.TEXT, anchor="w").pack(fill="x", padx=12, pady=(10, 2))
            ctk.CTkLabel(c, text=f"Key: {ti.secrets.masked(name) or 'not set'}", text_color=theme.MUTED,
                         font=theme.font(11), anchor="w").pack(fill="x", padx=12)
            e = ctk.CTkEntry(c, placeholder_text="Paste API key (stored encrypted with DPAPI)", show="•")
            e.pack(fill="x", padx=12, pady=6)
            sw = ctk.CTkSwitch(c, text="Enabled")
            if cfg.get(f"threat_intel.providers.{name}"):
                sw.select()
            sw.pack(anchor="w", padx=12, pady=(0, 10))
            self.entries[name], self.switches[name] = e, sw
            ctk.CTkLabel(c, text=url, text_color=theme.MUTED, font=theme.font(10), anchor="w").pack(fill="x", padx=12, pady=(0, 8))

        opts = Card(self)
        opts.pack(fill="x", padx=24, pady=8)
        row = ctk.CTkFrame(opts, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=10)
        ctk.CTkLabel(row, text="Lookup mode", text_color=theme.TEXT).pack(side="left")
        self.mode = ctk.CTkSegmentedButton(row, values=["off", "manual", "auto"])
        self.mode.set(cfg.get("threat_intel.mode"))
        self.mode.pack(side="left", padx=10)
        self.rdap = ctk.CTkSwitch(row, text="RDAP ownership lookups (rdap.org)")
        if cfg.get("threat_intel.rdap_lookups"):
            self.rdap.select()
        self.rdap.pack(side="left", padx=16)
        button(row, "Save", self._save, "primary", 90).pack(side="right")
        ctk.CTkLabel(opts, text="manual = only when you click Look up · auto = new public destinations are checked "
                                "automatically (requires explicit consent; respects provider rate limits)",
                     text_color=theme.MUTED, font=theme.font(11), anchor="w").pack(fill="x", padx=12, pady=(0, 10))

        lk = Card(self)
        lk.pack(fill="x", padx=24, pady=(0, 8))
        r2 = ctk.CTkFrame(lk, fg_color="transparent")
        r2.pack(fill="x", padx=12, pady=10)
        self.ind = ctk.CTkEntry(r2, placeholder_text="IP address or domain", width=320)
        self.ind.pack(side="left")
        button(r2, "Look up", self._lookup, "primary", 100).pack(side="left", padx=8)
        bl = ti.blocklist
        self.bl_lbl = ctk.CTkLabel(r2, text="", text_color=theme.MUTED, font=theme.font(11))
        self.bl_lbl.pack(side="left", padx=16)
        button(r2, "Reload blocklist", self._reload, "ghost", 130).pack(side="right")
        button(r2, "Edit blocklist", lambda: self._open(bl.path), "ghost", 120).pack(side="right", padx=6)

        self.results = DataTable(self, [("ts", "Time", 140), ("ind", "Indicator", 220), ("prov", "Provider", 130),
                                        ("verdict", "Verdict", 100), ("detail", "Detail", 420), ("owner", "Owner", 180),
                                        ("cc", "Country", 70)], height=12)
        self.results.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        self._reload(quiet=True)

    def _save(self):
        cfg, ti = self.svc.config, self.svc.ti
        for name in PROVIDERS:
            key = self.entries[name].get().strip()
            if key:
                ti.secrets.set(name, key)
                self.entries[name].delete(0, "end")
            cfg.set(f"threat_intel.providers.{name}", bool(self.switches[name].get()))
        mode = self.mode.get()
        if mode == "auto" and not cfg.get("threat_intel.auto_consent"):
            if not messagebox.askyesno("Consent required",
                                       "Automatic mode sends the IP address of each NEW public destination your "
                                       "computer contacts to the enabled providers. No other data is sent.\n\n"
                                       "Do you consent to automatic lookups?"):
                mode = "manual"
                self.mode.set("manual")
            else:
                cfg.set("threat_intel.auto_consent", True)
        if mode != "auto":
            cfg.set("threat_intel.auto_consent", False)
        cfg.set("threat_intel.mode", mode)
        cfg.set("threat_intel.rdap_lookups", bool(self.rdap.get()))
        errs = cfg.save()
        if not ti.secrets.persistent:
            errs.append("API keys are kept in memory only on this platform (DPAPI unavailable).")
        messagebox.showinfo("Saved", "Settings saved." + ("\n\n" + "\n".join(errs) if errs else ""))

    def _lookup(self):
        ind = self.ind.get().strip()
        if not ind:
            return
        ti = self.svc.ti
        ok, why = ti.allowed_indicator(ind)
        if not ok:
            messagebox.showinfo("Not sent", why)
            return
        provs = ti.configured_providers()
        if not provs:
            messagebox.showinfo("No providers", "Add an API key and enable at least one provider, then Save.")
            return
        if self.svc.config.get("threat_intel.mode") == "off":
            messagebox.showinfo("Lookups off", "Set the lookup mode to manual or auto first.")
            return
        if not messagebox.askyesno("Confirm", f"Send '{ind}' to {', '.join(provs)}?\nNothing else is sent."):
            return
        self.svc.lookup_indicator(ind, lambda _r: self.after(0, self.refresh))

    def _reload(self, quiet: bool = False):
        n = self.svc.ti.blocklist.load()
        self.bl_lbl.configure(text=f"Local blocklist: {n} entries ({self.svc.ti.blocklist.path})")
        if not quiet:
            messagebox.showinfo("Blocklist", f"Loaded {n} entries.")

    def _open(self, path):
        if os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", str(path)])

    def refresh(self):
        rows = self.svc.db.query_dicts("SELECT * FROM threat_intel ORDER BY ts DESC LIMIT 500")
        self.results.set_rows([(f"{r['indicator']}|{r['provider']}",
                                (fmt_ts(r["ts"], True), r["indicator"], r["provider"], r["verdict"].upper(), r["detail"],
                                 r["owner"] or "", r["country"] or ""),
                                {"malicious": "critical", "suspicious": "medium", "clean": "ok"}.get(r["verdict"], "muted"))
                               for r in rows])
