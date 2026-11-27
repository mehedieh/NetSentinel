"""Settings page."""
from __future__ import annotations

import sys
from tkinter import messagebox

import customtkinter as ctk

from core.config import SEVERITIES
from core.network_monitor import interface_names
from gui import theme
from gui.components.widgets import Card, DataTable, Page, button
from utils import windows_api
from utils.helpers import fmt_ts
from utils.paths import data_dir
from utils.permissions import ADMIN_FEATURES, is_admin, relaunch_as_admin

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "NetSentinel"


def get_run_at_login() -> bool:
    if not windows_api.IS_WINDOWS:
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.QueryValueEx(k, RUN_NAME)
            return True
    except OSError:
        return False


def set_run_at_login(enabled: bool) -> None:
    """Visible, user-controlled startup entry (Task Manager > Startup apps). Never hidden."""
    if not windows_api.IS_WINDOWS:
        return
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if enabled:
            cmd = f'"{sys.executable}"' if getattr(sys, "frozen", False) else f'"{sys.executable}" "{sys.argv[0]}"'
            winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_SZ, cmd)
        else:
            try:
                winreg.DeleteValue(k, RUN_NAME)
            except OSError:
                pass


class SettingsPage(Page):
    title = "Settings"

    FIELDS = [
        ("Monitoring", [("monitoring.connection_interval_sec", "Connection poll interval (s)", "entry"),
                        ("monitoring.privacy_interval_sec", "Privacy poll interval (s)", "entry"),
                        ("monitoring.dns_cache_interval_sec", "DNS cache poll interval (s)", "entry"),
                        ("monitoring.dns_eventlog_interval_sec", "DNS event-log poll interval (s)", "entry"),
                        ("monitoring.autostart_monitoring", "Start monitoring when NetSentinel opens", "switch")]),
        ("Packet capture & traffic measurement", [
            ("capture.enable_estats", "Per-connection TCP byte counters (EStats, admin)", "switch"),
            ("capture.enable_packet_capture", "Packet-header capture with Npcap (admin; headers only)", "switch"),
            ("capture.interface", "Network interface", "iface")]),
        ("DNS", [("dns.read_dns_client_log", "Read Windows DNS Client operational log", "switch"),
                 ("dns.read_dns_cache", "Read Windows DNS cache for domain association", "switch"),
                 ("dns.reverse_dns", "Reverse DNS lookups (PTR queries via your resolver)", "switch")]),
        ("Correlation", [("correlation.window_before_sec", "Seconds before device access", "entry"),
                         ("correlation.window_after_sec", "Seconds after device access", "entry"),
                         ("correlation.expected_apps", "Expected communication apps (comma separated)", "wide")]),
        ("Alert thresholds", [("thresholds.upload_spike_mb_per_min", "Upload spike (MB per minute)", "entry"),
                              ("thresholds.spike_factor", "Spike factor vs. baseline", "entry"),
                              ("thresholds.new_conn_per_min", "New outbound connections per minute", "entry"),
                              ("thresholds.beacon_min_events", "Beaconing: minimum connections", "entry"),
                              ("thresholds.beacon_max_cv", "Beaconing: max interval variation (0–1)", "entry"),
                              ("thresholds.long_lived_minutes", "Long-lived connection (minutes)", "entry"),
                              ("thresholds.dns_queries_per_min_per_domain", "DNS queries/min per domain", "entry"),
                              ("thresholds.dns_unique_subdomains_5min", "Unique subdomains per 5 min", "entry"),
                              ("thresholds.correlation_upload_mb", "Correlation upload of note (MB)", "entry"),
                              ("alerts.min_severity", "Minimum alert severity", "sev"),
                              ("alerts.dedup_minutes", "Group repeated alerts for (minutes)", "entry")]),
        ("Logging retention", [("retention.days", "Keep history for (days)", "entry"),
                               ("retention.cleanup_interval_hours", "Cleanup interval (hours)", "entry")]),
        ("Privacy controls", [("privacy.store_usernames", "Record process owner (user name)", "switch")]),
    ]

    def __init__(self, master, app):
        super().__init__(master, app)
        h = self.header("Settings", f"Stored in {data_dir()}")
        button(h, "Save settings", self._save, "primary", 130).pack(side="right")
        self.scroll = ctk.CTkScrollableFrame(self, fg_color=theme.BG)
        self.scroll.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self.widgets = {}
        cfg = self.svc.config
        for section, fields in self.FIELDS:
            card = self._section(section)
            for key, label, kind in fields:
                row = ctk.CTkFrame(card, fg_color="transparent")
                row.pack(fill="x", padx=14, pady=3)
                ctk.CTkLabel(row, text=label, text_color=theme.TEXT, anchor="w", width=380).pack(side="left")
                val = cfg.get(key)
                if kind == "switch":
                    w = ctk.CTkSwitch(row, text="")
                    if val:
                        w.select()
                elif kind == "sev":
                    w = ctk.CTkOptionMenu(row, values=SEVERITIES, width=160, fg_color=theme.CARD_HI, button_color=theme.BORDER)
                    w.set(val)
                elif kind == "iface":
                    w = ctk.CTkOptionMenu(row, values=["(all interfaces)"] + interface_names(), width=260,
                                          fg_color=theme.CARD_HI, button_color=theme.BORDER)
                    w.set(val or "(all interfaces)")
                else:
                    w = ctk.CTkEntry(row, width=520 if kind == "wide" else 120)
                    w.insert(0, ", ".join(val) if isinstance(val, list) else str(val))
                w.pack(side="left")
                self.widgets[key] = (w, kind)

        st = self._section("Startup behavior")
        r = ctk.CTkFrame(st, fg_color="transparent")
        r.pack(fill="x", padx=14, pady=3)
        ctk.CTkLabel(r, text="Launch NetSentinel when I sign in (visible in Task Manager › Startup apps)",
                     anchor="w", width=380, text_color=theme.TEXT).pack(side="left")
        self.run_login = ctk.CTkSwitch(r, text="", command=self._toggle_login)
        if get_run_at_login():
            self.run_login.select()
        if not windows_api.IS_WINDOWS:
            self.run_login.configure(state="disabled")
        self.run_login.pack(side="left")

        adm = self._section("Administrator privileges")
        ctk.CTkLabel(adm, text=("Running as Administrator." if is_admin() else
                                "Running as a standard user (least privilege). These features need elevation:"),
                     anchor="w", text_color=theme.OK if is_admin() else theme.WARN).pack(fill="x", padx=14, pady=4)
        for k, v in ADMIN_FEATURES.items():
            ctk.CTkLabel(adm, text=f"• {k} — {v}", anchor="w", text_color=theme.MUTED, font=theme.font(11)).pack(fill="x", padx=24)
        if not is_admin() and windows_api.IS_WINDOWS:
            button(adm, "Restart as Administrator", self._elevate, "ghost", 190).pack(anchor="w", padx=14, pady=8)

        db = self._section("Database maintenance")
        r = ctk.CTkFrame(db, fg_color="transparent")
        r.pack(fill="x", padx=14, pady=6)
        button(r, "Apply retention now", self._cleanup, "ghost", 160).pack(side="left")
        button(r, "Compact database", self._vacuum, "ghost", 150).pack(side="left", padx=8)

        fw = self._section("Firewall rules created by NetSentinel")
        self.rules = DataTable(fw, [("name", "Rule", 220), ("exe", "Program", 360), ("ip", "Blocked destination", 160),
                                    ("created", "Created", 140), ("state", "State", 80)], height=5)
        self.rules.pack(fill="x", padx=14, pady=6)
        button(fw, "Remove selected rule", self._remove_rule, "danger", 180).pack(anchor="w", padx=14, pady=(0, 10))
        ctk.CTkLabel(self.scroll, text="Some changes (intervals, capture, DNS sources, thresholds) apply after "
                                       "restarting monitoring.", text_color=theme.MUTED, anchor="w").pack(fill="x", padx=8, pady=8)

    def _section(self, title):
        card = Card(self.scroll)
        card.pack(fill="x", padx=8, pady=6)
        ctk.CTkLabel(card, text=title, font=theme.font(14, "bold"), text_color=theme.TEXT, anchor="w").pack(fill="x", padx=14, pady=(10, 4))
        return card

    def on_show(self):
        rows = self.svc.db.query_dicts("SELECT * FROM firewall_rules ORDER BY created_at DESC")
        self.rules.set_rows([(r["name"], (r["name"], r["exe"], r["remote_ip"], fmt_ts(r["created_at"], True),
                                          "active" if r["active"] else "removed"), "" if r["active"] else "muted")
                             for r in rows])

    def _save(self):
        cfg = self.svc.config
        errors = []
        for key, (w, kind) in self.widgets.items():
            try:
                if kind == "switch":
                    v = bool(w.get())
                elif kind == "iface":
                    v = "" if w.get() == "(all interfaces)" else w.get()
                else:
                    v = w.get()
                cfg.set(key, v)
            except ValueError as e:
                errors.append(str(e))
        if errors:
            messagebox.showerror("Invalid settings", "\n".join(errors))
            return
        errs = cfg.save()
        self.svc.alert_mgr.min_severity = cfg.get("alerts.min_severity")
        self.svc.alert_mgr.dedup_seconds = cfg.get("alerts.dedup_minutes") * 60
        self.svc.correlation.window_before = cfg.get("correlation.window_before_sec")
        self.svc.correlation.window_after = cfg.get("correlation.window_after_sec")
        self.svc.correlation.expected_apps = set(cfg.get("correlation.expected_apps"))
        msg = "Settings saved." + ("\n" + "\n".join(errs) if errs else "")
        if self.svc.running and messagebox.askyesno("Saved", msg + "\n\nRestart monitoring now to apply all changes?"):
            self.app.restart_service()
        elif not self.svc.running:
            messagebox.showinfo("Saved", msg)

    def _toggle_login(self):
        try:
            set_run_at_login(bool(self.run_login.get()))
        except OSError as e:
            messagebox.showerror("Startup", str(e))

    def _elevate(self):
        if relaunch_as_admin():
            self.app.on_close()

    def _cleanup(self):
        self.svc.db.cleanup(self.svc.config.get("retention.days"))
        messagebox.showinfo("Retention", "Old records are being removed in the background.")

    def _vacuum(self):
        self.svc.db.vacuum()
        messagebox.showinfo("Database", "Database compacted.")

    def _remove_rule(self):
        name = self.rules.selected()
        if not name:
            return
        if not messagebox.askyesno("Remove rule", f"Remove firewall rule '{name}'?"):
            return
        ok, msg = self.svc.firewall.remove(name)
        (messagebox.showinfo if ok else messagebox.showerror)("Firewall", msg)
        self.svc.db.flush(1.0)
        self.on_show()
