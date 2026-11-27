"""Main window: sidebar navigation, page host, UI timer and event draining."""
from __future__ import annotations

import logging
import time
import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk

from core.config import Config
from core.monitor_service import MonitorService
from core.risk_engine import level_rank
from gui import theme
from utils.paths import asset_path
from utils.permissions import compatibility_report

log = logging.getLogger(__name__)

NAV = [("Overview", "⌂"), ("Live Network", "⇅"), ("Applications", "▦"), ("Privacy Monitor", "◉"),
       ("DNS & Destinations", "◎"), ("Traffic Analysis", "▤"), ("Threat Intelligence", "⛨"),
       ("Security Alerts", "⚠"), ("Activity History", "⟲"), ("Settings", "⚙")]


def _page_classes():
    from gui.alerts_page import AlertsPage
    from gui.applications_page import ApplicationsPage
    from gui.dashboard import DashboardPage
    from gui.dns_page import DnsPage
    from gui.history_page import HistoryPage
    from gui.network_page import NetworkPage
    from gui.privacy_page import PrivacyPage
    from gui.settings_page import SettingsPage
    from gui.threat_page import ThreatPage
    from gui.traffic_page import TrafficPage
    return {"Overview": DashboardPage, "Live Network": NetworkPage, "Applications": ApplicationsPage,
            "Privacy Monitor": PrivacyPage, "DNS & Destinations": DnsPage, "Traffic Analysis": TrafficPage,
            "Threat Intelligence": ThreatPage, "Security Alerts": AlertsPage, "Activity History": HistoryPage,
            "Settings": SettingsPage}


class MainWindow(ctk.CTk):
    def __init__(self, config: Config):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        super().__init__(fg_color=theme.BG)
        self.config_obj = config
        self.svc = MonitorService(config)
        self.title("NetSentinel — Privacy & Network Security Monitor")
        self.geometry("1480x900")
        self.minsize(1180, 720)
        try:
            ico = asset_path("netsentinel.ico")
            if ico.exists():
                self.iconbitmap(str(ico))
        except tk.TclError:
            pass
        theme.apply_ttk_style(self)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._classes = _page_classes()
        self.pages: dict[str, ctk.CTkFrame] = {}
        self.current: str | None = None
        self.new_alerts = 0
        self._build()
        if config.errors:
            self.after(800, lambda: messagebox.showwarning("Settings", "\n".join(config.errors)))
        for w in compatibility_report()["warnings"]:
            log.warning(w)
        if config.get("monitoring.autostart_monitoring"):
            self.svc.start()
        start = config.get("ui.start_page")
        self.show(start if start in self._classes else "Overview")
        self.after(300, self._tick)

    # ------------------------------------------------------------- layout
    def _build(self):
        self.sidebar = ctk.CTkFrame(self, width=236, fg_color=theme.SIDEBAR, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=18, pady=(22, 18))
        ctk.CTkLabel(brand, text="⛊ NetSentinel", font=theme.font(20, "bold"), text_color=theme.TEXT, anchor="w").pack(fill="x")
        ctk.CTkLabel(brand, text="Privacy & Network Security", font=theme.font(11), text_color=theme.MUTED, anchor="w").pack(fill="x")
        self.nav_btns = {}
        for name, icon in NAV:
            b = ctk.CTkButton(self.sidebar, text=f"  {icon}   {name}", anchor="w", height=38, corner_radius=6,
                              fg_color="transparent", hover_color=theme.CARD_HI, text_color=theme.MUTED,
                              font=theme.font(13), command=lambda n=name: self.show(n))
            b.pack(fill="x", padx=10, pady=1)
            self.nav_btns[name] = b
        foot = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        foot.pack(side="bottom", fill="x", padx=18, pady=16)
        self.foot_status = ctk.CTkLabel(foot, text="", font=theme.font(11), text_color=theme.MUTED, anchor="w", justify="left")
        self.foot_status.pack(fill="x")

        right = ctk.CTkFrame(self, fg_color=theme.BG, corner_radius=0)
        right.pack(side="left", fill="both", expand=True)
        self.banner = ctk.CTkButton(right, text="", height=34, corner_radius=0, fg_color="#3b1d1d",
                                    hover_color="#4c2424", text_color="#fecaca", font=theme.font(12, "bold"),
                                    anchor="w", command=lambda: self.show("Security Alerts"))
        self._banner_until = 0.0
        self.host = ctk.CTkFrame(right, fg_color=theme.BG, corner_radius=0)
        self.host.pack(fill="both", expand=True)

    def show(self, name: str):
        if name not in self._classes:
            return
        if self.current and self.current in self.pages:
            self.pages[self.current].pack_forget()
        if name not in self.pages:
            try:
                self.pages[name] = self._classes[name](self.host, self)
            except Exception as e:
                log.exception("Failed to build page %s", name)
                messagebox.showerror("NetSentinel", f"Could not open {name}: {e}")
                return
        self.pages[name].pack(fill="both", expand=True)
        self.current = name
        for n, b in self.nav_btns.items():
            sel = n == name
            b.configure(fg_color=theme.CARD_HI if sel else "transparent", text_color=theme.TEXT if sel else theme.MUTED)
        if name == "Security Alerts":
            self.new_alerts = 0
            self._update_alert_badge()
        try:
            self.pages[name].on_show()
        except Exception:
            log.exception("on_show failed for %s", name)

    # ---------------------------------------------------------- UI timer
    def _tick(self):
        try:
            self._drain_events()
            if self.current:
                self.pages[self.current].refresh()
            self._footer()
            if self._banner_until and time.time() > self._banner_until:
                self.banner.pack_forget()
                self._banner_until = 0
        except Exception:
            log.exception("UI refresh failed")
        self.after(self.config_obj.get("ui.refresh_ms"), self._tick)

    def _drain_events(self):
        for _ in range(500):
            try:
                topic, payload = self.svc.events.get_nowait()
            except Exception:
                break
            if topic == "alert":
                if self.current != "Security Alerts":
                    self.new_alerts += 1
                if level_rank(payload.severity) >= 3:
                    self._show_banner(f"  ⚠  {payload.severity.upper()}: {payload.title} — {payload.process_name} "
                                      f"{payload.destination}   (click to review)")
        self._update_alert_badge()

    def _show_banner(self, text: str):
        self.banner.configure(text=text)
        if not self._banner_until:
            self.banner.pack(fill="x", before=self.host)
        self._banner_until = time.time() + 12

    def _update_alert_badge(self):
        b = self.nav_btns["Security Alerts"]
        b.configure(text=f"  ⚠   Security Alerts" + (f"  ({self.new_alerts})" if self.new_alerts else ""))

    def _footer(self):
        s = self.svc
        state = "● Monitoring" if s.running else "○ Paused"
        err = f"\n⚠ {len(s.component_errors)} component error(s)" if s.component_errors else ""
        self.foot_status.configure(text=f"{state}\n{'Administrator' if s.is_admin else 'Standard user'}{err}",
                                   text_color=theme.OK if s.running and not err else theme.WARN)

    # --------------------------------------------------------- lifecycle
    def restart_service(self):
        was_running = self.svc.running
        self.svc.shutdown()
        self.svc = MonitorService(self.config_obj)
        for p in self.pages.values():
            p.destroy()
        self.pages.clear()
        cur = self.current or "Overview"
        self.current = None
        if was_running:
            self.svc.start()
        self.show(cur)

    def on_close(self):
        self.foot_status.configure(text="Stopping…")
        self.update_idletasks()
        try:
            self.svc.shutdown()
        except Exception:
            log.exception("Shutdown error")
        self.destroy()


def run_gui() -> int:
    cfg = Config()
    app = MainWindow(cfg)
    app.mainloop()
    return 0
