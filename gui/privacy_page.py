"""Privacy Monitor page: microphone and camera access."""
from __future__ import annotations

import customtkinter as ctk

from core.privacy_monitor import BLIND_SPOTS, CAPABILITIES
from gui import theme
from gui.components.widgets import Card, DataTable, Page, Pill, TextPanel
from utils.helpers import fmt_bytes, fmt_duration, fmt_ts

EVENT_LABEL = {"access_started": "Access started", "access_stopped": "Access stopped",
               "access_session": "Access (start+stop between polls)", "active_at_start": "Already active at start",
               "historical": "Last recorded use (before monitoring)"}


class DeviceCard(Card):
    def __init__(self, master, label: str, icon: str):
        super().__init__(master)
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(14, 4))
        ctk.CTkLabel(top, text=f"{icon}  {label}", font=theme.font(16, "bold"), text_color=theme.TEXT).pack(side="left")
        self.badge = Pill(top)
        self.badge.pack(side="right")
        self.state_lbl = ctk.CTkLabel(self, text="—", font=theme.font(22, "bold"), anchor="w")
        self.state_lbl.pack(fill="x", padx=16)
        self.lines = ctk.CTkLabel(self, text="", font=theme.font(12), text_color=theme.MUTED, anchor="w", justify="left")
        self.lines.pack(fill="x", padx=16, pady=(2, 14))

    def set_state(self, st):
        if st is None or st.telemetry != "available":
            self.badge.set("Telemetry unavailable", theme.MUTED)
            self.state_lbl.configure(text="Unknown", text_color=theme.MUTED)
            self.lines.configure(text=(st.reason if st else "") or "Windows does not expose access data here.")
            return
        self.badge.set("✔ Windows telemetry", theme.OK)
        if st.active_apps:
            self.state_lbl.configure(text="● IN USE by " + ", ".join(st.active_apps[:3]), text_color=theme.DANGER)
        else:
            self.state_lbl.configure(text="○ Not in use", text_color=theme.OK)
        last = st.last_access
        perm = lambda p: p or "not set"  # noqa: E731
        self.lines.configure(text=f"Permission — this user: {perm(st.user_permission)} · device-wide: "
                                  f"{perm(st.machine_permission)}\nLast access: "
                                  f"{(last.display_name + ' at ' + fmt_ts(last.last_start, True)) if last else 'none recorded'}")


class PrivacyPage(Page):
    title = "Privacy Monitor"

    def __init__(self, master, app):
        super().__init__(master, app)
        self.header("Privacy Monitor", "Microphone & camera access recorded by Windows (read-only — devices are never opened)")
        cards = ctk.CTkFrame(self, fg_color="transparent")
        cards.pack(fill="x", padx=24, pady=(0, 8))
        self.mic = DeviceCard(cards, "Microphone", "🎙")
        self.cam = DeviceCard(cards, "Camera", "📷")
        self.mic.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.cam.pack(side="left", fill="both", expand=True)

        self.tabs = ctk.CTkTabview(self, fg_color=theme.CARD, segmented_button_selected_color=theme.ACCENT,
                                   segmented_button_fg_color=theme.CARD_HI)
        self.tabs.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        for t in ("Apps with access history", "Events this session", "Network correlations", "Blind spots"):
            self.tabs.add(t)
        self.records = DataTable(self.tabs.tab("Apps with access history"),
                                 [("app", "Application", 180), ("cap", "Device", 90), ("kind", "Type", 80),
                                  ("status", "Status", 90), ("start", "Last access start", 150),
                                  ("stop", "Last access stop", 150), ("dur", "Duration", 80),
                                  ("perm", "Permission", 80), ("scope", "Scope", 80), ("id", "Identity", 330)], height=14)
        self.records.pack(fill="both", expand=True)
        self.events = DataTable(self.tabs.tab("Events this session"),
                                [("ts", "Time", 140), ("cap", "Device", 90), ("event", "Event", 230),
                                 ("app", "Application", 180), ("dur", "Duration", 80), ("pids", "Running PIDs", 120),
                                 ("src", "Evidence source", 220)], height=14)
        self.events.pack(fill="both", expand=True)
        self.corr = DataTable(self.tabs.tab("Network correlations"),
                              [("ts", "Device access", 90), ("cap", "Device", 90), ("app", "Application", 160),
                               ("n", "Ext. conns", 75), ("first", "First connection", 230),
                               ("up", "Uploaded in window", 200), ("exp", "Expected app", 90)], height=12)
        self.corr.pack(fill="both", expand=True)
        ctk.CTkLabel(self.tabs.tab("Network correlations"), font=theme.font(11), text_color=theme.WARN, justify="left",
                     wraplength=1000, anchor="w",
                     text="A correlation means network activity happened close in time to device access. It is NOT "
                          "evidence that audio or video was transmitted; encrypted contents are never inspected."
                     ).pack(fill="x", pady=6)
        blind = TextPanel(self.tabs.tab("Blind spots"))
        blind.pack(fill="both", expand=True)
        blind.set_text("What Windows telemetry can and cannot show\n\n" + "\n\n".join(f"• {b}" for b in BLIND_SPOTS) +
                       "\n\nStatus meanings\n• IN USE: Windows currently records the device as open by that app.\n"
                       "• Last access: the most recent start/stop timestamps Windows stored.\n"
                       "• Permission: the Allow/Deny setting from Settings > Privacy & security (not usage).")

    def refresh(self):
        states, recs = self.svc.privacy.snapshot()
        self.mic.set_state(states.get("microphone"))
        self.cam.set_state(states.get("webcam"))
        rows = []
        for r in recs:
            dur = (r.last_stop - r.last_start) if (r.last_start and r.last_stop and r.last_stop >= r.last_start) else None
            rows.append((f"{r.capability}|{r.scope}|{r.app_id}",
                         (r.display_name, CAPABILITIES.get(r.capability), r.app_kind,
                          "● ACTIVE" if r.active else ("ended" if r.last_start else "never used"),
                          fmt_ts(r.last_start, True), fmt_ts(r.last_stop, True) if not r.active else "—",
                          fmt_duration(dur), r.permission or "—", r.scope, r.app_id),
                         "active" if r.active else ("" if r.last_start else "muted")))
        self.records.set_rows(rows)
        ev = list(self.svc.recent_privacy)[-500:]
        self.events.set_rows([(str(i), (fmt_ts(e.ts, True), CAPABILITIES.get(e.capability), EVENT_LABEL.get(e.event_type, e.event_type),
                                        e.display_name, fmt_duration(e.duration), ",".join(map(str, e.pids)) or "—",
                                        "CapabilityAccessManager (" + e.scope + ")"),
                               "active" if e.event_type in ("access_started", "active_at_start") else "")
                              for i, e in enumerate(ev)])
        crow = []
        for i, r in enumerate(list(self.svc.correlation.results)):
            first = min(r.connections, key=lambda c: c.first_seen)
            up = fmt_bytes(r.upload_bytes) if r.upload_measured else f"not measured"
            crow.append((str(i), (fmt_ts(r.privacy_ts), r.capability_label, r.display_name, len(r.connections),
                                  f"{first.remote} at {fmt_ts(first.first_seen)}", up, "yes" if r.expected_app else "no"),
                         "" if r.expected_app else "medium"))
        self.corr.set_rows(crow)
