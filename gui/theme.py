"""Dark Fluent-inspired palette and ttk styling."""
from __future__ import annotations

import os

FONT = "Segoe UI" if os.name == "nt" else "Helvetica"
MONO = "Cascadia Mono" if os.name == "nt" else "Courier"

BG = "#0b0e14"
SIDEBAR = "#0f131b"
CARD = "#151a23"
CARD_HI = "#1b2230"
BORDER = "#242c3b"
TEXT = "#e6e9ef"
MUTED = "#8b95a7"
ACCENT = "#3b82f6"
ACCENT_HOVER = "#2563eb"
OK = "#22c55e"
WARN = "#f59e0b"
DANGER = "#ef4444"

SEVERITY = {"informational": "#64748b", "low": "#38bdf8", "medium": "#f59e0b",
            "high": "#f97316", "critical": "#ef4444"}
STATUS = {"active": OK, "degraded": WARN, "unavailable": DANGER, "disabled": MUTED,
          "available": OK, "unknown": MUTED}


def font(size: int = 13, weight: str = "normal"):
    import customtkinter as ctk
    return ctk.CTkFont(family=FONT, size=size, weight=weight)


def apply_ttk_style(root) -> None:
    from tkinter import ttk
    st = ttk.Style(root)
    try:
        st.theme_use("clam")
    except Exception:
        pass
    st.configure("NS.Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT,
                 rowheight=26, borderwidth=0, relief="flat", font=(FONT, 10))
    st.configure("NS.Treeview.Heading", background=CARD_HI, foreground=MUTED, relief="flat",
                 borderwidth=0, font=(FONT, 10, "bold"), padding=(6, 6))
    st.map("NS.Treeview", background=[("selected", "#1e3a5f")], foreground=[("selected", TEXT)])
    st.map("NS.Treeview.Heading", background=[("active", BORDER)])
    st.layout("NS.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
    st.configure("NS.Vertical.TScrollbar", background=CARD_HI, troughcolor=CARD, bordercolor=CARD,
                 arrowcolor=MUTED, relief="flat")
