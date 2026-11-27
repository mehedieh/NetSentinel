"""Reusable widgets: cards, pills, sortable data table, text panel, page base."""
from __future__ import annotations

import csv
import json
import logging
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Optional

import customtkinter as ctk

from gui import theme

log = logging.getLogger(__name__)


class Page(ctk.CTkFrame):
    title = "Page"

    def __init__(self, master, app):
        super().__init__(master, fg_color=theme.BG, corner_radius=0)
        self.app = app
        self.svc = app.svc

    def refresh(self) -> None:  # called on the UI timer while visible
        pass

    def on_show(self) -> None:
        self.refresh()

    def header(self, title: str, subtitle: str = "") -> ctk.CTkFrame:
        f = ctk.CTkFrame(self, fg_color="transparent")
        f.pack(fill="x", padx=24, pady=(20, 8))
        ctk.CTkLabel(f, text=title, font=theme.font(22, "bold"), text_color=theme.TEXT).pack(side="left")
        if subtitle:
            ctk.CTkLabel(f, text=subtitle, font=theme.font(12), text_color=theme.MUTED).pack(side="left", padx=12, pady=(6, 0))
        return f


class Card(ctk.CTkFrame):
    def __init__(self, master, **kw):
        kw.setdefault("fg_color", theme.CARD)
        kw.setdefault("corner_radius", 10)
        kw.setdefault("border_width", 1)
        kw.setdefault("border_color", theme.BORDER)
        super().__init__(master, **kw)


class StatCard(Card):
    def __init__(self, master, title: str, value: str = "—", sub: str = "", accent: str = theme.ACCENT):
        super().__init__(master)
        self.bar = ctk.CTkFrame(self, width=4, fg_color=accent, corner_radius=2)
        self.bar.pack(side="left", fill="y", padx=(8, 0), pady=12)
        box = ctk.CTkFrame(self, fg_color="transparent")
        box.pack(side="left", fill="both", expand=True, padx=12, pady=10)
        ctk.CTkLabel(box, text=title.upper(), font=theme.font(10, "bold"), text_color=theme.MUTED, anchor="w").pack(fill="x")
        self.value = ctk.CTkLabel(box, text=value, font=theme.font(24, "bold"), text_color=theme.TEXT, anchor="w")
        self.value.pack(fill="x")
        self.sub = ctk.CTkLabel(box, text=sub, font=theme.font(11), text_color=theme.MUTED, anchor="w",
                                justify="left", wraplength=220)
        self.sub.pack(fill="x")

    def set(self, value: str, sub: str | None = None, accent: str | None = None) -> None:
        self.value.configure(text=value)
        if sub is not None:
            self.sub.configure(text=sub)
        if accent:
            self.bar.configure(fg_color=accent)


class Pill(ctk.CTkLabel):
    def __init__(self, master, text="", color=theme.MUTED):
        super().__init__(master, text=text, font=theme.font(11, "bold"), corner_radius=10,
                         fg_color=theme.CARD_HI, text_color=color, padx=10, pady=2)

    def set(self, text: str, color: str) -> None:
        self.configure(text=text, text_color=color)


class DataTable(ctk.CTkFrame):
    """ttk.Treeview with dark styling, click-to-sort headers, diff-based updates,
    severity row colouring, context menu and CSV/JSON export."""

    def __init__(self, master, columns: list[tuple[str, str, int]], height: int = 12,
                 on_select: Callable[[str], None] | None = None,
                 on_double: Callable[[str], None] | None = None,
                 menu: list[tuple[str, Callable[[str], None]]] | None = None):
        super().__init__(master, fg_color=theme.CARD, corner_radius=8)
        self.columns = columns
        self._keys = [c[0] for c in columns]
        self.tree = ttk.Treeview(self, columns=self._keys, show="headings", height=height,
                                 style="NS.Treeview", selectmode="browse")
        for key, label, width in columns:
            self.tree.heading(key, text=label, command=lambda k=key: self.sort_by(k))
            self.tree.column(key, width=width, minwidth=40, stretch=True, anchor="w")
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview, style="NS.Vertical.TScrollbar")
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(4, 0), pady=4)
        vsb.pack(side="right", fill="y", pady=4)
        for lvl, col in theme.SEVERITY.items():
            self.tree.tag_configure(lvl, foreground=col if lvl != "informational" else theme.TEXT)
        self.tree.tag_configure("muted", foreground=theme.MUTED)
        self.tree.tag_configure("active", foreground=theme.DANGER)
        self.tree.tag_configure("ok", foreground=theme.OK)
        self._rows: dict[str, tuple] = {}
        self._sort: tuple[str, bool] | None = None
        self.on_select, self.on_double = on_select, on_double
        self.tree.bind("<<TreeviewSelect>>", self._sel)
        self.tree.bind("<Double-1>", self._dbl)
        self._menu = None
        if menu:
            self._menu = tk.Menu(self, tearoff=0, bg=theme.CARD_HI, fg=theme.TEXT,
                                 activebackground=theme.ACCENT, activeforeground="white", bd=0)
            for label, fn in menu:
                self._menu.add_command(label=label, command=lambda f=fn: self._menu_call(f))
            self.tree.bind("<Button-3>", self._popup)

    # ----------------------------------------------------------------- data
    def set_rows(self, rows: list[tuple[str, tuple, str]]) -> None:
        """rows: (iid, values, tag). Only changed rows are touched."""
        new_ids = set()
        for iid, values, tag in rows:
            iid = str(iid)
            new_ids.add(iid)
            values = tuple("" if v is None else v for v in values)
            prev = self._rows.get(iid)
            if prev is None:
                self.tree.insert("", "end", iid=iid, values=values, tags=(tag,) if tag else ())
            elif prev != (values, tag):
                self.tree.item(iid, values=values, tags=(tag,) if tag else ())
            self._rows[iid] = (values, tag)
        for iid in [i for i in self._rows if i not in new_ids]:
            try:
                self.tree.delete(iid)
            except tk.TclError:
                pass
            del self._rows[iid]
        if self._sort:
            self._apply_sort()

    def clear(self) -> None:
        self.set_rows([])

    def selected(self) -> Optional[str]:
        s = self.tree.selection()
        return s[0] if s else None

    def values(self, iid: str) -> tuple:
        r = self._rows.get(iid)
        return r[0] if r else ()

    def sort_by(self, key: str) -> None:
        desc = bool(self._sort and self._sort[0] == key and not self._sort[1])
        self._sort = (key, desc)
        for k, label, _w in self.columns:
            arrow = (" ▼" if desc else " ▲") if k == key else ""
            self.tree.heading(k, text=label + arrow)
        self._apply_sort()

    def _apply_sort(self) -> None:
        key, desc = self._sort
        idx = self._keys.index(key)

        def sk(iid):
            v = self._rows[iid][0][idx] if idx < len(self._rows[iid][0]) else ""
            try:
                return (0, float(str(v).replace(",", "").split()[0]))
            except (ValueError, IndexError):
                return (1, str(v).lower())
        order = sorted(self._rows, key=sk, reverse=desc)
        for pos, iid in enumerate(order):
            if self.tree.index(iid) != pos:
                self.tree.move(iid, "", pos)

    # -------------------------------------------------------------- events
    def _sel(self, _e=None):
        if self.on_select and self.selected():
            self.on_select(self.selected())

    def _dbl(self, _e=None):
        if self.on_double and self.selected():
            self.on_double(self.selected())

    def _popup(self, e):
        iid = self.tree.identify_row(e.y)
        if iid:
            self.tree.selection_set(iid)
            self._menu.tk_popup(e.x_root, e.y_root)

    def _menu_call(self, fn):
        if self.selected():
            fn(self.selected())

    # -------------------------------------------------------------- export
    def export(self, default_name: str = "netsentinel-table") -> None:
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=default_name,
                                            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")])
        if not path:
            return
        headers = [c[1] for c in self.columns]
        data = [dict(zip(headers, self._rows[i][0])) for i in self.tree.get_children()]
        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            else:
                with open(path, "w", newline="", encoding="utf-8-sig") as f:
                    w = csv.DictWriter(f, fieldnames=headers)
                    w.writeheader()
                    w.writerows(data)
            messagebox.showinfo("Export complete", f"Saved {len(data)} rows to\n{path}")
        except OSError as e:
            messagebox.showerror("Export failed", str(e))


class TextPanel(ctk.CTkTextbox):
    def __init__(self, master, **kw):
        kw.setdefault("fg_color", theme.CARD)
        kw.setdefault("text_color", theme.TEXT)
        kw.setdefault("font", theme.font(12))
        kw.setdefault("wrap", "word")
        kw.setdefault("corner_radius", 8)
        super().__init__(master, **kw)
        self.configure(state="disabled")

    def set_text(self, text: str) -> None:
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.insert("1.0", text)
        self.configure(state="disabled")


def button(master, text, command, kind: str = "primary", width: int = 120, **kw) -> ctk.CTkButton:
    colors = {"primary": (theme.ACCENT, theme.ACCENT_HOVER, "white"),
              "ghost": (theme.CARD_HI, theme.BORDER, theme.TEXT),
              "danger": ("#7f1d1d", "#991b1b", "white")}[kind]
    return ctk.CTkButton(master, text=text, command=command, fg_color=colors[0], hover_color=colors[1],
                         text_color=colors[2], width=width, height=32, corner_radius=6,
                         font=theme.font(12, "bold"), **kw)


def toolbar(master) -> ctk.CTkFrame:
    f = ctk.CTkFrame(master, fg_color="transparent")
    f.pack(fill="x", padx=24, pady=(0, 8))
    return f
