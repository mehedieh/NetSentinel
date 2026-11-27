"""Minimal stand-in for tkinter/customtkinter used ONLY when a real Tk is unavailable
(e.g. headless CI). It lets the GUI smoke test exercise page logic: data flow, table
diffing/sorting, formatting and event handling. Real rendering is tested on Windows."""
from __future__ import annotations

import sys
import types


class _Call:
    def __call__(self, *a, **k):
        return W()

    def __getattr__(self, n):
        return _Call()


class W:
    def __init__(self, *a, **k):
        self._kw = dict(k)
        self._val = None

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return _Call()

    # value-bearing widgets
    def get(self, *a):
        if self._val is not None:
            return self._val
        vals = self._kw.get("values")
        return vals[0] if vals else ""

    def set(self, v):
        self._val = v

    def select(self):
        self._val = 1

    def deselect(self):
        self._val = 0

    def insert(self, *a):
        if len(a) >= 2 and isinstance(a[1], str):
            self._val = a[1]

    def after(self, ms, fn=None, *a):
        return "after#"

    def winfo_exists(self):
        return True


class Switch(W):
    def get(self):
        return self._val or 0


class Treeview(W):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.order: list[str] = []
        self.items: dict[str, dict] = {}
        self._sel: tuple = ()

    def insert(self, parent, index, iid=None, values=(), tags=()):
        self.order.append(iid)
        self.items[iid] = {"values": values, "tags": tags}
        return iid

    def item(self, iid, **k):
        self.items[iid].update(k)

    def delete(self, iid):
        self.order.remove(iid)
        del self.items[iid]
        self._sel = tuple(s for s in self._sel if s != iid)

    def move(self, iid, parent, pos):
        self.order.remove(iid)
        self.order.insert(pos, iid)

    def index(self, iid):
        return self.order.index(iid)

    def get_children(self, *a):
        return tuple(self.order)

    def selection(self):
        return self._sel

    def selection_set(self, iid):
        self._sel = (iid,)

    def identify_row(self, y):
        return self.order[0] if self.order else ""


def install() -> None:
    tk = types.ModuleType("tkinter")
    tk.TclError = Exception
    tk.Menu = W
    tk.Tk = W
    tk.END = "end"
    ttk = types.ModuleType("tkinter.ttk")
    ttk.Treeview, ttk.Scrollbar, ttk.Style = Treeview, W, W
    mb = types.ModuleType("tkinter.messagebox")
    for n in ("showinfo", "showwarning", "showerror"):
        setattr(mb, n, lambda *a, **k: "ok")
    mb.askyesno = lambda *a, **k: False
    fd = types.ModuleType("tkinter.filedialog")
    fd.asksaveasfilename = lambda *a, **k: ""
    tk.ttk, tk.messagebox, tk.filedialog = ttk, mb, fd
    ctk = types.ModuleType("customtkinter")
    for n in ("CTk", "CTkFrame", "CTkLabel", "CTkButton", "CTkEntry", "CTkOptionMenu", "CTkSegmentedButton",
              "CTkTextbox", "CTkScrollableFrame", "CTkToplevel", "CTkTabview", "CTkFont", "CTkCheckBox"):
        setattr(ctk, n, type(n, (W,), {}))
    ctk.CTkSwitch = type("CTkSwitch", (Switch,), {})
    ctk.set_appearance_mode = ctk.set_default_color_theme = lambda *a: None
    tkagg = types.ModuleType("matplotlib.backends.backend_tkagg")

    class FigureCanvasTkAgg:
        def __init__(self, fig, master=None):
            from matplotlib.backends.backend_agg import FigureCanvasAgg
            self.agg = FigureCanvasAgg(fig)

        def get_tk_widget(self):
            return W()

        def draw_idle(self):
            self.agg.draw()   # really render, to catch plotting errors

    tkagg.FigureCanvasTkAgg = FigureCanvasTkAgg
    sys.modules.update({"tkinter": tk, "tkinter.ttk": ttk, "tkinter.messagebox": mb, "tkinter.filedialog": fd,
                        "customtkinter": ctk, "matplotlib.backends.backend_tkagg": tkagg})
    import matplotlib
    matplotlib.use("Agg", force=True)
    matplotlib.use = lambda *a, **k: None
