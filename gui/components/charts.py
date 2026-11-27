"""Matplotlib charts embedded in CustomTkinter, styled to match the dark theme."""
from __future__ import annotations

import datetime as dt

import matplotlib

matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

from gui import theme  # noqa: E402
from utils.helpers import fmt_bytes  # noqa: E402

UP = "#60a5fa"     # upload
DOWN = "#34d399"   # download


def _style(ax, fig):
    fig.patch.set_facecolor(theme.CARD)
    ax.set_facecolor(theme.CARD)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(theme.BORDER)
    ax.tick_params(colors=theme.MUTED, labelsize=8)
    ax.grid(axis="y", color=theme.BORDER, linewidth=0.6, alpha=0.7)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _p: fmt_bytes(v)))


class _Chart:
    def __init__(self, master, title: str, height: float = 2.4):
        self.fig = Figure(figsize=(6, height), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.title = title
        self.canvas = FigureCanvasTkAgg(self.fig, master=master)
        self.widget = self.canvas.get_tk_widget()
        self.widget.configure(bg=theme.CARD, highlightthickness=0)
        self._sig = None

    def _finish(self):
        self.ax.set_title(self.title, color=theme.TEXT, fontsize=10, loc="left")
        self.fig.tight_layout(pad=1.2)
        self.canvas.draw_idle()

    def _empty(self, msg: str):
        self.ax.clear()
        _style(self.ax, self.fig)
        self.ax.text(0.5, 0.5, msg, ha="center", va="center", color=theme.MUTED, fontsize=9,
                     transform=self.ax.transAxes, wrap=True)
        self.ax.set_xticks([])
        self.ax.set_yticks([])
        self._finish()


class RateChart(_Chart):
    """Upload/download rate over time (bytes/s)."""

    def update(self, series: list[tuple[float, float, float]]) -> None:
        sig = (len(series), series[-1][0] if series else 0)
        if sig == self._sig:
            return
        self._sig = sig
        if len(series) < 2:
            return self._empty("Collecting interface samples…")
        self.ax.clear()
        _style(self.ax, self.fig)
        xs = [dt.datetime.fromtimestamp(t) for t, _s, _r in series]
        self.ax.fill_between(xs, [s for _t, s, _r in series], color=UP, alpha=0.25, linewidth=0)
        self.ax.plot(xs, [s for _t, s, _r in series], color=UP, linewidth=1.4, label="Upload /s")
        self.ax.fill_between(xs, [r for _t, _s, r in series], color=DOWN, alpha=0.18, linewidth=0)
        self.ax.plot(xs, [r for _t, _s, r in series], color=DOWN, linewidth=1.4, label="Download /s")
        import matplotlib.dates as mdates
        self.ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        leg = self.ax.legend(loc="upper left", fontsize=8, frameon=False)
        for t in leg.get_texts():
            t.set_color(theme.MUTED)
        self._finish()


class BarChart(_Chart):
    """Grouped horizontal bars (upload/download) for labelled items."""

    def update(self, items: list[tuple[str, float, float]], empty_msg: str = "No measured data") -> None:
        sig = tuple(items)
        if sig == self._sig:
            return
        self._sig = sig
        if not items:
            return self._empty(empty_msg)
        self.ax.clear()
        _style(self.ax, self.fig)
        self.ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _p: fmt_bytes(v)))
        self.ax.yaxis.set_major_formatter(matplotlib.ticker.NullFormatter())
        self.ax.grid(axis="x", color=theme.BORDER, linewidth=0.6, alpha=0.7)
        self.ax.grid(axis="y", visible=False)
        items = list(reversed(items))
        ys = range(len(items))
        h = 0.38
        self.ax.barh([y + h / 2 for y in ys], [i[1] for i in items], height=h, color=UP, label="Upload")
        self.ax.barh([y - h / 2 for y in ys], [i[2] for i in items], height=h, color=DOWN, label="Download")
        self.ax.set_yticks(list(ys))
        self.ax.set_yticklabels([i[0][:28] for i in items])
        leg = self.ax.legend(loc="lower right", fontsize=8, frameon=False)
        for t in leg.get_texts():
            t.set_color(theme.MUTED)
        self._finish()


class HourlyChart(_Chart):
    def update(self, rows: list[tuple[float, float, float]], empty_msg: str = "No history yet") -> None:
        sig = tuple(rows)
        if sig == self._sig:
            return
        self._sig = sig
        if not rows:
            return self._empty(empty_msg)
        self.ax.clear()
        _style(self.ax, self.fig)
        labels = [dt.datetime.fromtimestamp(r[0]).strftime("%d %H:00") for r in rows]
        xs = range(len(rows))
        w = 0.4
        self.ax.bar([x - w / 2 for x in xs], [r[1] for r in rows], width=w, color=UP, label="Sent")
        self.ax.bar([x + w / 2 for x in xs], [r[2] for r in rows], width=w, color=DOWN, label="Received")
        step = max(1, len(rows) // 8)
        self.ax.set_xticks(list(xs)[::step])
        self.ax.set_xticklabels(labels[::step], rotation=0)
        leg = self.ax.legend(loc="upper left", fontsize=8, frameon=False)
        for t in leg.get_texts():
            t.set_color(theme.MUTED)
        self._finish()
