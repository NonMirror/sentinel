"""TUI 自定义组件: 统计卡、迷你图表、标题栏、状态栏."""
from __future__ import annotations

import time

from rich.text import Text

from . import palette
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Static

BLOCKS = "▁▂▃▄▅▆▇█"


def sparkline(values: list[float], width: int = 40, color: str = palette.ACCENT) -> Text:
    """将数值序列渲染为块状迷你折线图."""
    if not values:
        values = [0.0]
    if len(values) > width:
        step = len(values) / width
        values = [values[int(i * step)] for i in range(width)]
    peak = max(values) or 1.0
    text = Text()
    for value in values:
        level = int((value / peak) * (len(BLOCKS) - 1)) if peak else 0
        char = BLOCKS[max(0, min(len(BLOCKS) - 1, level))]
        style = color
        if value / peak > 0.8:
            style = palette.RED if color == palette.RED else palette.LAVENDER
        text.append(char, style=style)
    return text


def hbar(value: float, total: float, width: int = 24, color: str = palette.ACCENT) -> Text:
    filled = 0 if not total else int(round(width * (value / total)))
    filled = max(0, min(width, filled))
    text = Text()
    text.append("█" * filled, style=color)
    text.append("░" * (width - filled), style=palette.SURFACE2)
    return text


def fmt_num(value: float) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.2f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}K"
    return f"{value:.0f}"


def fmt_uptime(seconds: float) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


class StatCard(Static):
    """单个指标卡 (标题 + 数值 + 可选趋势)."""

    def __init__(self, title: str, value: str = "-", variant: str = "info",
                 trend: str = "", id: str | None = None) -> None:
        super().__init__(id=id)
        self.add_class("card", f"card-{variant}")
        self._title = title
        self._value = value
        self._trend = trend

    def update_value(self, value: str, trend: str = "") -> None:
        self._value = value
        self._trend = trend
        self.update(self.render_text())

    def on_mount(self) -> None:
        self.update(self.render_text())

    def render_text(self) -> Text:
        text = Text()
        text.append(self._title.upper() + "\n", style=palette.OVERLAY1)
        text.append(self._value, style="bold")
        if self._trend:
            text.append("\n" + self._trend, style=palette.OVERLAY0)
        return text


class SparkPanel(Static):
    """带标题的迷你折线图."""

    def __init__(self, title: str, color: str = palette.ACCENT, width: int = 46,
                 id: str | None = None) -> None:
        super().__init__(id=id)
        self.add_class("card")
        self.title_text = title
        self.color = color
        self.width = width
        self.values: list[float] = []

    def set_values(self, values: list[float]) -> None:
        self.values = values
        self.update(self.render_text())

    def render_text(self) -> Text:
        text = Text()
        text.append(self.title_text + "\n", style=palette.OVERLAY1)
        text.append_text(sparkline(self.values, self.width, self.color))
        text.append(f"  peak {max(self.values) if self.values else 0:.0f}",
                    style=palette.OVERLAY0)
        return text


class BarList(Static):
    """名称 + 条形 + 数值 的排行榜."""

    def __init__(self, title: str, color: str = palette.ACCENT, width: int = 22,
                 id: str | None = None) -> None:
        super().__init__(id=id)
        self.add_class("card")
        self.title_text = title
        self.color = color
        self.bar_width = width
        self.rows: list[tuple[str, float]] = []

    def set_rows(self, rows: list[tuple[str, float]]) -> None:
        self.rows = rows
        self.update(self.render_text())

    def render_text(self) -> Text:
        text = Text()
        text.append(self.title_text + "\n", style=palette.OVERLAY1)
        if not self.rows:
            text.append("(暂无数据)", style=palette.OVERLAY0)
            return text
        total = max(v for _, v in self.rows) or 1
        for name, value in self.rows[:8]:
            label = (name[:16]).ljust(17)
            text.append(label, style=palette.SUBTEXT0)
            text.append_text(hbar(value, total, self.bar_width, self.color))
            text.append(f" {value:,.0f}\n", style="bold")
        return text


class TitleBar(Horizontal):
    """顶部标题栏."""

    LOGO = "◆ SENTINEL"

    def __init__(self) -> None:
        super().__init__(id="titlebar")

    def compose(self) -> ComposeResult:
        yield Static(self.LOGO, id="titlebar-logo")
        yield Static(" 可视化安全运营与管理平台  ·  轻量级防火墙 + 漏洞扫描",
                     id="titlebar-status")
        yield Static("", id="titlebar-clock")

    def on_mount(self) -> None:
        self.set_interval(1.0, self._tick)

    def _tick(self) -> None:
        try:
            self.query_one("#titlebar-clock", Static).update(
                time.strftime(" %Y-%m-%d %H:%M:%S "))
        except Exception:
            pass


class StatusBar(Static):
    """底部状态栏 (模式 / 端口 / 快捷键提示)."""

    def __init__(self) -> None:
        super().__init__(id="statusbar")

    def render_status(self, mode: str, port: int | None, qps: float,
                      running: bool, hint_key: str = "NORMAL",
                      hint: str = "") -> None:
        """渲染状态栏.

        ``hint`` 是**短时**提示 (按键在当前面板没有可移动对象等), 由主循环
        在超时后自动清空 —— 比每次按键弹个 toast 安静得多, 又能解释「为什么
        按了没反应」。
        """
        text = Text()
        text.append(f" {hint_key} ", style=f"bold {palette.CRUST} on {palette.SKY}")
        text.append("  ·  mode=", style=palette.OVERLAY0)
        style = {"block": f"bold {palette.RED}",
                 "detect": f"bold {palette.YELLOW}",
                 "off": palette.OVERLAY0}.get(mode, palette.TEXT)
        text.append(mode, style=style)
        text.append(f"  ·  proxy=:{port or '-'}  ·  ", style=palette.OVERLAY0)
        text.append("qps=", style=palette.OVERLAY0)
        text.append(f"{qps:.1f}", style=f"bold {palette.SKY}")
        text.append("  ·  ", style=palette.OVERLAY0)
        text.append("● running" if running else "○ stopped",
                    style=f"bold {palette.GREEN}" if running else f"bold {palette.RED}")
        if hint:
            text.append("   ")
            text.append(hint, style=f"bold {palette.YELLOW}")
        else:
            text.append("   [1-9]模块  j/k移动  g/G首尾  a多引擎  /搜索  :命令  ?帮助  q退出",
                        style=palette.OVERLAY0)
        self.update(text)
