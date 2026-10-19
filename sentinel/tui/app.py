"""可视化安全运营与管理平台 — 极致 TUI (Textual).

Vim 键位:
    1-9        切换功能模块        j / k      下 / 上移动
    g g / G    首行 / 末行         h / l      侧栏 / 主面板
    Enter      激活 / 切换          x / Space  启停 (规则/配置项)
    d d        清空当前视图         y y        复制当前行
    /          搜索过滤            :          命令模式
    r          刷新 / 重载引擎     s / D      普通 / 深度扫描
    ?          帮助                q          退出
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (ContentSwitcher, DataTable, Input, RichLog,
                             Static)

from ..core.config import Config
from ..runtime import SentinelRuntime
from . import palette
from .panels import (AuditPanel, ConfigPanel, DashboardPanel, EnginesPanel, IdsPanel,
                     ReportPanel, RulesPanel, ScanPanel, VulnDbPanel)
from .widgets import StatusBar, TitleBar, fmt_num


def _first(widget, widget_type):
    """取 widget 子树里的第一个指定类型控件 (没有则 None)."""
    for child in widget.query(widget_type):
        return child
    return None


def _scroller(panel):
    """面板里适合作为滚动目标的区域.

    优先 ``RichLog`` —— 仪表盘的实时事件流、审计面板的审计流都是它,
    Vim 用户按 j/k 时想动的正是这些「一行一行」的东西。
    """
    for widget_type in (RichLog, VerticalScroll):
        found = _first(panel, widget_type)
        if found is not None:
            return found
    return None


class ModuleItem(Static):
    """侧栏一行: 模块名 + 右对齐徽标 (两列布局).

    名字与徽标拆成**两个子控件**, 徽标固定占行尾的窄列 —— 对齐交给布局
    引擎, 而不是手动补空格。这样即使某个图标字节宽与终端实际渲染宽度
    不一致 (字体缺字时回退到更宽的符号字体, 会多占一列), 也不影响徽标
    所在列。图标本身仍应尽量选用终端主字体覆盖的字形。
    """

    can_focus = True

    def __init__(self, index: int, panel_cls, **kwargs) -> None:
        kwargs.setdefault("classes", "module")
        kwargs.setdefault("id", f"mod-{index}")
        super().__init__(**kwargs)
        self.index = index
        self.panel_cls = panel_cls

    def compose(self) -> ComposeResult:
        yield Static(self.label_markup(), id=f"mod-{self.index}-label",
                     classes="module-label")
        yield Static("", id=f"mod-{self.index}-badge", classes="module-badge")

    def label_markup(self) -> str:
        return (f"[dim]{self.index}[/]  {self.panel_cls.MODULE_ICON}  "
                f"{self.panel_cls.MODULE_NAME}")

#: (面板类, 综合设计归属, 归属中文名) —— 顺序即 1-9 的模块编号
MODULES = [
    (DashboardPanel, "综设III", "管理平台"),
    (ConfigPanel, "综设III", "管理平台"),
    (IdsPanel, "综设II", "轻量级防火墙"),
    (RulesPanel, "综设II", "轻量级防火墙"),
    (AuditPanel, "综设II", "轻量级防火墙"),
    (ScanPanel, "综设I", "漏洞扫描子系统"),
    (VulnDbPanel, "综设I", "漏洞扫描子系统"),
    (ReportPanel, "综设I", "漏洞扫描子系统"),
    (EnginesPanel, "综设II", "引擎与资产"),
]

#: 模块编号 (1 起) -> 面板类, 用于命令与扫描动作的**按名寻址**。
#: 曾经用 ``self._panels[5]`` 这类硬编码下标, 一旦调整模块顺序就会静默指向
#: 错误的面板 (扫描命令打到漏洞库上)。
MODULE_INDEX = {cls.__name__: index for index, (cls, _g, _n) in enumerate(MODULES, 1)}

HELP_TEXT = r"""[bold cyan]SENTINEL — 可视化安全运营与管理平台[/]

[bold]架构映射[/]
  [cyan]综设III 管理平台[/]      \[1] WAF 可视化   \[2] 配置管理
  [cyan]综设II  轻量级防火墙[/]   \[3] 入侵检测     \[4] 规则防御     \[5] 日志审计
  [cyan]综设II  引擎与资产[/]     \[9] 原生解释器 · 内置规则/模板 · 可选 C 数据面
  [cyan]综设I   漏洞扫描子系统[/]  \[6] 漏洞检测     \[7] 漏洞库管理   \[8] 报告生成

[bold]Vim 键位[/]
  [yellow]1-9[/]        切换模块 (也可鼠标点击侧栏)   [yellow]j / k[/]  下 / 上移动
  [yellow]g g / G[/]    首行 / 末行             [yellow]h / l[/]      侧栏 / 主面板
  [dim]进入时焦点在模块导航; j/k 移动模块, l 进入主面板, h 返回侧栏。[/]
  [dim]j/k 作用于当前面板: 有表格就移动光标, 否则滚动实时日志;
   主面板里 j/k 移动表格或日志; 在日志里按 k 会暂停自动跟随,
   按 G 回到末行并恢复跟随。[/]
  [yellow]Enter[/]      激活 / 切换引擎         [yellow]x Space[/]    启停规则 / 切换引擎
  [yellow]d d[/]        清空当前视图            [yellow]y y[/]        复制当前行
  [yellow]/[/]          搜索过滤                [yellow]:[/]          命令模式
  [yellow]r[/]          刷新 / 重载引擎         [yellow]s / D[/]      普通 / 深度扫描
  [yellow]a / A[/]      多引擎融合扫描 / 深度融合扫描 (模板 + 插件 + 内置)
  [yellow]Ctrl-O[/]     打开快速导航 (模块 / 常用动作)
  [yellow]Tab[/]        下一模块                [yellow]?[/]          本帮助
  [yellow]q[/]          退出

[bold]命令模式 (:)[/]
  :q / :q! / :wq        退出
  :w                    保存配置到 sentinel.toml
  :set mode=block|detect|off
  :set threshold=3..30   :set pl=1..4   :set rate=0..200
  :set strategy=round_robin|least_conn|random|ip_hash
  :engine [name]        查看 / 热切换引擎 (原生: modsecurity·naxsi·python;
                        参考: nginx-modsecurity·nginx-naxsi, 需先构建)
  :vendor               内置第三方资产 (规则/模板) 的来源与完整性
  :scan [url]            :scan! [url]   (深度扫描)
  :scanall [url]         :scanall! [url] 多引擎融合扫描 (模板+插件+内置)
  :report [md|html|json] :export        导出当前引擎规则
  :reload               重载引擎规则     :clear  清空事件

[dim]按 Esc 或 ? 关闭 · j/k 滚动帮助[/]"""


class HelpScreen(ModalScreen):
    """帮助浮层."""

    BINDINGS = [Binding("escape", "dismiss", "关闭"), Binding("question_mark", "dismiss", "关闭"),
                Binding("q", "dismiss", "关闭"),
                Binding("j", "scroll_down", "下移", show=False),
                Binding("down", "scroll_down", "下移", show=False),
                Binding("k", "scroll_up", "上移", show=False),
                Binding("up", "scroll_up", "上移", show=False),
                Binding("g", "scroll_home", "顶部", show=False),
                Binding("G", "scroll_end", "底部", show=False)]

    def compose(self) -> ComposeResult:
        with Vertical(id="help"):
            yield Static("帮助 · 快捷键与命令", classes="help-title")
            with VerticalScroll(id="help-scroll"):
                yield Static(HELP_TEXT)
            yield Static("Esc/? 关闭 · j/k 滚动 · Ctrl-O 快速导航", classes="help-hint")

    def action_dismiss(self, *_) -> None:
        self.app.pop_screen()

    def on_key(self, event) -> None:
        actions = {"j": self.action_scroll_down, "down": self.action_scroll_down,
                   "k": self.action_scroll_up, "up": self.action_scroll_up,
                   "g": self.action_scroll_home, "G": self.action_scroll_end}
        action = actions.get(event.key)
        if action is not None:
            action()
            event.stop()
            event.prevent_default()

    def _scroll(self, direction: str) -> None:
        scroll = self.query_one("#help-scroll", VerticalScroll)
        if direction == "home":
            scroll.scroll_home(animate=False)
        elif direction == "end":
            scroll.scroll_end(animate=False)
        else:
            scroll.scroll_relative(y=1 if direction == "down" else -1, animate=False)

    def action_scroll_down(self) -> None:
        self._scroll("down")

    def action_scroll_up(self) -> None:
        self._scroll("up")

    def action_scroll_home(self) -> None:
        self._scroll("home")

    def action_scroll_end(self) -> None:
        self._scroll("end")


class NavigatorScreen(ModalScreen):
    """Keyboard-first quick navigator for modules and common actions.

    The numbered shortcuts remain available, but this gives new users a visible
    route into the application and avoids making them remember every command.
    """

    BINDINGS = [
        Binding("escape", "dismiss", "关闭"),
        Binding("ctrl+o", "dismiss", "关闭", show=False),
        Binding("enter", "activate", "打开"),
        Binding("j", "move_down", "下移", show=False),
        Binding("down", "move_down", "下移", show=False),
        Binding("k", "move_up", "上移", show=False),
        Binding("up", "move_up", "上移", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="navigator"):
            yield Static("快速导航", classes="navigator-title")
            yield Static("j/k 选择 · Enter 打开 · Esc 关闭", classes="navigator-hint")
            yield DataTable(id="navigator-table", zebra_stripes=True)

    def on_mount(self) -> None:
        table = self.query_one("#navigator-table", DataTable)
        table.add_columns("键", "目标", "说明")
        for index, (panel_cls, _group, _group_name) in enumerate(MODULES, 1):
            table.add_row(str(index), panel_cls.MODULE_NAME, "切换模块", key=f"module:{index - 1}")
        for key, label, description in (
            ("s", "普通扫描", "打开漏洞检测面板并开始扫描"),
            ("a", "融合扫描", "运行模板、插件和内置引擎"),
            ("e", "引擎管理", "打开引擎与资产面板"),
            ("r", "报告生成", "打开报告面板"),
            ("?", "帮助", "查看完整快捷键与命令"),
        ):
            table.add_row(key, label, description, key=f"action:{key}")
        table.focus()

    def on_key(self, event) -> None:
        actions = {"j": self.action_move_down, "down": self.action_move_down,
                   "k": self.action_move_up, "up": self.action_move_up,
                   "enter": self.action_activate}
        action = actions.get(event.key)
        if action is not None:
            action()
            event.stop()
            event.prevent_default()

    def _table(self) -> DataTable:
        return self.query_one("#navigator-table", DataTable)

    def action_dismiss(self) -> None:
        self.app.pop_screen()

    def action_move_down(self) -> None:
        table = self._table()
        if table.row_count:
            table.move_cursor(row=min(table.row_count - 1, table.cursor_row + 1))

    def action_move_up(self) -> None:
        table = self._table()
        if table.row_count:
            table.move_cursor(row=max(0, table.cursor_row - 1))

    def action_activate(self) -> None:
        table = self._table()
        if not table.row_count:
            return
        try:
            key = str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        except Exception:  # noqa: BLE001 - selection can be empty during mount
            return
        self.app.pop_screen()
        if key.startswith("module:"):
            self.app.select_module(int(key.split(":", 1)[1]), focus="main")
            return
        action = key.split(":", 1)[1] if ":" in key else key
        if action == "e":
            self.app.select_module(MODULE_INDEX[EnginesPanel.__name__] - 1, focus="main")
        elif action == "r":
            self.app.select_module(MODULE_INDEX[ReportPanel.__name__] - 1, focus="main")
        elif action == "?":
            self.app.push_screen(HelpScreen())
        elif action in ("s", "a"):
            self.app.select_module(MODULE_INDEX[ScanPanel.__name__] - 1, focus="main")
            panel = self.app.panel_for(ScanPanel)
            if action == "s":
                panel.start_scan(deep=False)
            else:
                panel.start_multi_scan(deep=False)


@dataclass
class VimState:
    count: str = ""
    pending: str = ""
    pending_ts: float = 0.0

    def reset(self) -> None:
        self.count = ""
        self.pending = ""
        self.pending_ts = 0.0


class SentinelTUI(App):
    """Sentinel 管理平台 TUI."""

    CSS_PATH = "theme.tcss"
    TITLE = "Sentinel"
    SUB_TITLE = "可视化安全运营与管理平台"
    BINDINGS = [
        Binding("ctrl+c", "quit_app", "退出", show=False),
        Binding("escape", "escape", "取消", show=False),
        Binding("ctrl+o", "open_navigator", "快速导航", show=False),
    ]

    def __init__(self, config: Config | None = None,
                 runtime: SentinelRuntime | None = None,
                 own_runtime: bool | None = None,
                 engine: str | None = None) -> None:
        super().__init__()
        self.config = config or Config()
        self._own_runtime = own_runtime if own_runtime is not None else runtime is None
        self.runtime = runtime or SentinelRuntime(self.config, engine=engine)
        self.vim = VimState()
        self._count_timer = None
        self.cmdbar_mode: str | None = None
        self._cmdbar_focus_region = "main"
        self.focus_region = "sidebar"
        self.active_index = 0
        self._panels: list = []
        self._status_bar: StatusBar | None = None
        #: 状态栏的短时提示 (按键无效果时解释原因, 而不是静默吞掉)
        self._hint_text = ""
        self._hint_until = 0.0

    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield TitleBar()
        with Horizontal(id="body"):
            with VerticalScroll(id="sidebar"):
                yield Static("模块导航", id="sidebar-title")
                for index, (panel_cls, _group, _group_name) in enumerate(MODULES, 1):
                    yield ModuleItem(index, panel_cls)
                yield Static("", id="sidebar-info")
            yield ContentSwitcher(id="main")
        yield Input(placeholder="", id="cmdbar")
        yield StatusBar()

    def on_mount(self) -> None:
        self.register_theme(palette.frappe())
        self.theme = palette.THEME_NAME
        if self._own_runtime:
            self.runtime.start()
        switcher = self.query_one("#main", ContentSwitcher)
        for panel_cls, _g, _n in MODULES:
            panel = panel_cls()
            self._panels.append(panel)
            switcher.mount(panel)
        self.select_module(0, focus="sidebar")
        self.call_after_refresh(lambda: self.select_module(self.active_index))
        interval = 1.0 / max(0.5, self.config.tui.refresh_hz)
        self.set_interval(interval, self.refresh_active)
        self.set_interval(interval, self._update_status)
        # 侧栏徽标刷新得慢一些: 它是导航, 不需要跟着 5Hz 的面板一起抖
        self.set_interval(1.0, self._update_sidebar)
        self.refresh_active()

    def panel_for(self, panel_cls):
        """按类取面板实例 (替代硬编码下标)."""
        index = MODULE_INDEX.get(panel_cls.__name__ if isinstance(panel_cls, type)
                                 else panel_cls)
        return self._panels[index - 1] if index else None

    def goto(self, panel_cls) -> None:
        """切到指定面板并返回它."""
        index = MODULE_INDEX.get(panel_cls.__name__ if isinstance(panel_cls, type)
                                 else panel_cls)
        if index:
            self.select_module(index - 1, focus="main")
        return self.panel_for(panel_cls)

    def _update_sidebar(self) -> None:
        """把实时计数写进侧栏徽标 (拦截 / 告警 / 漏洞)."""
        snap = None
        try:
            snap = self.runtime.snapshot()
        except Exception:                       # noqa: BLE001 - 卸载期间忽略
            return
        metrics = snap["metrics"]
        ids_stats = self.runtime.stats()
        badges = {
            DashboardPanel: (metrics["blocked"], palette.DANGER),
            IdsPanel: (ids_stats["alerts"], palette.MAUVE),
            ScanPanel: (metrics["findings"], palette.PEACH),
            AuditPanel: (snap["audit_total"], palette.SKY),
            EnginesPanel: (snap["rules"]["total"], palette.ACCENT2),
        }
        for index, (panel_cls, _group, _name) in enumerate(MODULES, 1):
            count, color = badges.get(panel_cls, (0, palette.OVERLAY0))
            try:
                widget = self.query_one(f"#mod-{index}-badge", Static)
            except Exception:                   # noqa: BLE001
                continue
            # 徽标是独立控件, 由布局引擎锚定在行尾窄列 —— 与图标/名字的
            # 实际渲染宽度无关, 因此不会因终端把 ambiguous 图标画成双宽而错位。
            widget.update(f"[bold {color}]{fmt_num(float(count))}[/]" if count else "")

        try:
            info = self.query_one("#sidebar-info", Static)
        except Exception:                       # noqa: BLE001
            return
        engine = snap["engine"]
        vendor = self.runtime.platform_snapshot()
        totals = (vendor.get("vendor") or {}).get("totals", {})
        missing = vendor.get("vendor_missing") or []
        lines = [
            "",
            "[dim]运行时[/]",
            f"  [{palette.GREEN}]●[/] 引擎 [b]{snap['engine_name']}[/]"
            f"  [dim]{'进程内' if not engine['real_engine'] else 'C 数据面'}[/]",
            f"  [{palette.GREEN}]●[/] 反向代理 [dim]:{snap['front_port'] or '-'}[/]",
            f"  [{palette.GREEN}]●[/] 负载均衡 [dim]{len(snap['backends'] or {})} 后端[/]",
            f"  [{palette.GREEN}]●[/] 事件总线 [dim]{ids_stats['alerts']} 告警[/]",
            "",
            "[dim]内置资产[/]",
            f"  [{'red' if missing else palette.GREEN}]"
            f"{'●' if not missing else '○'}[/] "
            f"[dim]{totals.get('files', 0)} 文件 / "
            f"{totals.get('bytes', 0) / 1048576:.1f} MiB[/]",
            f"  [dim]{'vendor 完整' if not missing else '缺: ' + ','.join(missing)}[/]",
        ]
        info.update("\n".join(lines))

    def on_click(self, event) -> None:
        """鼠标点击侧栏模块即切换 (TUI 也是 GUI)."""
        # 点击可能落在行内的名字/徽标子控件上, 因此向上找到整行 (ModuleItem)
        widget = getattr(event, "widget", None)
        while widget is not None and not isinstance(widget, ModuleItem):
            widget = getattr(widget, "parent", None)
        if widget is None:
            return
        try:
            self.select_module(widget.index - 1, focus="main")
        except (AttributeError, IndexError, ValueError):
            pass

    # ------------------------------------------------------------------
    # 模块与刷新
    # ------------------------------------------------------------------
    def select_module(self, index: int, *, focus: str | None = None) -> None:
        index = max(0, min(len(MODULES) - 1, index))
        self.active_index = index
        if focus is not None:
            self.focus_region = focus
        panel = self._panels[index]
        try:
            self.query_one("#main", ContentSwitcher).current = panel.id
        except Exception:
            pass
        for position, other in enumerate(self._panels):
            try:
                other.display = (position == index)
            except Exception:
                pass
        for i in range(1, len(MODULES) + 1):
            try:
                self.query_one(f"#mod-{i}", Static).set_class(i == index + 1, "active")
            except Exception:
                pass
        if self.focus_region == "sidebar":
            self._focus_sidebar()
        else:
            self._focus_panel()

    def _focus_sidebar(self) -> None:
        """Focus the selected module row and keep it visible in the sidebar."""
        self.focus_region = "sidebar"
        try:
            item = self.query_one(f"#mod-{self.active_index + 1}", ModuleItem)
            item.focus()
            item.scroll_visible()
        except Exception:  # noqa: BLE001 - during initial composition
            pass

    def _focus_main(self) -> None:
        self.focus_region = "main"
        self._focus_panel()

    def _focus_panel(self) -> None:
        """把焦点交给当前面板里第一个可聚焦控件.

        面板没有可聚焦控件时 (例如仪表盘只有卡片和 RichLog), 必须**主动把焦点
        收回面板本身**: 否则焦点会滞留在上一个面板的控件上, 而那些面板此刻是
        ``display: none`` —— 键盘事件会打进一个看不见的表格里。
        """
        panel = self.active_panel
        for widget_type in (DataTable, Input):
            target = _first(panel, widget_type)
            if target is not None:
                target.focus()
                return
        panel.focus()

    @property
    def active_panel(self):
        return self._panels[self.active_index]

    def action_open_navigator(self) -> None:
        if not isinstance(self.screen, NavigatorScreen):
            self.push_screen(NavigatorScreen())

    def refresh_active(self) -> None:
        for panel in self._panels:
            if panel is self.active_panel:
                table = _first(panel, DataTable)
                cursor = table.cursor_coordinate if table is not None else None
                try:
                    panel.refresh_data()
                except Exception:
                    return
                # Panels rebuild their rows during refresh. Keep the row
                # selection stable so a refresh tick cannot make j/k jump.
                if table is not None and cursor is not None and table.row_count:
                    row, column = cursor
                    columns = len(table.ordered_columns)
                    if columns:
                        table.move_cursor(
                            row=min(row, table.row_count - 1),
                            column=min(column, columns - 1),
                        )

    def _update_status(self) -> None:
        # 状态栏挂在默认屏幕上; 模态浮层激活时 current screen 会变,
        # 因此缓存引用并容错, 避免定时器抛错拖垮整个应用。
        bar = self._status_bar
        if bar is None:
            try:
                bar = self._status_bar = self.query_one(StatusBar)
            except Exception:  # noqa: BLE001 - 浮层/卸载期间忽略
                return
        hint = ""
        if self._hint_text and time.monotonic() < self._hint_until:
            hint = self._hint_text
        elif self._hint_text:
            self._hint_text = ""
        try:
            metrics = self.runtime.metrics.snapshot()
            bar.render_status(
                self.runtime.config.waf.mode, self.runtime.proxy_port, metrics["qps"],
                self.runtime.running, "INSERT" if self.cmdbar_mode else "NORMAL",
                hint=hint)
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Vim 引擎
    # ------------------------------------------------------------------
    async def on_key(self, event) -> None:
        if self.cmdbar_mode:
            if event.key == "escape":
                self.close_cmdbar()
                event.stop()
            return
        if isinstance(self.focused, Input):
            if event.key == "escape":
                self._restore_focus_region()
                event.stop()
            return
        if self._handle_vim(event.key):
            event.stop()
            event.prevent_default()

    def _handle_vim(self, key: str) -> bool:  # noqa: C901
        state = self.vim
        # 数字既是模块快捷键也是移动计数前缀。只保留一个很短的歧义窗口，
        # 让单独的模块键几乎立即反馈，同时仍允许 ``3j`` 这样的 Vim 计数。
        if key.isdigit() and len(state.count) < 2:
            state.count += key
            state.pending = "count"
            state.pending_ts = time.time()
            if self._count_timer is not None:
                self._count_timer.stop()
            self._count_timer = self.set_timer(0.20, self._commit_count)
            return True
        if state.pending == "count":
            if self._count_timer is not None:
                self._count_timer.stop()
                self._count_timer = None

        count = int(state.count) if state.count else 1
        if key == "g":
            if state.pending == "g":
                state.pending = ""
                if self.focus_region == "sidebar":
                    self.select_module(0, focus="sidebar")
                elif not self._move("top", count):
                    self._hint(self._no_move_reason())
            else:
                state.pending = "g"
            return True
        if key == "d":
            if state.pending == "d":
                state.pending = ""
                return self.active_panel.vim_key("dd", count)
            state.pending = "d"
            return True
        if key == "y":
            if state.pending == "y":
                state.pending = ""
                return self._yank()
            state.pending = "y"
            return True
        state.pending = ""

        if key in ("j", "down", "k", "up", "G"):
            direction = {"j": "down", "down": "down", "k": "up", "up": "up",
                         "G": "bottom"}[key]
            if self.focus_region == "sidebar":
                if direction == "bottom":
                    self.select_module(len(MODULES) - 1, focus="sidebar")
                else:
                    delta = count if direction == "down" else -count
                    self.select_module(self.active_index + delta, focus="sidebar")
            elif not self._move(direction, count):
                self._hint(self._no_move_reason())
        elif key in ("h", "l"):
            direction = "left" if key == "h" else "right"
            if self.focus_region == "sidebar":
                if direction == "right":
                    self._focus_main()
                else:
                    self._hint("侧栏已聚焦 · 按 l 进入主面板")
            elif direction == "left":
                self._focus_sidebar()
            else:
                self._hint("主面板已聚焦 · 按 h 返回侧栏")
        elif key in ("enter", "space", "x"):
            if self.focus_region == "sidebar" and key == "enter":
                self._focus_main()
            else:
                self.active_panel.vim_key(key, count)
        elif key == "q":
            self.action_quit_app()
        elif key == "r":
            self.active_panel.vim_key("r", count)
            self.active_panel.refresh_data()
        elif key == "s":
            self.active_panel.vim_key("s", count)
        elif key in ("a", "A", "D"):
            # 面板级动作: 多引擎融合扫描 (a/A) 与深度扫描 (D)
            self.active_panel.vim_key(key, count)
        elif key == "slash":
            self.open_cmdbar("/")
        elif key == "colon":
            self.open_cmdbar(":")
        elif key == "tab":
            self.select_module(self.active_index + 1)
        elif key == "shift+tab":
            self.select_module(self.active_index - 1)
        elif key == "question_mark":
            self.push_screen(HelpScreen())
        elif key == "ctrl+o":
            self.push_screen(NavigatorScreen())
        elif key == "escape":
            return False
        else:
            return False
        state.count = ""
        return True

    def _commit_count(self) -> None:
        """歧义窗口结束后把单独数字解释为模块切换."""
        state = self.vim
        self._count_timer = None
        if state.pending != "count":
            return
        try:
            number = int(state.count)
        except ValueError:
            number = 0
        state.count = ""
        state.pending = ""
        if 1 <= number <= len(MODULES):
            self.select_module(number - 1, focus="main")

    def _move(self, direction: str, count: int = 1) -> bool:
        """移动当前面板的「主光标」, 返回是否真的移动了.

        面板形态不一, 所以从前到后依次尝试三种目标:

        1. **有数据的表格** —— 移动行光标 (规则库 / 引擎 / 漏洞库 …);
        2. **可滚动区域** —— 滚动它 (仪表盘的实时事件流就是 ``RichLog``);
        3. 都没有 —— 返回 ``False``, 由调用方给出提示。

        早先这里只处理第 1 种, 而且**没数据就直接 return**: 仪表盘根本没有表格,
        刚进 TUI 时入侵检测 / 审计 / 漏洞检测的表格也是空的 —— 按 j/k 全都毫无
        反应, 看起来就像键位坏了。
        """
        panel = self.active_panel
        table = _first(panel, DataTable)
        if table is not None and table.row_count and table.size.height > 0:
            rows = table.row_count
            if direction == "top":
                table.move_cursor(row=0)
            elif direction == "bottom":
                table.move_cursor(row=rows - 1)
            else:
                delta = count if direction == "down" else -count
                table.move_cursor(row=max(0, min(rows - 1, table.cursor_row + delta)))
            try:
                panel._update_detail()
            except Exception:                     # noqa: BLE001 - 面板可无详情卡
                pass
            return True

        scroller = _scroller(panel)
        scrollable = False
        if scroller is not None and scroller.max_scroll_y > 0:
            if isinstance(scroller, RichLog):
                # A compact terminal can report a zero layout height while a
                # short startup log is still below the fold. Only treat a
                # RichLog as a movement target once it has real history; this
                # leaves h/j/k/l available for module navigation on startup.
                scrollable = scroller.size.height > 0 or len(scroller.lines) > 8
            else:
                scrollable = scroller.size.height > 0
        if scrollable:
            if direction == "top":
                scroller.scroll_home(animate=False)
            elif direction == "bottom":
                scroller.scroll_end(animate=False)
            else:
                delta = count if direction == "down" else -count
                scroller.scroll_relative(y=delta, animate=False)
            if isinstance(scroller, RichLog):
                # 实时日志默认「自动跟随到底」, 新事件会把用户刚滚上去的位置
                # 立刻拽回底部 —— 按 k 就像什么都没发生。这里按**方向**决定
                # 跟随开关 (不能看 is_vertical_scroll_end: 滚动要到下一个消息
                # 周期才生效, 此刻读到的仍是旧位置):
                #   向上 / 到顶 -> 停止跟随 (开始翻阅历史)
                #   到末行 (G)  -> 恢复跟随
                #   向下        -> 不改动: 已经跟随的话本来就是空操作
                if direction in ("up", "top"):
                    scroller.auto_scroll = False
                elif direction == "bottom":
                    scroller.auto_scroll = True
            return True
        return False

    def _no_move_reason(self) -> str:
        """j/k 没起作用时, 说清楚是**哪一种**没起作用.

        「有表格但还没数据」和「压根没有列表」对用户来说要做的事完全不同:
        前者去产生流量 / 跑一次扫描就行, 后者是换个面板。
        """
        panel = self.active_panel
        name = panel.MODULE_NAME

        def _count(widget_type) -> int:
            return sum(1 for _ in panel.query(widget_type))

        if _count(DataTable):
            return f"{name}: 表格还是空的 —— 先产生流量或执行一次扫描"
        if _count(RichLog) or _count(VerticalScroll):
            return f"{name}: 内容不足一屏, 无需滚动"
        return f"{name}: 本面板没有可移动的列表 (用 Tab 切换模块)"

    def _hint(self, message: str, seconds: float = 3.0) -> None:
        """在状态栏给一句**短时提示** (比每次按键弹 toast 安静得多)."""
        self._hint_text = message
        self._hint_until = time.monotonic() + seconds

    def _yank(self) -> bool:
        row = self.active_panel.selected_row()
        if not row:
            return False
        text = " | ".join(f"{k}={v}" for k, v in row.items())
        try:
            import subprocess
            subprocess.run(["wl-copy"], input=text.encode(), check=False,
                           timeout=1, capture_output=True)
            self.notify(f"已复制: {text[:60]}", timeout=2)
        except Exception:
            self.notify(f"(剪贴板不可用) {text[:60]}", timeout=3)
        return True

    # ------------------------------------------------------------------
    # 命令栏
    # ------------------------------------------------------------------
    def open_cmdbar(self, prefix: str) -> None:
        bar = self.query_one("#cmdbar", Input)
        self._cmdbar_focus_region = self.focus_region
        self.cmdbar_mode = prefix
        bar.value = prefix
        bar.add_class("visible")
        bar.focus()

    def close_cmdbar(self) -> None:
        bar = self.query_one("#cmdbar", Input)
        bar.value = ""
        bar.remove_class("visible")
        self.cmdbar_mode = None
        self._restore_focus_region()

    def _restore_focus_region(self) -> None:
        if self._cmdbar_focus_region == "sidebar":
            self.focus_region = "sidebar"
            self._focus_sidebar()
        else:
            self._focus_main()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "cmdbar":
            if event.input.id == "scan-target":
                panel = self.panel_for(ScanPanel)
                if panel is not None:
                    panel.start_scan(deep=False)   # type: ignore[attr-defined]
            return
        value = event.value.strip()
        mode = self.cmdbar_mode
        self.close_cmdbar()
        if mode == "/":
            needle = value[1:].strip() if value.startswith("/") else value
            if hasattr(self.active_panel, "set_filter"):
                self.active_panel.set_filter(needle)
                self.notify(f"过滤: {needle or '(清除)'}", timeout=2)
        else:
            self.run_command(value.lstrip(":").strip())

    def run_command(self, command: str) -> None:  # noqa: C901
        if not command:
            return
        parts = command.split()
        name, args = parts[0], parts[1:]

        if name in ("q", "q!", "wq", "quit"):
            self.action_quit_app()
        elif name == "w":
            self._save_config()
        elif name == "set":
            self._cmd_set(" ".join(args))
        elif name in ("scanall", "scanall!"):
            panel = self.goto(ScanPanel)
            if args:
                panel.query_one("#scan-target", Input).value = args[0]
            panel.start_multi_scan(deep=name.endswith("!"))
        elif name in ("scan", "scan!"):
            panel = self.goto(ScanPanel)
            if args:
                panel.query_one("#scan-target", Input).value = args[0]
            panel.start_scan(deep=name.endswith("!"))
        elif name == "report":
            fmt = args[0] if args else "md"
            if self.runtime.last_report is None:
                self.notify("尚无扫描结果", timeout=3, severity="warning")
                return
            from ..scanner.report import write_report
            paths = write_report(self.runtime.last_report, "reports", "sentinel-scan",
                                 (fmt,))
            panel = self.goto(ReportPanel)
            panel._generated.extend(paths.values())
            self.notify(f"报告已生成: {paths.get(fmt, '-')}", timeout=4)
        elif name == "export":
            engine = self.runtime.engine_name
            suffix = {"modsecurity": "crs-rules.conf", "naxsi": "naxsi.rules"}.get(
                engine, "builtin-rules.conf")
            path = f"reports/exported-{engine}-{suffix}"
            count = self.runtime.export_rules(path)
            self.notify(f"已导出 {count} 条规则 -> {path} (引擎: {engine})", timeout=4)
        elif name == "reload":
            try:
                self.runtime.reload_engine()
            except Exception as exc:                  # noqa: BLE001
                self.notify(f"引擎重载失败: {exc}", timeout=5, severity="error")
                return
            self.notify(f"引擎规则已重载: "
                        f"{self.runtime.rules_summary().get('total', 0)} 条", timeout=3)
        elif name == "engine":
            self._cmd_engine(args)
        elif name == "vendor":
            self._cmd_vendor()
        elif name == "clear":
            self.runtime.bus.clear()
            self.notify("事件历史已清空", timeout=2)
        elif name in ("help", "h"):
            self.push_screen(HelpScreen())
        else:
            self.notify(f"未知命令: {name}", timeout=3, severity="warning")

    def _cmd_engine(self, args: list[str]) -> None:
        """``:engine`` —— 列出或热切换引擎 (原生与参考都列出来)."""
        if not args:
            from ..waf.engines import ENGINE_CLASSES, NATIVE_ENGINES
            entries = []
            for name, cls in ENGINE_CLASSES.items():
                mark = "*" if name == self.runtime.engine_name else " "
                kind = "原生" if name in NATIVE_ENGINES else "参考"
                state = "可用" if cls.available() else "不可用"
                entries.append(f"{mark}{name}({kind}/{state})")
            self.notify("引擎: " + "  ".join(entries) + "   —— :engine <name> 切换",
                        timeout=8)
            return
        name = args[0]
        try:
            switched = self.runtime.switch_engine(name)
        except KeyError as exc:
            self.notify(f"未知引擎: {exc}", timeout=4, severity="warning")
        except Exception as exc:                      # noqa: BLE001
            self.notify(f"引擎切换失败: {exc}", timeout=6, severity="error")
        else:
            self.notify(f"WAF 引擎已切换 -> {switched}", timeout=3)
            self.select_module(MODULE_INDEX["EnginesPanel"] - 1, focus="main")

    def _cmd_vendor(self) -> None:
        """``:vendor`` —— 内置第三方资产的来源与完整性."""
        snapshot = self.runtime.platform_snapshot()
        lines = ["Sentinel 内置资产 (sentinel/vendor):"]
        for item in snapshot["vendor"]["collections"]:
            mark = "OK " if item["present"] else "缺失"
            lines.append(f"  [{mark}] {item['key']:<18} {item['files']:>6} 文件  "
                         f"{item['bytes'] / 1024:>8.0f} KiB  {item['license']}")
        missing = snapshot["vendor_missing"]
        lines.append("  全部完整 ✓" if not missing
                     else f"  ⚠ 缺失: {', '.join(missing)} — 运行 tools/vendor.py")
        health = snapshot.get("health") or {}
        if health:
            lines.append(
                f"  解释器: 正则编译失败 {health.get('failed_patterns', 0)} / "
                f"PCRE 方言改写 {health.get('translated_patterns', 0)}")
        self.notify("\n".join(lines), timeout=12,
                    severity="warning" if missing else "information")

    def _cmd_set(self, expression: str) -> None:
        if "=" not in expression:
            self.notify("用法: :set key=value", timeout=3, severity="warning")
            return
        key, _, value = expression.partition("=")
        key, value = key.strip(), value.strip()
        cfg = self.runtime.config.waf
        try:
            if key == "mode" and value in ("block", "detect", "off"):
                cfg.mode = value
            elif key == "threshold":
                cfg.anomaly_threshold = int(value)
            elif key == "pl":
                cfg.paranoia_level = max(1, min(4, int(value)))
            elif key == "rate":
                cfg.rate_limit_rps = float(value)
            elif key == "strategy":
                if value not in ("round_robin", "least_conn", "random", "ip_hash"):
                    raise ValueError("非法策略")
                cfg.strategy = value
            elif key in ("body", "inspect_body"):
                cfg.inspect_body = value.lower() in ("1", "true", "on", "yes")
            else:
                self.notify(f"未知配置项: {key}", timeout=3, severity="warning")
                return
        except ValueError as exc:
            self.notify(f"设置失败: {exc}", timeout=3, severity="error")
            return
        engine = self.runtime.engine
        # 不要往驱动的 ``config`` 里塞 WafConfig: 驱动持有的是整个 Config,
        # 覆写会让 set_paranoia 之类的内部读 `config.waf` 时炸掉。`cfg` 本来就是
        # `config.waf` 的同一对象, 就地改字段即可。
        if hasattr(engine, "set_paranoia"):
            # 原生引擎会就地重建规则库 (PL / 阈值影响规则选择)
            engine.set_paranoia(int(cfg.paranoia_level))
        ids = self.runtime.ids          # IDS 现由代理持有, 不再向引擎借
        ids.rate_limit_rps = float(cfg.rate_limit_rps)
        ids.rate_limit_burst = int(cfg.rate_limit_rps) * 2
        self.runtime.balancer.strategy = cfg.strategy
        self.runtime.proxy.config.waf = cfg
        try:
            self.runtime.reload_engine()
        except Exception as exc:  # noqa: BLE001
            self.notify(f"引擎重载失败: {exc}", timeout=4, severity="warning")
        self.notify(f"{key} = {value}", timeout=2)
        config_panel = self.panel_for(ConfigPanel)
        if config_panel is not None:
            config_panel.refresh_data()

    def _save_config(self) -> None:
        path = "sentinel.toml"
        self.runtime.config.save(path)
        self.notify(f"配置已保存 -> {path}", timeout=3)

    # ------------------------------------------------------------------
    def action_quit_app(self) -> None:
        if self._own_runtime:
            self.runtime.stop()
        self.exit()

    def action_escape(self) -> None:
        if self.cmdbar_mode:
            self.close_cmdbar()


def run(config: Config | None = None, engine: str | None = None) -> None:
    """启动 TUI (``engine`` 可指定 WAF 引擎, 默认自动选择)."""
    SentinelTUI(config, engine=engine).run()


if __name__ == "__main__":
    run()
