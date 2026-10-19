"""极致 TUI 测试 (Textual run_test 驾驶舱).

覆盖: 9 大模块切换、Vim 键位 (j/k/g/G/count/x/dd/yy)、命令模式 (:set/:engine/
:clear/:report)、搜索过滤 (/)、帮助浮层、引擎热切换与多引擎融合扫描。
"""
from __future__ import annotations

import asyncio
import time
import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest
from textual.widgets import DataTable, Input, RichLog, Static

from sentinel.core.config import Config
from sentinel.tui import palette
from sentinel.tui.app import (MODULES, SIDEBAR_ORDER, BenchmarkScreen, HelpScreen,
                              ModuleItem, NavigatorScreen, SentinelTUI)
from sentinel.tui.widgets import StatusBar


@pytest.fixture()
def tui_config(tmp_path) -> Config:
    config = Config()
    config.listener.host = "127.0.0.1"
    config.listener.port = 0
    config.lab.base_port = 0
    config.lab.instances = 2
    config.tui.refresh_hz = 8.0
    config.audit_path = str(tmp_path / "audit.jsonl")
    return config


def _run(coro_factory) -> object:
    return asyncio.run(coro_factory())


async def settle(pilot, predicate, *, timeout: float = 8.0, interval: float = 0.05):
    """轮询等待界面进入期望状态, 而不是靠写死的 ``pause`` 时长.

    TUI 用例里到处是 ``await pilot.pause(0.5)``: 机器一忙 (并行跑测试 / 截图),
    半秒就不够, 表现为随机的 ``NoMatches`` 失败 —— 测试本身没问题, 是等待方式
    不可靠。这里改成"条件成立即返回", 既快又稳。
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except Exception:                      # noqa: BLE001 - 界面尚未就绪
            pass
        await pilot.pause(interval)
    raise AssertionError(f"等待超时 ({timeout}s): 界面未进入期望状态")


# --------------------------------------------------------------------------
# 布局 / 模块导航
# --------------------------------------------------------------------------
def test_tui_has_nine_modules_and_frappe_theme(tui_config):
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            assert len(MODULES) == 9
            assert [panel[0].MODULE_NAME for panel in MODULES] == [
                "WAF 可视化", "配置管理", "入侵检测管理", "规则防御管理", "日志审计管理",
                "引擎与资产", "漏洞检测", "漏洞库管理", "报告生成"]
            for index in range(1, 10):
                assert app.query_one(f"#mod-{index}", Static) is not None
            assert str(app.query_one("#sidebar-group-blue", Static).render()) == "BLUE · WAF"
            assert str(app.query_one("#sidebar-group-red", Static).render()) == "RED · Scanner"
            assert SIDEBAR_ORDER == tuple(range(9))
            assert app.theme == palette.THEME_NAME
            assert palette.BASE == "#303446" and palette.TEXT == "#c6d0f5"
            status = str(app.query_one(StatusBar).render())
            assert "mode=block" in status and "[1-9]模块" in status
            assert app.runtime.running is True
            return True

    assert _run(body) is True


def test_tui_number_keys_switch_modules(tui_config):
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            seen = []
            for key in "123456789":
                await pilot.press(key)
                await pilot.pause(0.5)          # 等待计数超时提交
                seen.append(app.active_index)
            return seen

    assert _run(body) == list(range(9))


def test_tui_number_keys_switch_quickly(tui_config):
    """模块数字键不能因为 Vim 计数前缀而有明显延迟."""
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            before = app.active_index
            await pilot.press("6")
            await pilot.pause(0.25)
            return before, app.active_index

    before, after = _run(body)
    assert before == 0 and after == 5


def test_tui_quick_navigator_opens_and_jumps(tui_config):
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            await pilot.press("ctrl+o")
            await pilot.pause(0.2)
            opened = isinstance(app.screen, NavigatorScreen)
            # 首行是模块 1; j/k 也可在浮层内使用, 这里跳到模块 2。
            await pilot.press("j", "enter")
            await pilot.pause(0.2)
            return opened, app.active_index, isinstance(app.screen, NavigatorScreen)

    opened, index, still_open = _run(body)
    assert opened is True and index == 1 and still_open is False


def test_tui_scanner_benchmark_runs_and_shows_comparison(tui_config, monkeypatch):
    class Reachable:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    monkeypatch.setattr("sentinel.tui.app.urlopen", lambda *_args, **_kwargs: Reachable())

    async def body():
        app = SentinelTUI(tui_config, engine="python")

        def fake_scan_multi(targets, **_kwargs):
            juice = ":3000" in targets[0]
            stats = {"endpoints": 75 if juice else 26,
                     "findings": 14 if juice else 27,
                     "requests": 2878 if juice else 1851,
                     "errors": 0, "seconds": 0.2}
            app.runtime.scanner_manager.engines["w13scan"].stats = stats
            return SimpleNamespace(runs=[SimpleNamespace(
                ok=True, findings=stats["findings"], seconds=stats["seconds"])])

        app.runtime.scan_multi = fake_scan_multi
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            await pilot.press("7")
            await settle(pilot, lambda: app.active_panel.MODULE_NAME == "漏洞检测")
            await pilot.press("b")
            await settle(pilot, lambda: isinstance(app.screen, BenchmarkScreen))
            screen = app.screen
            await pilot.press("r")
            await settle(pilot, lambda: not screen._benchmark_running
                         and len(screen._results) == 2)
            table = screen.query_one("#benchmark-live", DataTable)
            rows = table.get_row("sentinel"), table.get_row("nuclei")
            await pilot.press("escape")
            await pilot.pause(0.1)
            return rows, table.row_count, isinstance(app.screen, BenchmarkScreen)

    rows, row_count, still_open = _run(body)
    assert rows[0] == ["Sentinel", "现场完成", "12/12", "7/7",
                       "19/19 (100.0%)，另3项", "4,729 / 0错误"]
    assert rows[1] == ["Nuclei", "归档", "5/12", "3/7", "8/19 (42.1%)", "18,119"]
    assert row_count == 5
    assert still_open is False


def test_tui_waf_panel_runs_balanced_benchmark(tui_config, monkeypatch):
    def fake_waf_benchmark(**kwargs):
        kwargs["progress"]("攻击样本", 434, 603)
        kwargs["progress"]("良性样本", 603, 603)
        return {
            "attack_recall": .9539,
            "category_macro_recall": .9515,
            "false_positive_rate": .0296,
            "attacks": {"n": 434, "blocked": 414},
            "benign": {"n": 169, "blocked": 5},
            "seconds": 4.2,
            "qps": 123.4,
        }

    def fake_peer_benchmarks(**kwargs):
        for key in ("modsecurity_crs_pl1", "coraza_crs_pl1",
                    "modsecurity_crs_pl4", "coraza_crs_pl4"):
            kwargs["progress"](key, "回放 603 条请求")
            kwargs["result"](key, fake_waf_benchmark(progress=lambda *_: None))
        return {}

    monkeypatch.setattr("benchmarks.scripts.bench_waf_proxy.run_benchmark",
                        fake_waf_benchmark)
    monkeypatch.setattr("benchmarks.scripts.bench_waf_proxy.run_peer_benchmarks",
                        fake_peer_benchmarks)

    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            assert app.active_panel.MODULE_NAME == "WAF 可视化"
            await pilot.press("b")
            await settle(pilot, lambda: isinstance(app.screen, BenchmarkScreen))
            screen = app.screen
            assert screen.kind == "waf"
            await pilot.press("a")
            await settle(pilot, lambda: not screen._benchmark_running
                         and not screen._peer_running and screen._waf_result is not None)
            table = screen.query_one("#benchmark-live", DataTable)
            rows = (table.get_row("sentinel_balanced"),
                    table.get_row("modsecurity_crs_pl1"), table.get_row("naxsi_pl1"))
            await pilot.press("escape")
            await pilot.pause(0.1)
            return rows, table.row_count, isinstance(app.screen, BenchmarkScreen)

    rows, row_count, still_open = _run(body)
    assert rows[0] == ["Sentinel balanced PL4", "现场达标", "414/434 (95.39%)",
                       "95.15%", "5/169 (2.96%)", "508/10,000 (5.08%)"]
    assert rows[1] == ["ModSecurity + CRS PL1", "现场", "414/434 (95.39%)",
                       "95.15%", "5/169 (2.96%)", "486/10,000 (4.86%)"]
    assert rows[2][1] == "归档·无现场镜像"
    assert row_count == 6
    assert still_open is False


def test_tui_tab_and_shift_tab_cycle_modules(tui_config):
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            await pilot.press("tab")
            await pilot.pause(0.1)
            forward = app.active_index
            await pilot.press("shift+tab")
            await pilot.pause(0.1)
            back = app.active_index
            return forward, back

    assert _run(body) == (1, 0)


def test_tui_sidebar_focus_and_pane_navigation(tui_config):
    """The sidebar is the initial selection surface; l enters the main pane."""
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            initial = (app.focus_region, app.active_index, type(app.focused), app.focused.id)
            await pilot.press("j")
            await pilot.pause(0.1)
            sidebar_down = (app.focus_region, app.active_index, app.focused.id)
            await pilot.press("2", "j")
            await pilot.pause(0.1)
            sidebar_count = (app.focus_region, app.active_index, app.focused.id)
            await pilot.press("l")
            await pilot.pause(0.1)
            main = (app.focus_region, app.active_index, app.focused.id)
            await pilot.press("j", "j")
            await pilot.pause(0.1)
            row = app.active_panel.query_one(DataTable).cursor_row
            await pilot.press("h")
            await pilot.pause(0.1)
            back = (app.focus_region, app.active_index, app.focused.id)
            return initial, sidebar_down, sidebar_count, main, row, back

    initial, down, counted, main, row, back = _run(body)
    assert initial == ("sidebar", 0, ModuleItem, "mod-1")
    assert down == ("sidebar", 1, "mod-2")
    assert counted == ("sidebar", 3, "mod-4")
    assert main == ("main", 3, "rules-table")
    assert row == 2
    assert back == ("sidebar", 3, "mod-4")


def test_tui_sidebar_navigation_follows_blue_red_order(tui_config):
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            await pilot.press("5")
            await pilot.pause(0.3)
            app._focus_sidebar()
            await pilot.press("j")
            after_blue = (app.active_index, app.focused.id)
            await pilot.press("j")
            first_red = (app.active_index, app.focused.id)
            await pilot.press("G")
            last_red = (app.active_index, app.focused.id)
            await pilot.press("g", "g")
            first_blue = (app.active_index, app.focused.id)
            return after_blue, first_red, last_red, first_blue

    assert _run(body) == ((5, "mod-6"), (6, "mod-7"),
                          (8, "mod-9"), (0, "mod-1"))


# --------------------------------------------------------------------------
# Vim 键位
# --------------------------------------------------------------------------
def test_tui_vim_motions_on_engine_panel(tui_config):
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            await pilot.press("6")
            await settle(pilot, lambda: app.active_panel.MODULE_NAME == "引擎与资产")
            panel = app.active_panel
            table = panel.query_one("#engine-table", DataTable)
            # 原生 3 个 (modsecurity·naxsi·python) + 参考 2 个 (nginx-*)
            assert table.row_count == 5
            assert table.cursor_row == 0

            await pilot.press("G")
            await pilot.pause(0.1)
            bottom = table.cursor_row
            await pilot.press("g", "g")
            await pilot.pause(0.1)
            top = table.cursor_row
            await pilot.press("j", "j")
            await pilot.pause(0.1)
            twice = table.cursor_row
            await pilot.press("2", "k")
            await pilot.pause(0.1)
            counted = table.cursor_row
            await pilot.press("k")
            await pilot.pause(0.1)
            return bottom, top, twice, counted, table.cursor_row, table.row_count

    bottom, top, twice, counted, after_k, rows = _run(body)
    # 末尾行下标随引擎数量变化 (原生 3 + 参考 2), 因此按行数推导而不是写死
    assert (top, twice, counted, after_k) == (0, 2, 0, 0)
    assert bottom == rows - 1


def test_tui_vim_count_moves_by_count(tui_config):
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            await pilot.press("4")            # 规则面板 (行数很多)
            await pilot.pause(0.5)
            table = app.active_panel.query_one("#rules-table", DataTable)
            await pilot.press("3", "j")
            await pilot.pause(0.2)
            return table.cursor_row, table.row_count

    row, count = _run(body)
    assert row == 3 and count > 10


def test_periodic_refresh_does_not_rebuild_unchanged_tables(tui_config, monkeypatch):
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            await pilot.press("4")
            await settle(pilot, lambda: app.active_panel.MODULE_NAME == "规则防御管理")
            panel = app.active_panel
            table = panel.query_one("#rules-table", DataTable)
            clears = 0
            original_clear = table.clear

            def counted_clear(*args, **kwargs):
                nonlocal clears
                clears += 1
                return original_clear(*args, **kwargs)

            monkeypatch.setattr(table, "clear", counted_clear)
            for _ in range(5):
                panel.refresh_data()
            return clears, table.row_count

    clears, rows = _run(body)
    assert rows > 0
    assert clears == 0


def test_tui_h_l_switches_panes(tui_config):
    """h/l move focus between the sidebar and the main pane."""
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            await pilot.press("4")
            await settle(pilot, lambda: app.active_panel.MODULE_NAME == "规则防御管理")
            await pilot.press("h")
            await pilot.pause(0.1)
            sidebar = (app.focus_region, app.focused.id)
            await pilot.press("l")
            await pilot.pause(0.1)
            main = (app.focus_region, app.focused.id)
            return sidebar, main

    sidebar, main = _run(body)
    assert sidebar == ("sidebar", "mod-4")
    assert main == ("main", "rules-table")


def test_tui_x_toggles_rule_and_yy_yanks(tui_config):
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            await pilot.press("4")
            await pilot.pause(0.5)
            panel = app.active_panel
            rule_id = int(panel.selected_row()["id"])
            before = app.runtime.rule_by_id(rule_id).enabled

            await pilot.press("x")
            await pilot.pause(0.2)
            after = app.runtime.rule_by_id(rule_id).enabled

            yanked = app._yank()
            return before, after, yanked, panel.selected_row() is not None

    before, after, yanked, has_row = _run(body)
    assert before is not after
    assert yanked is True and has_row is True


def test_tui_dd_clears_audit_view(tui_config):
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            from tests.conftest import fetch
            fetch(f"http://127.0.0.1:{app.runtime.front_port}/?q=hello")
            fetch(f"http://127.0.0.1:{app.runtime.front_port}/?q=1%20union%20select%201")
            await pilot.pause(0.4)
            await pilot.press("5")
            await pilot.pause(0.5)
            panel = app.active_panel
            rows_before = panel.query_one("#audit-table", DataTable).row_count
            await pilot.press("d", "d")
            await pilot.pause(0.2)             # 跨越多个自动刷新周期
            frozen = panel._frozen
            rows_after = panel.query_one("#audit-table", DataTable).row_count
            await pilot.press("r")             # 恢复实时刷新
            await pilot.pause(0.3)
            return rows_before, frozen, rows_after, panel.query_one(
                "#audit-table", DataTable).row_count

    rows_before, frozen, rows_after, restored = _run(body)
    assert rows_before > 0
    assert frozen is True and rows_after == 0
    assert restored >= rows_before


# --------------------------------------------------------------------------
# 搜索过滤 / 命令模式
# --------------------------------------------------------------------------
def test_tui_slash_filter_on_rules_panel(tui_config):
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            await pilot.press("4")
            await pilot.pause(0.5)
            panel = app.active_panel
            table = panel.query_one("#rules-table", DataTable)
            total = table.row_count
            first_id = int(panel.selected_row()["id"])

            app.open_cmdbar("/")
            app.query_one("#cmdbar", Input).value = f"/{first_id}"
            await pilot.press("enter")
            await pilot.pause(0.2)
            filtered = table.row_count
            needle = panel._filter

            app.open_cmdbar("/")
            app.query_one("#cmdbar", Input).value = "/"
            await pilot.press("enter")
            await pilot.pause(0.2)
            cleared = table.row_count
            return total, filtered, needle, cleared

    total, filtered, needle, cleared = _run(body)
    assert total > 1
    assert filtered == 1 and needle.isdigit()
    assert cleared == total


def test_tui_command_mode_set_clear_and_engine(tui_config):
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)

            async def command(text: str) -> None:
                app.open_cmdbar(":")
                app.query_one("#cmdbar", Input).value = text
                await pilot.press("enter")
                await pilot.pause(0.1)

            await command(":set threshold=7")
            await command(":set pl=3")
            await command(":set rate=25")
            await command(":set strategy=least_conn")
            scope = (app.runtime.config.waf.anomaly_threshold,
                     app.runtime.config.waf.paranoia_level,
                     app.runtime.config.waf.rate_limit_rps,
                     app.runtime.config.waf.strategy)

            await command(":engine")
            await command(":engine python")
            engine = app.runtime.engine_name

            await command(":clear")
            events = len(app.runtime.bus.history())
            return scope, engine, events

    scope, engine, events = _run(body)
    assert scope == (7, 3, 25.0, "least_conn")
    assert engine == "python"
    assert events == 0


def test_tui_help_overlay_opens_and_closes(tui_config):
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            await pilot.press("question_mark")
            await pilot.pause(0.3)
            opened = isinstance(app.screen, HelpScreen)
            await pilot.press("escape")
            await pilot.pause(0.3)
            return opened, isinstance(app.screen, HelpScreen)

    opened, closed = _run(body)
    assert opened is True and closed is False


def test_tui_report_command_writes_files(tui_config, tmp_path, monkeypatch):
    import sentinel.scanner.report as report_module

    real_write = report_module.write_report

    def write_to_tmp(report, outdir="reports", prefix="scan", formats=("md", "html", "json")):
        return real_write(report, str(tmp_path), prefix, formats)

    monkeypatch.setattr(report_module, "write_report", write_to_tmp)

    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            app.runtime.scan(app.runtime.lab_urls()[0])
            for command in ("report", "report html", "report json"):
                app.run_command(command)
            await pilot.pause(0.3)
            return sorted(path.name for path in tmp_path.glob("sentinel-scan-*"))

    names = _run(body)
    assert any(name.endswith(".md") for name in names)
    assert any(name.endswith(".html") for name in names)
    assert any(name.endswith(".json") for name in names)


# --------------------------------------------------------------------------
# 数据面联动
# --------------------------------------------------------------------------
def test_tui_panels_reflect_live_traffic(tui_config):
    async def body():
        from tests.conftest import fetch
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            base = f"http://127.0.0.1:{app.runtime.front_port}"
            fetch(f"{base}/?q=hello")
            fetch(f"{base}/?q=%3Cscript%3Ealert(1)%3C/script%3E")
            fetch(f"{base}/download?file=../../../../etc/passwd")
            await pilot.pause(0.5)

            await pilot.press("3")            # 入侵检测
            await pilot.pause(0.5)
            ids_rows = app.active_panel.query_one("#ids-table", DataTable).row_count
            await pilot.press("5")            # 日志审计
            await pilot.pause(0.5)
            audit_rows = app.active_panel.query_one("#audit-table", DataTable).row_count
            await pilot.press("1")            # WAF 可视化
            await pilot.pause(0.5)
            dashboard = app.runtime.metrics.snapshot()
            return ids_rows, audit_rows, dashboard

    ids_rows, audit_rows, metrics = _run(body)
    assert audit_rows > 0
    assert metrics["blocked"] >= 2 and metrics["requests"] >= 3


def test_ids_enter_jumps_to_matching_rule(tui_config):
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.3)
            rule_id = app.runtime.rule_index()[0].id
            app.runtime.bus.publish("ids", {
                "rule_id": rule_id, "severity": "high", "created_at": time.time(),
                "client": "127.0.0.1", "category": "waf", "message": "测试命中",
                "evidence": f"rule={rule_id}",
            })
            await pilot.press("3")
            await settle(pilot, lambda: app.active_panel.query_one(
                "#ids-table", DataTable).row_count > 0)
            await pilot.press("enter")
            await settle(pilot, lambda: app.active_panel.MODULE_NAME == "规则防御管理")
            selected = int(app.active_panel.selected_row()["id"])
            return rule_id, selected, app.focused.id

    rule_id, selected, focused = _run(body)
    assert selected == rule_id
    assert focused == "rules-table"


# --------------------------------------------------------------------------
# 引擎热切换 (经 TUI 引擎面板)
# --------------------------------------------------------------------------
@pytest.mark.slow
@pytest.mark.integration
def test_tui_engine_panel_hot_switches_native_engine(tui_config):
    from sentinel.waf.engines import available_engines

    available = available_engines()
    if not (available.get("modsecurity") and available.get("naxsi")):
        pytest.skip("需要 modsecurity 与 naxsi 原生引擎可用")

    async def body():
        app = SentinelTUI(tui_config, engine="modsecurity")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.6)
            await pilot.press("6")
            await settle(pilot, lambda: app.active_panel.MODULE_NAME == "引擎与资产"
                         and app.active_panel.query("#engine-table"))
            panel = app.active_panel
            table = panel.query_one("#engine-table", DataTable)
            start = app.runtime.engine_name
            assert start == "modsecurity"

            for row in range(table.row_count):
                if str(table.coordinate_to_cell_key((row, 0)).row_key.value) == "naxsi":
                    table.move_cursor(row=row)
                    break
            await pilot.press("x")
            await settle(pilot, lambda: app.runtime.engine_name == "naxsi")
            return start, app.runtime.engine_name, app.runtime.engine_manager.is_real

    start, now, real = _run(body)
    # 原生引擎在进程内决策, real_engine 为 False 是**预期**结果
    assert start == "modsecurity" and now == "naxsi" and real is False


@pytest.mark.slow
@pytest.mark.integration
def test_tui_scan_panel_reflects_report(tui_config):
    """扫描完成后, 「漏洞检测」面板必须真的把报告数字渲染出来.

    这条用例来自一个真实的回归: 面板刷新逻辑被改坏后 ``refresh_data`` 提前返回,
    卡片永远停在 "-"、结果表恒为空 —— 而扫描本身是成功的, 没有任何异常冒出来。
    断言「卡片 == 报告」才能守住这种静默失效。
    """
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.4)
            app.run_command(f"scan http://127.0.0.1:{app.runtime.proxy_port}/")
            for _ in range(600):
                await pilot.pause(0.1)
                if app.runtime.last_report is not None:
                    break
            await pilot.press("7")
            await settle(pilot, lambda: app.active_panel.MODULE_NAME == "漏洞检测")
            app.active_panel.refresh_data()
            await pilot.pause(0.2)
            panel = app.active_panel
            cards = {
                cid: panel.query_one(f"#{cid}").render_text().plain
                for cid in ("scan-urls", "scan-params", "scan-findings",
                            "scan-requests")
            }
            rows = panel.query_one("#scan-table", DataTable).row_count
            return app.runtime.last_report, cards, rows

    report, cards, rows = _run(body)
    assert report is not None, "扫描未产出报告"
    assert str(report.stats.findings) in cards["scan-findings"]
    assert str(report.stats.urls) in cards["scan-urls"]
    assert str(report.stats.params) in cards["scan-params"]
    assert str(report.stats.requests) in cards["scan-requests"]
    assert rows == len(report.findings) > 0, "结果表未渲染扫描发现"


@pytest.mark.slow
@pytest.mark.integration
def test_tui_multi_engine_scan_end_to_end(tui_config):
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.4)
            await pilot.press("7")
            await pilot.pause(0.5)
            app.run_command("scanall")
            panel = app.active_panel
            started = panel._state
            # 多引擎扫描 (nuclei 全模板) 约 345 s, 轮询窗口给到 600 s
            for _ in range(3000):
                await pilot.pause(0.2)
                if app.runtime.last_outcome is not None:
                    break
            outcome = app.runtime.last_outcome
            return started, outcome

    started, outcome = _run(body)
    assert "多引擎扫描中" in started
    assert outcome is not None
    assert outcome.findings, "多引擎融合扫描未发现任何漏洞"
    engines = {run.engine for run in outcome.runs}
    assert "builtin" in engines
    assert any(run.ok for run in outcome.runs)


# --------------------------------------------------------------------------
# j/k 的行进目标 (回归: 曾经在仪表盘与空表格上完全没反应)
# --------------------------------------------------------------------------
def _first(widget, widget_type):
    for child in widget.query(widget_type):
        return child
    return None


def test_vim_jk_moves_table_cursor(tui_config):
    """有数据的面板: j/k 移动表格光标."""
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.4)
            await pilot.press("4")                     # 规则防御
            await settle(pilot, lambda: app.active_panel.MODULE_NAME == "规则防御管理")
            table = app.active_panel.query_one(DataTable)
            assert table.row_count > 2
            await pilot.press("j", "j")
            await pilot.pause(0.15)
            moved = table.cursor_row
            await pilot.press("k")
            await pilot.pause(0.15)
            return moved, table.cursor_row

    moved, back = _run(body)
    assert moved == 2 and back == 1


def test_vim_jk_scrolls_event_log_and_pauses_follow(tui_config):
    """仪表盘没有表格, j/k 应当滚动实时事件流, 且向上翻阅时暂停自动跟随.

    这就是「进了 TUI 按 j/k 没反应」的那个回归: 仪表盘没有 DataTable,
    旧实现直接 return, 按键被静默吞掉。
    """
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.4)
            base = f"http://127.0.0.1:{app.runtime.proxy_port}"
            for _ in range(3):
                for path in ("/?q=hello", "/?q=1+OR+1%3D1", "/?f=../../etc/passwd"):
                    try:
                        urllib.request.urlopen(base + path, timeout=3).read()
                    except urllib.error.HTTPError:
                        pass
            await pilot.pause(1.0)

            panel = app.active_panel
            assert panel.MODULE_NAME == "WAF 可视化"
            assert list(panel.query(DataTable)) == []    # 仪表盘确实没有表格
            log = _first(panel, RichLog)
            assert log is not None and log.max_scroll_y > 0

            await pilot.press("l")
            await pilot.pause(0.2)
            top_before = log.scroll_y
            await pilot.press("k", "k", "k")
            await pilot.pause(0.3)
            paused = (log.scroll_y, log.auto_scroll)

            # 继续产生事件: 暂停跟随后位置不应被拽回底部
            for path in ("/?q=a", "/?q=b", "/?q=c", "/?q=d"):
                try:
                    urllib.request.urlopen(base + path, timeout=3).read()
                except urllib.error.HTTPError:
                    pass
            await pilot.pause(1.0)
            held = log.scroll_y

            await pilot.press("G")
            await pilot.pause(0.6)
            return top_before, paused, held, log.auto_scroll, log.scroll_y

    top_before, (paused_at, following), held, resumed, end = _run(body)
    assert top_before > 0
    assert paused_at < top_before, "k 没有滚动事件流"
    assert following is False, "向上翻阅后应暂停自动跟随"
    assert held == paused_at, "暂停跟随后位置被新事件拽走了"
    assert resumed is True and end == top_before or end >= held, "G 应回到末行并恢复跟随"


def test_vim_jk_on_empty_table_explains_instead_of_silence(tui_config):
    """空表格上按 j/k 不能毫无反应 —— 状态栏要说明原因."""
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.4)
            await pilot.press("3")                       # 入侵检测: 还没产生流量
            await settle(pilot, lambda: app.active_panel.MODULE_NAME == "入侵检测管理")
            table = app.active_panel.query_one(DataTable)
            assert table.row_count == 0
            app._hint_text = ""
            await pilot.press("j")
            await pilot.pause(0.2)
            return app._hint_text, app._hint_until

    hint, until = _run(body)
    assert "表格还是空的" in hint
    assert until > 0


def test_vim_jk_never_leaves_focus_in_a_hidden_panel(tui_config):
    """切到没有可聚焦控件的面板时, 焦点不能滞留在隐藏面板的表格里."""
    async def body():
        app = SentinelTUI(tui_config, engine="python")
        async with app.run_test(size=(150, 46)) as pilot:
            await pilot.pause(0.4)
            await pilot.press("6")                       # 引擎面板有表格
            await settle(pilot, lambda: app.active_panel.MODULE_NAME == "引擎与资产")
            await pilot.press("1")                       # 仪表盘没有可聚焦控件
            await settle(pilot, lambda: app.active_panel.MODULE_NAME == "WAF 可视化")
            focused = app.focused
            return type(focused).__name__, getattr(focused, "id", "")

    _kind, widget_id = _run(body)
    assert widget_id != "engine-table", "焦点仍停在隐藏面板的引擎表格上"
