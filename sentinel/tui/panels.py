"""TUI 面板 — 对应架构图中的各功能模块.

综设III 可视化安全运营与管理平台: DashboardPanel / ConfigPanel / IdsPanel /
                                   RulesPanel / AuditPanel
综设I  漏洞扫描子系统:              ScanPanel / VulnDbPanel / ReportPanel
"""
from __future__ import annotations

import time
from collections import deque

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Input, ProgressBar, RichLog, Static

from ..scanner.report import SEVERITY_ZH, TYPE_ZH, render_markdown, write_report
from ..scanner.vulndb import default_db
from . import palette
from .widgets import BarList, StatCard, SparkPanel, fmt_num, fmt_uptime, hbar

SEV_STYLE = {k: f"bold {v}" if k in ("critical", "high") else v
             for k, v in palette.SEVERITY.items()}

CONFIG_SPECS = [
    ("enabled", "WAF 开关", "bool", "是否启用防火墙检测"),
    ("mode", "运行模式", ["block", "detect", "off"], "拦截 / 仅记录 / 关闭"),
    ("anomaly_threshold", "异常阈值", [3, 5, 10, 15, 20, 30], "CRS 风格累积评分阈值"),
    ("paranoia_level", "偏执等级 PL", [1, 2, 3, 4], "OWASP CRS 偏执级别"),
    ("strategy", "负载均衡策略", ["round_robin", "least_conn", "random", "ip_hash"],
     "后端选择算法"),
    ("inspect_body", "检查请求体", "bool", "是否深度检测 POST body"),
    ("block_above_threshold", "超阈值拦截", "bool", "累计评分超阈值即拦截"),
    ("rate_limit_rps", "速率限制 (rps)", [0, 5, 20, 50, 100, 200], "0 表示关闭"),
    ("add_x_forwarded_for", "透传 XFF", "bool", "向后端注入 X-Forwarded-For"),
    ("max_body_bytes", "最大检测体", [65536, 131072, 524288, 1048576], "请求体检测上限"),
]


class _Panel(Vertical):
    """面板基类.

    ``can_focus = True`` 是为了让**面板本身**能成为焦点落点: 仪表盘只有卡片与
    日志, 没有任何可聚焦控件, 若不收焦点, 焦点会滞留在上一个面板的表格上 ——
    而那个面板此刻是 ``display: none``, 键盘事件就打进了一个看不见的控件里。
    """

    MODULE_NAME = "面板"
    MODULE_ICON = "◆"
    KEY = ""
    can_focus = True

    def __init__(self) -> None:
        super().__init__(id=self.__class__.__name__)
        self.add_class("panel")

    @property
    def runtime(self):
        return self.app.runtime  # type: ignore[attr-defined]

    def refresh_data(self) -> None:  # pragma: no cover - 由子类实现
        pass

    def vim_key(self, key: str, count: int = 1) -> bool:
        """处理面板级 vim 按键; 返回 True 表示已消费."""
        return False

    def selected_row(self) -> dict | None:
        return None

    def on_mount(self) -> None:
        self.refresh_data()


# ==========================================================================
# 综设III-1: WAF 可视化
# ==========================================================================
class DashboardPanel(_Panel):
    MODULE_NAME = "WAF 可视化"
    MODULE_ICON = "▤"
    KEY = "1"

    def compose(self) -> ComposeResult:
        yield Static("▤ 可视化安全运营与管理平台  —  实时态势", classes="panel-title")
        with Horizontal(classes="row"):
            yield StatCard("总请求", id="st-requests")
            yield StatCard("已拦截", id="st-blocked", variant="bad")
            yield StatCard("拦截率", id="st-rate", variant="warn")
            yield StatCard("当前 QPS", id="st-qps", variant="info")
            yield StatCard("平均延迟", id="st-latency", variant="good")
            yield StatCard("漏洞发现", id="st-findings", variant="warn")
        with Horizontal(classes="row"):
            yield SparkPanel("请求速率 (60s)", palette.SKY, 52, id="sp-req")
            yield SparkPanel("拦截速率 (60s)", palette.RED, 52, id="sp-blk")
        with Horizontal(classes="row"):
            yield BarList("命中规则 TOP", palette.MAUVE, 20, id="bl-rules")
            yield BarList("高频来源 IP", palette.YELLOW, 20, id="bl-clients")
            yield Static("", id="lat-box", classes="card")
        yield Static("实时事件流  (最近 200 条)", classes="panel-title")
        yield RichLog(id="dash-log", markup=False, max_lines=200, wrap=False)

    def refresh_data(self) -> None:
        snap = self.runtime.snapshot()
        metrics = snap["metrics"]
        engine = snap["engine"]
        requests = metrics["requests"]
        blocked = metrics["blocked"]
        rate = (blocked / requests * 100) if requests else 0.0

        def card(cid, value, trend="", variant=None):
            widget = self.query_one(f"#{cid}", StatCard)
            widget.update_value(value, trend)

        card("st-requests", fmt_num(requests), f"uptime {fmt_uptime(snap['uptime_s'])}")
        card("st-blocked", fmt_num(blocked))
        card("st-rate", f"{rate:.1f}%")
        card("st-qps", f"{metrics['qps']:.1f}")
        card("st-latency", f"{metrics['waf_mean_ms']:.2f}ms")
        card("st-findings", str(metrics["findings"]))

        self.query_one("#sp-req", SparkPanel).set_values(
            self.runtime.metrics.qps.series())
        self.query_one("#sp-blk", SparkPanel).set_values(
            self.runtime.metrics.blocked_window.series())

        rule_hits: dict[str, float] = {}
        for event in self.runtime.bus.history("decision", 2000):
            for rule in event.payload.get("rules", []):
                rule_hits[str(rule)] = rule_hits.get(str(rule), 0) + 1
        self.query_one("#bl-rules", BarList).set_rows(
            sorted(rule_hits.items(), key=lambda kv: kv[1], reverse=True))

        self.query_one("#bl-clients", BarList).set_rows(
            [(ip, float(score)) for ip, _n, _s, score in snap["ids_top_clients"]][:8])

        latency = Text()
        latency.append("WAF 决策延迟分位\n", style=palette.OVERLAY1)
        lw = metrics["waf_p50_ms"]
        for label, key in (("P50", "waf_p50_ms"), ("P90", "waf_p90_ms"),
                           ("P95", "waf_p95_ms"), ("P99", "waf_p99_ms"),
                           ("MAX", "waf_max_ms")):
            value = metrics[key]
            latency.append(f"{label:>3} ", style=palette.OVERLAY0)
            latency.append_text(hbar(value, max(1.0, lw * 4), 11, palette.GREEN))
            latency.append(f" {value:6.3f}ms\n", style=f"bold {palette.TEXT}")
        latency.append("\n规则库\n", style=palette.OVERLAY1)
        rules = snap["rules"]
        latency.append(f" 启用 {rules['enabled']}/{rules['total']} 条\n",
                       style=f"bold {palette.SKY}")
        # 只显示占比最高的前 8 类: CRS 的类别名很长 (protocol-enforcement),
        # 全列出来会把卡片撑爆并挤掉右边的条形图。
        categories = sorted(rules.get("by_category", {}).items(),
                            key=lambda kv: -kv[1])[:8]
        peak = max((count for _name, count in categories), default=1) or 1
        # 宽度预算: 卡片约 32 列 (含 2 列内边距), 减去序号与计数后留给条形图。
        # 早先按 19+10 排版会超宽, 每条都折成两行, 排行榜反而更难读。
        for category, count in categories:
            label = category if len(category) <= 16 else category[:15] + "…"
            latency.append(f"  {label:<17}", style=palette.SUBTEXT0)
            latency.append_text(hbar(count, peak, 7, palette.MAUVE))
            latency.append(f" {count}\n", style="bold")
        remaining = len(rules.get("by_category", {})) - len(categories)
        if remaining > 0:
            latency.append(f"  … 另 {remaining} 类\n", style=palette.OVERLAY0)

        # 检测是「谁」做的 —— 原生解释器还是可选的真实 C 数据面, 一眼可见
        platform = self.runtime.platform_snapshot()
        health = platform.get("health") or {}
        latency.append("\n引擎\n", style=palette.OVERLAY1)
        latency.append(f" {platform['engine_display'][:34]}\n", style=palette.SUBTEXT1)
        latency.append("  数据面 ", style=palette.OVERLAY0)
        latency.append("原生解释器 (进程内)\n" if platform["in_process"]
                       else "真实 nginx (参考实现)\n",
                       style=palette.GREEN if platform["in_process"] else palette.YELLOW)
        failed = int(health.get("failed_patterns", 0) or 0)
        latency.append("  解释器 ", style=palette.OVERLAY0)
        latency.append("无缺口" if not failed else f"缺失 {failed} 条正则",
                       style=palette.GREEN if not failed else palette.DANGER)
        latency.append(f" · 方言改写 {int(health.get('translated_patterns', 0) or 0)}\n",
                       style=palette.OVERLAY1)
        totals = (platform.get("vendor") or {}).get("totals", {})
        latency.append("  内置资产 ", style=palette.OVERLAY0)
        latency.append(f"{totals.get('files', 0)} 文件 / "
                       f"{totals.get('bytes', 0) / 1048576:.1f} MiB\n",
                       style=palette.SUBTEXT1)
        self.query_one("#lat-box", Static).update(latency)

        log = self.query_one("#dash-log", RichLog)
        seen = getattr(self, "_seen", 0)
        events = self.runtime.bus.history(limit=10_000)
        if len(events) < seen:
            seen = 0
            log.clear()
        for event in events[seen:]:
            self._log_event(log, event)
        self._seen = len(events)

    def _log_event(self, log: RichLog, event) -> None:
        ts = time.strftime("%H:%M:%S", time.localtime(event.ts))
        payload = event.payload if isinstance(event.payload, dict) else {}
        line = Text()
        line.append(f"{ts} ", style=palette.OVERLAY0)
        if event.topic == "decision":
            verdict = payload.get("verdict", "?")
            style = {"pass": palette.GREEN, "log": palette.YELLOW,
                     "block": f"bold {palette.RED}", "drop": f"bold {palette.RED}",
                     "rate_limit": f"bold {palette.PEACH}"}.get(verdict, palette.TEXT)
            line.append(f"{verdict.upper():<10}", style=style)
            line.append(f"{payload.get('client',''):<16}", style=palette.OVERLAY1)
            line.append(str(payload.get("url", ""))[:70], style=palette.SUBTEXT1)
            line.append(f"  score={payload.get('score',0)}", style=palette.OVERLAY0)
        elif event.topic == "ids":
            line.append("IDS       ", style=f"bold {palette.MAUVE}")
            line.append(f"{payload.get('client',''):<16}", style=palette.OVERLAY1)
            line.append(f"{payload.get('message','')}", style=palette.MAUVE)
        elif event.topic == "scan.finding":
            line.append("FINDING   ", style=f"bold {palette.DANGER}")
            line.append(f"{payload.get('vuln_type',''):<34}", style=palette.DANGER)
            line.append(str(payload.get("url", ""))[:60], style=palette.SUBTEXT1)
        elif event.topic == "lifecycle":
            line.append("LIFECYCLE ", style=palette.SKY)
            line.append(str(payload)[:100], style=palette.OVERLAY1)
        else:
            return
        log.write(line)


# ==========================================================================
# 综设III-2: 配置管理
# ==========================================================================
class ConfigPanel(_Panel):
    MODULE_NAME = "配置管理"
    MODULE_ICON = "⚙"
    KEY = "2"

    def compose(self) -> ComposeResult:
        yield Static("⚙ 配置管理模块  —  j/k 选择 · Enter/Space 切换 · :w 保存",
                     classes="panel-title")
        yield DataTable(id="cfg-table", zebra_stripes=True)
        yield Static("", id="cfg-detail", classes="card")

    def on_mount(self) -> None:
        table = self.query_one("#cfg-table", DataTable)
        table.add_columns("配置项", "说明", "当前值")
        self.refresh_data()
        table.focus()

    def refresh_data(self) -> None:
        table = self.query_one("#cfg-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        values = self._values()
        for key, label, _spec, desc in CONFIG_SPECS:
            value = values[key]
            style = f"bold {palette.GREEN}" if value not in (False, 0, "off") else palette.OVERLAY0
            table.add_row(key, desc, Text(str(value), style=style), key=key)
        if cursor < table.row_count:
            table.move_cursor(row=cursor)
        self._update_detail()

    def _values(self) -> dict:
        cfg = self.runtime.config
        return {
            "enabled": cfg.waf.enabled, "mode": cfg.waf.mode,
            "anomaly_threshold": cfg.waf.anomaly_threshold,
            "paranoia_level": cfg.waf.paranoia_level, "strategy": cfg.waf.strategy,
            "inspect_body": cfg.waf.inspect_body,
            "block_above_threshold": cfg.waf.block_above_threshold,
            "rate_limit_rps": int(cfg.waf.rate_limit_rps),
            "add_x_forwarded_for": cfg.waf.add_x_forwarded_for,
            "max_body_bytes": cfg.waf.max_body_bytes,
        }

    def _current_key(self) -> str | None:
        table = self.query_one("#cfg-table", DataTable)
        if table.row_count == 0:
            return None
        try:
            row = table.get_row_at(table.cursor_row)
        except Exception:
            return None
        return str(row[0])

    def vim_key(self, key: str, count: int = 1) -> bool:
        if key not in ("enter", "space", "x"):
            return False
        name = self._current_key()
        if not name:
            return False
        spec = dict((k, s) for k, _l, s, _d in CONFIG_SPECS)[name]
        cfg = self.runtime.config.waf
        if spec == "bool":
            setattr(cfg, name, not getattr(cfg, name))
        elif isinstance(spec, list):
            current = getattr(cfg, name)
            try:
                idx = spec.index(current)
            except ValueError:
                if name == "paranoia_level":
                    idx = spec.index(cfg.paranoia_level) if cfg.paranoia_level in spec else 0
                else:
                    idx = 0
            setattr(cfg, name, spec[(idx + 1) % len(spec)])
        self._apply_runtime()
        self.refresh_data()
        self.app.notify(f"{name} → {getattr(cfg, name)}", timeout=2)  # type: ignore[attr-defined]
        return True

    def _apply_runtime(self) -> None:
        cfg = self.runtime.config.waf
        engine = self.runtime.engine
        engine.config.mode = cfg.mode
        engine.config.enabled = cfg.enabled
        engine.config.anomaly_threshold = cfg.anomaly_threshold
        engine.config.inspect_body = cfg.inspect_body
        engine.config.block_above_threshold = cfg.block_above_threshold
        engine.config.rate_limit_rps = float(cfg.rate_limit_rps)
        engine.set_paranoia(int(cfg.paranoia_level))
        engine.ids.rate_limit_rps = float(cfg.rate_limit_rps)
        engine.ids.rate_limit_burst = max(0, int(cfg.rate_limit_rps) * 2)
        self.runtime.balancer.strategy = cfg.strategy
        self.runtime.proxy.config.waf = cfg

    def _update_detail(self) -> None:
        name = self._current_key()
        spec = dict((k, s) for k, _l, s, _d in CONFIG_SPECS).get(name or "")
        text = Text()
        text.append("当前配置项: ", style=palette.OVERLAY0)
        text.append(str(name), style=f"bold {palette.SKY}")
        text.append("\n  可选值: ", style=palette.OVERLAY0)
        if isinstance(spec, list):
            text.append(" → ".join(str(s) for s in spec), style=palette.SUBTEXT1)
        elif spec == "bool":
            text.append("true / false", style=palette.SUBTEXT1)
        else:
            text.append("数值", style=palette.SUBTEXT1)
        text.append("\n\n配置文件: ", style=palette.OVERLAY0)
        text.append("sentinel.toml / :w 保存", style=palette.SUBTEXT1)
        self.query_one("#cfg-detail", Static).update(text)

    def selected_row(self) -> dict | None:
        name = self._current_key()
        return {"config": name, "value": self._values().get(name or "")}


# ==========================================================================
# 综设III-3: 入侵检测管理
# ==========================================================================
class IdsPanel(_Panel):
    MODULE_NAME = "入侵检测管理"
    MODULE_ICON = "◉"
    KEY = "3"

    def compose(self) -> ComposeResult:
        yield Static("◉ 入侵检测模块  —  行为分析 / 速率限制 / 异常评分", classes="panel-title")
        with Horizontal(classes="row"):
            yield StatCard("告警总数", id="ids-alerts", variant="bad")
            yield StatCard("跟踪来源 IP", id="ids-clients", variant="info")
            yield StatCard("速率限制", id="ids-limited", variant="warn")
            yield BarList("来源 IP 风险排行", palette.RED, 18, id="ids-top")
        yield DataTable(id="ids-table", zebra_stripes=True)

    def on_mount(self) -> None:
        table = self.query_one("#ids-table", DataTable)
        table.add_columns("时间", "规则", "严重级别", "来源", "类型", "描述", "证据")
        self._alerts: deque = deque(maxlen=500)
        self.runtime.bus.subscribe("ids", self._on_alert)
        for event in self.runtime.bus.history("ids", 200):
            self._on_alert(event)
        table.focus()

    def _on_alert(self, event) -> None:
        payload = event.payload
        if hasattr(payload, "as_dict"):
            payload = payload.as_dict()      # 便携引擎发布 Alert 对象
        self._alerts.append(payload)

    def refresh_data(self) -> None:
        snap = self.runtime.snapshot()
        self.query_one("#ids-alerts", StatCard).update_value(
            str(snap["metrics"]["ids_alerts"]))
        self.query_one("#ids-clients", StatCard).update_value(
            str(snap["engine"]["ids"]["tracked_clients"]))
        self.query_one("#ids-limited", StatCard).update_value(
            str(snap["metrics"]["rate_limited"]))
        self.query_one("#ids-top", BarList).set_rows(
            [(ip, float(score)) for ip, _n, _s, score in snap["ids_top_clients"]][:8])

        table = self.query_one("#ids-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        for alert in list(self._alerts)[-200:]:
            severity = alert.get("severity", "medium")
            table.add_row(
                time.strftime("%H:%M:%S", time.localtime(alert.get("created_at", 0))),
                str(alert.get("rule_id", "")),
                Text(SEVERITY_ZH.get(severity, severity), style=SEV_STYLE.get(severity, "")),
                alert.get("client", ""),
                alert.get("category", ""),
                alert.get("message", "")[:42],
                alert.get("evidence", "")[:28],
            )
        if 0 <= cursor < table.row_count:
            table.move_cursor(row=cursor)

    def selected_row(self) -> dict | None:
        if not self._alerts:
            return None
        index = self.query_one("#ids-table", DataTable).cursor_row
        items = list(self._alerts)[-200:]
        return items[index] if 0 <= index < len(items) else None


# ==========================================================================
# 综设II-3: 规则防御管理
# ==========================================================================
class RulesPanel(_Panel):
    MODULE_NAME = "规则防御管理"
    MODULE_ICON = "⛨"
    KEY = "4"

    def compose(self) -> ComposeResult:
        yield Static("⛨ 规则防御模块 (ModSecurity 兼容)  —  j/k 移动 · x 启停 · / 过滤 · :export 导出",
                     classes="panel-title")
        with Horizontal(classes="row"):
            yield StatCard("规则总数", id="rule-total", variant="info")
            yield StatCard("已启用", id="rule-active", variant="good")
            yield StatCard("命中次数", id="rule-hits", variant="warn")
            yield StatCard("PL 等级", id="rule-pl", variant="warn")
        yield DataTable(id="rules-table", zebra_stripes=True)
        yield Static("", id="rule-detail", classes="card")

    def on_mount(self) -> None:
        table = self.query_one("#rules-table", DataTable)
        table.add_columns("ID", "级别", "类别", "动作", "状态", "描述")
        self._filter = ""
        self.refresh_data()
        table.focus()

    def set_filter(self, text: str) -> None:
        self._filter = text.lower()
        self.refresh_data()

    def _rules(self):
        rules = list(self.runtime.rule_index())
        if self._filter:
            rules = [r for r in rules
                     if self._filter in r.description.lower()
                     or self._filter in str(r.id)
                     or self._filter in r.category.lower()]
        return sorted(rules, key=lambda r: (r.severity.weight, r.id), reverse=True)

    def refresh_data(self) -> None:
        table = self.query_one("#rules-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        hits: dict[str, int] = {}
        for event in self.runtime.bus.history("decision", 3000):
            for rule in event.payload.get("rules", []):
                hits[str(rule)] = hits.get(str(rule), 0) + 1
        for rule in self._rules():
            enabled = Text("启用" if rule.enabled else "停用",
                           style=palette.GREEN if rule.enabled else palette.OVERLAY0)
            table.add_row(
                str(rule.id),
                Text(SEVERITY_ZH[rule.severity.value], style=SEV_STYLE[rule.severity.value]),
                rule.category, rule.action, enabled, rule.description[:52],
                key=str(rule.id))
        if 0 <= cursor < table.row_count:
            table.move_cursor(row=cursor)
        snapshot = self.runtime.engine_snapshot()
        self.query_one("#rule-total", StatCard).update_value(str(snapshot["rules_total"]))
        self.query_one("#rule-active", StatCard).update_value(str(snapshot["rules_active"]))
        self.query_one("#rule-hits", StatCard).update_value(
            fmt_num(sum(hits.values())))
        self.query_one("#rule-pl", StatCard).update_value(f"PL{snapshot['paranoia_level']}")
        self._update_detail()

    def _current_rule(self):
        table = self.query_one("#rules-table", DataTable)
        if table.row_count == 0:
            return None
        try:
            row = table.get_row_at(table.cursor_row)
        except Exception:
            return None
        return self.runtime.rule_by_id(int(str(row[0])))

    def _update_detail(self) -> None:
        rule = self._current_rule()
        text = Text()
        if rule is None:
            text.append("(无)", style=palette.OVERLAY0)
        else:
            variables = [str(v) for v in getattr(rule, "variables", [])]
            transforms = [str(t) for t in getattr(rule, "transforms", [])]
            tags = [str(t) for t in getattr(rule, "tags", [])]
            secrule = getattr(rule, "secrule", "") or (
                rule.to_modsecurity() if hasattr(rule, "to_modsecurity") else "")
            text.append(f"#{rule.id}  ", style=f"bold {palette.SKY}")
            text.append(rule.description + "\n", style="bold")
            text.append("  来源: ", style=palette.OVERLAY0)
            text.append(f"{getattr(rule, 'source', '-')}   动作: {rule.action}\n",
                        style=palette.SUBTEXT1)
            text.append("  变量: ", style=palette.OVERLAY0)
            text.append(" | ".join(variables) or "(无)" , style=palette.SUBTEXT1)
            text.append("\n  算子: ", style=palette.OVERLAY0)
            # 算子内部用小写规范名分派, 展示时还原成 ModSecurity 的 @驼峰写法
            text.append(_operator_label(rule), style=palette.SUBTEXT1)
            text.append("\n  变换: ", style=palette.OVERLAY0)
            text.append(", ".join(transforms) or "(无)", style=palette.SUBTEXT1)
            text.append("\n  标签: ", style=palette.OVERLAY0)
            text.append(", ".join(tags) or "(无)", style=palette.SUBTEXT1)
            text.append("\n  规则原文: ", style=palette.OVERLAY0)
            text.append(secrule[:180], style=palette.OVERLAY0)
        self.query_one("#rule-detail", Static).update(text)

    def vim_key(self, key: str, count: int = 1) -> bool:
        if key in ("x", "space", "enter"):
            rule = self._current_rule()
            if rule is None:
                return False
            rule.enabled = not rule.enabled
            self.refresh_data()
            self.app.notify(  # type: ignore[attr-defined]
                f"规则 #{rule.id} {'启用' if rule.enabled else '停用'}", timeout=2)
            return True
        return False

    def selected_row(self) -> dict | None:
        rule = self._current_rule()
        return rule.to_dict() if rule else None


# ==========================================================================
# 综设III-4 / II-4: 日志审计管理
# ==========================================================================
class AuditPanel(_Panel):
    MODULE_NAME = "日志审计管理"
    MODULE_ICON = "▦"
    KEY = "5"

    def compose(self) -> ComposeResult:
        yield Static("▦ 日志审计模块  —  j/k 浏览 · / 检索 · d d 冻结清空 · r 恢复 · :export 导出",
                     classes="panel-title")
        with Horizontal(classes="row"):
            yield StatCard("审计条数", id="aud-total", variant="info")
            yield StatCard("放行", id="aud-pass", variant="good")
            yield StatCard("拦截", id="aud-block", variant="bad")
            yield StatCard("平均延迟", id="aud-latency", variant="warn")
        yield DataTable(id="audit-table", zebra_stripes=True)

    def on_mount(self) -> None:
        table = self.query_one("#audit-table", DataTable)
        table.add_columns("时间", "动作", "级别", "来源", "方法", "URL", "状态",
                          "后端", "耗时(ms)")
        self._filter = ""
        self._frozen = False
        self.refresh_data()
        table.focus()

    def set_filter(self, text: str) -> None:
        self._filter = text.lower()
        self._frozen = False
        self.refresh_data()

    def vim_key(self, key: str, count: int = 1) -> bool:
        if key == "dd":
            # 冻结自动刷新, 否则下一帧就会被实时数据覆盖
            self._frozen = True
            self.query_one("#audit-table", DataTable).clear()
            self.app.notify("已冻结审计视图 (磁盘日志保留), 按 r 恢复", timeout=2)  # type: ignore[attr-defined]
            return True
        if key == "r":
            self._frozen = False
            return True
        return False

    def refresh_data(self) -> None:
        if getattr(self, "_frozen", False):
            return
        table = self.query_one("#audit-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        records = self.runtime.audit.search(self._filter, limit=400)
        for record in reversed(records):
            action_style = f"bold {palette.RED}" if record.action == "block" else palette.GREEN
            table.add_row(
                time.strftime("%H:%M:%S", time.localtime(record.ts)),
                Text(record.action, style=action_style),
                record.severity, record.client, record.method,
                record.url[:46], str(record.status), record.backend,
                f"{record.latency_ms:.2f}")
        if 0 <= cursor < table.row_count:
            table.move_cursor(row=cursor)
        counts = self.runtime.audit.counts_by_action()
        self.query_one("#aud-total", StatCard).update_value(fmt_num(len(self.runtime.audit)))
        self.query_one("#aud-pass", StatCard).update_value(str(counts.get("pass", 0)))
        self.query_one("#aud-block", StatCard).update_value(str(counts.get("block", 0)))
        self.query_one("#aud-latency", StatCard).update_value(
            f"{self.runtime.metrics.latency.mean_ms:.2f}ms")

    def selected_row(self) -> dict | None:
        records = self.runtime.audit.search(self._filter, limit=400)
        index = self.query_one("#audit-table", DataTable).cursor_row
        items = list(reversed(records))
        if 0 <= index < len(items):
            record = items[index]
            return {"url": record.url, "client": record.client, "action": record.action,
                    "status": record.status, "latency_ms": record.latency_ms}
        return None


# ==========================================================================
# 综设I: 目标识别 + 漏洞检测
# ==========================================================================
class ScanPanel(_Panel):
    MODULE_NAME = "漏洞检测"
    MODULE_ICON = "⌖"
    KEY = "6"

    def compose(self) -> ComposeResult:
        yield Static("⌖ 漏洞扫描子系统  —  目标识别 -> 漏洞检测  (Enter 输入目标 · s 扫描 · d 深度扫描)",
                    classes="panel-title")
        with Horizontal(classes="row"):
            yield Input(placeholder="http://127.0.0.1:8080/ 或 直接回车使用靶场地址",
                        id="scan-target")
        with Horizontal(classes="row"):
            yield Static("", id="scan-engines", classes="card")
        with Horizontal(classes="row"):
            yield StatCard("扫描状态", "空闲", variant="info", id="scan-state")
            yield StatCard("接口发现", "-", id="scan-urls")
            yield StatCard("可注入参数", "-", id="scan-params")
            yield StatCard("漏洞数量", "-", variant="bad", id="scan-findings")
            yield StatCard("风险评分", "-", variant="warn", id="scan-risk")
            yield StatCard("请求数", "-", id="scan-requests")
        yield ProgressBar(total=100, show_eta=False, id="scan-progress")
        yield DataTable(id="scan-table", zebra_stripes=True)

    def on_mount(self) -> None:
        table = self.query_one("#scan-table", DataTable)
        table.add_columns("漏洞类型", "级别", "方法", "URL", "参数", "置信度")
        self._findings: list = []
        self._state = "空闲"
        self.runtime.bus.subscribe("scan.progress", self._on_progress)
        self.runtime.bus.subscribe("scan.finding", self._on_finding)
        table.focus()

    # ---- 事件 ----
    def _on_progress(self, event) -> None:
        phase = event.payload.get("phase")
        if phase == "recognized":
            self._state = f"已识别 {event.payload.get('urls')} 接口"
        elif phase == "finished":
            self._state = "已完成"
        elif phase == "error":
            self._state = "错误"

    def _on_finding(self, event) -> None:
        payload = event.payload
        if payload not in self._findings:
            self._findings.append(payload)

    # ---- 动作 ----
    def start_scan(self, deep: bool = False) -> None:
        target = self.query_one("#scan-target", Input).value.strip()
        if not target:
            urls = self.runtime.lab_urls()
            target = urls[0] if urls else "http://127.0.0.1:8080/"
            self.query_one("#scan-target", Input).value = target
        self._findings = []
        self._state = "扫描中 ..."
        self.query_one("#scan-progress", ProgressBar).update(progress=15)
        self.app.notify(f"开始{'深度' if deep else ''}扫描: {target}", timeout=3)  # type: ignore[attr-defined]
        self.runtime.scan_async(target, deep=deep, on_done=self._done)

    def _done(self, report) -> None:
        self._report = report
        self._findings = [f.as_dict() for f in report.findings]
        self._state = "已完成"

    def start_multi_scan(self, deep: bool = False) -> None:
        """多引擎融合扫描 (nuclei + w13scan + 内置)."""
        target = self.query_one("#scan-target", Input).value.strip()
        if not target:
            urls = self.runtime.lab_urls()
            target = urls[0] if urls else "http://127.0.0.1:8080/"
            self.query_one("#scan-target", Input).value = target
        targets = self.runtime.scan_targets(target)
        self._findings = []
        self._state = f"多引擎扫描中 ({len(targets)} 目标) ..."
        self.query_one("#scan-progress", ProgressBar).update(progress=10)
        self.app.notify(f"多引擎融合扫描: {len(targets)} 个目标", timeout=3)  # type: ignore[attr-defined]

        def _finished(outcome) -> None:
            report = self.runtime.last_report
            if report is not None:
                self._done(report)

        self.runtime.scan_multi_async(targets, deep=deep, on_done=_finished)

    def vim_key(self, key: str, count: int = 1) -> bool:
        if key in ("s", "r"):
            self.start_scan(deep=False)
            return True
        if key == "d":
            self.start_scan(deep=True)
            return True
        if key == "a":
            self.start_multi_scan(deep=False)
            return True
        if key == "A":
            self.start_multi_scan(deep=True)
            return True
        if key == "enter" and self.app.focused is self.query_one("#scan-target", Input):
            return False
        return False

    def refresh_data(self) -> None:
        self.query_one("#scan-state", StatCard).update_value(self._state)
        self.query_one("#scan-engines", Static).update(self._engine_line())
        self._update_stats()
        self._update_table()

    def _update_stats(self) -> None:
        report = getattr(self, "_report", None)
        if not report:
            return
        self.query_one("#scan-urls", StatCard).update_value(str(report.stats.urls))
        self.query_one("#scan-params", StatCard).update_value(str(report.stats.params))
        self.query_one("#scan-findings", StatCard).update_value(str(report.stats.findings))
        self.query_one("#scan-risk", StatCard).update_value(
            f"{report.risk_score} ({report.risk_level})")
        self.query_one("#scan-requests", StatCard).update_value(str(report.stats.requests))
        self.query_one("#scan-progress", ProgressBar).update(progress=100)

    def _update_table(self) -> None:
        table = self.query_one("#scan-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        for finding in self._findings:
            severity = finding.get("severity", "medium")
            table.add_row(
                TYPE_ZH.get(finding.get("vuln_type", ""), finding.get("vuln_type", "")),
                Text(SEVERITY_ZH.get(severity, severity),
                     style=SEV_STYLE.get(severity, "")),
                finding.get("method", ""), finding.get("url", "")[:52],
                finding.get("param", "") or "-",
                f"{finding.get('confidence', 0):.2f}")
        if 0 <= cursor < table.row_count:
            table.move_cursor(row=cursor)

    def _engine_line(self) -> Text:
        """引擎概览 —— 单行放得下, 否则换行排版会很难看.

        引擎的 ``display`` 是给人读的长句 (「Nuclei 模板引擎 (Sentinel 原生
        解释器)」), 直接铺开会撑爆卡片并挤走快捷键提示。这里只取名称主体,
        版本另起一行用弱化色显示。
        """
        infos = self.runtime.scanner_snapshot()["engines"]
        text = Text()
        text.append("扫描引擎  ", style=palette.OVERLAY0)
        for index, info in enumerate(infos):
            if index:
                text.append(" · ", style=palette.OVERLAY0)
            style = palette.GREEN if info["available"] else palette.OVERLAY0
            name = str(info["display"]).split(" (")[0]
            text.append(name, style=f"bold {style}")
        text.append("      [a] 融合扫描  [A] 深度融合", style=palette.OVERLAY1)
        text.append("\n")
        for info in infos:
            style = palette.OVERLAY1 if info["available"] else palette.DANGER
            version = (info["version"] or "不可用")[:30]
            text.append(f"  {info['name']:<9}", style=palette.SUBTEXT0)
            text.append(f"{version:<31}", style=style)
            text.append(f"{info['detail'][:46]}\n", style=palette.OVERLAY0)
        return text

    def selected_row(self) -> dict | None:
        index = self.query_one("#scan-table", DataTable).cursor_row
        return self._findings[index] if 0 <= index < len(self._findings) else None


# ==========================================================================
# 综设I-3: 漏洞库与规则引擎
# ==========================================================================
class VulnDbPanel(_Panel):
    MODULE_NAME = "漏洞库管理"
    MODULE_ICON = "☰"
    KEY = "7"

    def compose(self) -> ComposeResult:
        yield Static("☰ 漏洞库与规则引擎  —  检测插件 / Payload / 匹配规则", classes="panel-title")
        with Horizontal(classes="row"):
            yield StatCard("检测插件", id="vdb-plugins", variant="info")
            yield StatCard("Payload 集", id="vdb-payloads", variant="warn")
            yield StatCard("严重级插件", id="vdb-critical", variant="bad")
            yield StatCard("覆盖 OWASP", id="vdb-owasp", variant="good")
        yield DataTable(id="vdb-table", zebra_stripes=True)
        yield Static("", id="vdb-detail", classes="card")

    def on_mount(self) -> None:
        self._db = default_db()
        table = self.query_one("#vdb-table", DataTable)
        table.add_columns("插件", "名称", "级别", "CWE", "OWASP", "参数提示")
        self.refresh_data()
        table.focus()

    def refresh_data(self) -> None:
        table = self.query_one("#vdb-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        for spec in self._db.specs.values():
            table.add_row(
                spec.name, spec.title,
                Text(SEVERITY_ZH[spec.severity.value], style=SEV_STYLE[spec.severity.value]),
                spec.cwe, spec.owasp,
                ", ".join(spec.param_hints[:4]) or "*", key=spec.name)
        if 0 <= cursor < table.row_count:
            table.move_cursor(row=cursor)
        summary = self._db.summary()
        self.query_one("#vdb-plugins", StatCard).update_value(str(summary["plugins"]))
        self.query_one("#vdb-payloads", StatCard).update_value(
            str(summary["payload_sets"]))
        self.query_one("#vdb-critical", StatCard).update_value(
            str(summary["by_severity"].get("critical", 0)))
        owasp = {s.owasp for s in self._db.specs.values()}
        self.query_one("#vdb-owasp", StatCard).update_value(str(len(owasp)))
        self._update_detail()

    def _current(self):
        table = self.query_one("#vdb-table", DataTable)
        if table.row_count == 0:
            return None
        try:
            name = str(table.get_row_at(table.cursor_row)[0])
        except Exception:
            return None
        return self._db.specs.get(name)

    def _update_detail(self) -> None:
        spec = self._current()
        text = Text()
        if spec:
            text.append(f"{spec.name}\n", style=f"bold {palette.SKY}")
            text.append(spec.description + "\n\n", style=palette.SUBTEXT1)
            text.append("  严重级别: ", style=palette.OVERLAY0)
            text.append(spec.severity.value, style=SEV_STYLE[spec.severity.value])
            text.append(f"    CWE: {spec.cwe}    OWASP: {spec.owasp}\n", style=palette.OVERLAY0)
            payloads = self._db.payloads.get(spec.name)
            if isinstance(payloads, dict):
                text.append("  Payload: ", style=palette.OVERLAY0)
                text.append(f"{sum(len(v) for v in payloads.values())} 条 ("
                            + ", ".join(f"{k}:{len(v)}" for k, v in payloads.items()) + ")",
                            style=palette.SUBTEXT1)
            elif isinstance(payloads, list):
                text.append("  Payload: ", style=palette.OVERLAY0)
                text.append(f"{len(payloads)} 条\n", style=palette.SUBTEXT1)
                text.append("  " + " | ".join(str(p)[:24] for p in payloads[:3]),
                            style=palette.OVERLAY0)
        self.query_one("#vdb-detail", Static).update(text)

    def vim_key(self, key: str, count: int = 1) -> bool:
        return False

    def selected_row(self) -> dict | None:
        spec = self._current()
        if not spec:
            return None
        return {"plugin": spec.name, "title": spec.title, "severity": spec.severity.value,
                "cwe": spec.cwe, "owasp": spec.owasp}


# ==========================================================================
# 综设I-4: 报告生成
# ==========================================================================
class ReportPanel(_Panel):
    MODULE_NAME = "报告生成"
    MODULE_ICON = "✦"
    KEY = "8"

    FORMATS = [("全部格式 (md + html + json)", ("md", "html", "json")),
               ("Markdown", ("md",)), ("HTML", ("html",)), ("JSON", ("json",))]

    def compose(self) -> ComposeResult:
        yield Static("✦ 报告生成模块  —  Enter 生成报告 · j/k 选择格式 · 中文报告", classes="panel-title")
        with Horizontal(classes="row"):
            yield StatCard("最近扫描", "无", variant="info", id="rep-last")
            yield StatCard("漏洞总数", "-", variant="bad", id="rep-findings")
            yield StatCard("风险评分", "-", variant="warn", id="rep-risk")
            yield StatCard("已生成报告", "0", variant="good", id="rep-count")
        yield DataTable(id="rep-format", zebra_stripes=True)
        yield Static("", id="rep-preview", classes="card")

    def on_mount(self) -> None:
        table = self.query_one("#rep-format", DataTable)
        table.add_columns("#", "报告格式", "说明")
        for idx, (label, _fmt) in enumerate(self.FORMATS, 1):
            table.add_row(str(idx), label, "生成到 reports/ 目录")
        self._generated: list[str] = []
        self.refresh_data()
        table.focus()

    def vim_key(self, key: str, count: int = 1) -> bool:
        if key in ("enter", "space", "g"):
            self.generate()
            return True
        return False

    def generate(self) -> None:
        report = self.runtime.last_report
        if report is None:
            self.app.notify("尚无扫描结果, 请先执行扫描", timeout=3, severity="warning")  # type: ignore[attr-defined]
            return
        index = self.query_one("#rep-format", DataTable).cursor_row
        formats = self.FORMATS[max(0, min(len(self.FORMATS) - 1, index))][1]
        paths = write_report(report, "reports", "sentinel-scan", formats)
        self._generated.extend(paths.values())
        for kind, path in paths.items():
            self.app.notify(f"已生成 {kind.upper()}: {path}", timeout=4)  # type: ignore[attr-defined]
        self.refresh_data()

    def refresh_data(self) -> None:
        report = self.runtime.last_report
        if report:
            self.query_one("#rep-last", StatCard).update_value(report.seed[:22])
            self.query_one("#rep-findings", StatCard).update_value(str(report.stats.findings))
            self.query_one("#rep-risk", StatCard).update_value(
                f"{report.risk_score} ({report.risk_level})")
        self.query_one("#rep-count", StatCard).update_value(str(len(self._generated)))
        text = Text()
        text.append("报告预览 (Markdown 摘要)\n\n", style=palette.OVERLAY1)
        if report is None:
            text.append("暂无扫描结果 — 请先在 [6] 漏洞检测 面板执行扫描。", style=palette.OVERLAY0)
        else:
            preview = render_markdown(report).splitlines()
            for line in preview[:26]:
                style = f"bold {palette.SAPPHIRE}" if line.startswith("#") else palette.SUBTEXT1
                text.append(line[:110] + "\n", style=style)
        self.query_one("#rep-preview", Static).update(text)


# ==========================================================================
def _backend_distribution(raw) -> dict[str, int]:
    """归一化后端分布: 真实引擎返回 ``{upstream_addr: hits}``,
    便携引擎返回 :meth:`LoadBalancer.stats` 的列表."""
    if isinstance(raw, dict):
        return {str(k): int(v) for k, v in raw.items()}
    out: dict[str, int] = {}
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        key = item.get("address") or item.get("name") or "backend"
        out[str(key)] = int(item.get("total", 0))
    return out


# 综设II-5: WAF 引擎管理 (真实 nginx 引擎驱动)
# ==========================================================================
class EnginesPanel(_Panel):
    """引擎管理: 原生解释器的探测 / 监控 / 热切换 + 内置资产自检.

    这里要回答的核心问题是「Sentinel 到底靠什么在做检测」: 规则数据来自
    ``sentinel/vendor`` (仓内自包含), 决策由进程内的原生解释器完成; 真实
    nginx C 数据面只是可选的参考实现。面板把这三件事同时摆在眼前。
    """

    MODULE_NAME = "引擎与资产"
    MODULE_ICON = "⚙"
    KEY = "9"

    def compose(self) -> ComposeResult:
        yield Static("⚙ 引擎与资产  —  原生解释器 (进程内) · 内置规则/模板 · "
                     "可选的真实 C 数据面   ·   Enter/x 切换", classes="panel-title")
        with Horizontal(classes="row"):
            yield StatCard("当前引擎", id="eng-active", variant="good")
            yield StatCard("规则总数", id="eng-rules", variant="info")
            yield StatCard("已拦截", id="eng-blocks", variant="bad")
            yield StatCard("解释器缺失", id="eng-gaps", variant="warn")
            yield StatCard("内置资产", id="eng-vendor", variant="info")
        yield DataTable(id="engine-table", zebra_stripes=True)
        yield Static("", id="engine-detail", classes="card")

    def on_mount(self) -> None:
        table = self.query_one("#engine-table", DataTable)
        table.add_columns("类型", "引擎", "可用", "状态", "规则", "说明")
        self.refresh_data()
        table.focus()

    def _active_name(self) -> str:
        return self.runtime.snapshot()["engines"]["active"]

    def refresh_data(self) -> None:
        snap = self.runtime.snapshot()
        info = snap["engines"]
        active = info["active"]
        eng = snap["engine"]
        platform = self.runtime.platform_snapshot()

        table = self.query_one("#engine-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        native = set(info.get("native", ()))
        for item in info["engines"]:
            is_active = item["name"] == active
            kind = "原生" if item["name"] in native else "参考"
            table.add_row(
                Text(kind, style=palette.MAUVE if kind == "原生" else palette.OVERLAY0),
                Text(("* " if is_active else "  ") + item["display"],
                     style=f"bold {palette.SKY}" if is_active else palette.TEXT),
                Text("●" if item["available"] else "○",
                     style=palette.GREEN if item["available"] else palette.OVERLAY0),
                Text("运行中" if item["running"] else "待命",
                     style=palette.GREEN if item["running"] else palette.OVERLAY0),
                str(item.get("rules", 0)),
                (item.get("detail") or "")[:38],
                key=item["name"])
        if 0 <= cursor < table.row_count:
            table.move_cursor(row=cursor)

        health = platform.get("health") or {}
        gaps = int(health.get("failed_patterns", 0) or 0)
        totals = (platform.get("vendor") or {}).get("totals", {})
        self.query_one("#eng-active", StatCard).update_value(eng["name"])
        self.query_one("#eng-rules", StatCard).update_value(fmt_num(eng["rules_total"]))
        self.query_one("#eng-blocks", StatCard).update_value(fmt_num(eng["blocks"]))
        self.query_one("#eng-gaps", StatCard).update_value(str(gaps))
        self.query_one("#eng-vendor", StatCard).update_value(
            fmt_num(totals.get("files", 0)),
            f"{totals.get('bytes', 0) / 1048576:.1f} MiB")

        self.query_one("#engine-detail", Static).update(
            self._detail_text(eng, platform, snap, health))

    def _detail_text(self, eng: dict, platform: dict, snap: dict,
                     health: dict) -> Text:
        detail = Text()
        detail.append(f"{eng['display']}\n", style=f"bold {palette.SKY}")
        detail.append("  上游: ", style=palette.OVERLAY0)
        detail.append(eng["upstream"] + "\n", style=palette.SUBTEXT1)
        detail.append("  数据面: ", style=palette.OVERLAY0)
        detail.append(("真实 nginx 进程 (C 引擎决策 · 参考实现)" if eng["real_engine"]
                       else "Sentinel 进程内原生解释器 (无外部二进制)") + "\n",
                      style=palette.SUBTEXT1)
        detail.append("  运行参数: ", style=palette.OVERLAY0)
        detail.append(f"mode={eng['mode']}  PL{eng['paranoia_level']}  "
                      f"阈值 {eng['anomaly_threshold']}  规则 {eng['rules_total']}\n",
                      style=palette.SUBTEXT1)

        detail.append("\n  内置第三方资产 (sentinel/vendor)\n", style=palette.ACCENT)
        for item in (platform.get("vendor") or {}).get("collections", []):
            mark = "●" if item["present"] else "○"
            style = palette.GREEN if item["present"] else palette.DANGER
            detail.append(f"   {mark} ", style=style)
            detail.append(f"{item['key']:<18}", style=palette.SUBTEXT0)
            detail.append(f"{item['files']:>6} 文件  "
                          f"{item['bytes'] / 1024:>8.0f} KiB  ", style=palette.OVERLAY1)
            detail.append(f"{item['license']}\n", style=palette.OVERLAY0)
        missing = platform.get("vendor_missing") or []
        if missing:
            detail.append(f"   ⚠ 缺失集合: {', '.join(missing)} "
                          "(运行 tools/vendor.py 重新同步)\n", style=palette.DANGER)

        detail.append("\n  解释器自检\n", style=palette.ACCENT)
        failed = int(health.get("failed_patterns", 0) or 0)
        translated = int(health.get("translated_patterns", 0) or 0)
        detail.append("   正则: ", style=palette.OVERLAY0)
        detail.append(f"编译失败 {failed}", style=palette.DANGER if failed
                      else palette.GREEN)
        detail.append(" / ", style=palette.OVERLAY0)
        detail.append(f"PCRE 方言改写 {translated}\n", style=palette.YELLOW
                      if translated else palette.SUBTEXT1)
        for key, label in (("warnings", "解析告警"), ("templates", "模板条数"),
                           ("functions", "DSL 函数"), ("active", "生效规则")):
            if key in health:
                detail.append(f"   {label}: ", style=palette.OVERLAY0)
                detail.append(f"{health[key]}\n", style=palette.SUBTEXT1)

        traffic = eng.get("traffic") or {}
        if traffic:
            detail.append("  nginx stub_status: ", style=palette.OVERLAY0)
            detail.append(f"active={traffic.get('active', 0)} "
                          f"accepts={traffic.get('accepts', 0)} "
                          f"requests={traffic.get('requests', 0)}\n",
                          style=palette.SUBTEXT1)
        backends = _backend_distribution(snap.get("backends"))
        if backends:
            detail.append("  负载均衡分布: ", style=palette.OVERLAY0)
            detail.append("  ".join(f"{addr}×{count}"
                                    for addr, count in sorted(backends.items())) + "\n",
                          style=palette.SUBTEXT1)
        detail.append("  提示: ", style=palette.OVERLAY0)
        detail.append("j/k 选择, Enter/x 热切换; :engine <name> 亦可。",
                      style=palette.OVERLAY1)
        return detail

    def _selected_engine(self) -> str | None:
        table = self.query_one("#engine-table", DataTable)
        if table.row_count == 0:
            return None
        try:
            return str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        except Exception:
            return None

    def vim_key(self, key: str, count: int = 1) -> bool:
        if key not in ("x", "space", "enter"):
            return False
        name = self._selected_engine()
        if not name:
            return False
        try:
            switched = self.runtime.switch_engine(name)
        except Exception as exc:  # noqa: BLE001
            self.app.notify(f"引擎切换失败: {exc}", timeout=5, severity="error")  # type: ignore[attr-defined]
            return True
        self.app.notify(f"WAF 引擎已切换 -> {switched}", timeout=3)  # type: ignore[attr-defined]
        self.refresh_data()
        return True

    def selected_row(self) -> dict | None:
        name = self._selected_engine()
        if not name:
            return None
        for item in self.runtime.snapshot()["engines"]["engines"]:
            if item["name"] == name:
                return item
        return None


def _operator_label(rule) -> str:
    """规则算子的人类可读写法 (``@rx`` / ``@detectSQLi`` / ``@ge``).

    内部按小写规范名分派 (见 ``secrule.syntax.OPERATOR_DISPLAY``), 面板要还原成
    ModSecurity 的写法 —— 否则用户在界面上看到 ``detectsqli`` 会以为是 bug。
    """
    from ..waf.secrule.syntax import OPERATOR_DISPLAY

    name = getattr(rule, "operator", "") or ""
    if not name:
        return "(无)"
    label = OPERATOR_DISPLAY.get(name.lower(), f"@{name}")
    argument = getattr(rule, "operator_arg", "") or ""
    if len(argument) > 160:
        argument = argument[:157] + "…"
    return f"{label} {argument}".strip()
