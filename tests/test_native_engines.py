"""原生引擎端到端测试 (进程内决策, 无外部二进制).

这是 Sentinel 现在的**主数据面**: 反向代理直接调用
:class:`~sentinel.waf.engines.modsecurity.ModSecurityEngine` /
:class:`~sentinel.waf.engines.naxsi.NaxsiEngine` 的 ``inspect()`` 拿到决策。

与 ``test_engine_e2e.py`` (真实 nginx C 数据面) 的分工:
  * 这里守住**默认路径**的正确性 —— 拦截、放行、审计、指标、模式、热切换;
  * 那里守住**语义对照** —— 原生解释器与 libmodsecurity 是否一致。
"""
from __future__ import annotations

import pytest

from sentinel.core.config import Config
from sentinel.core.models import HttpRequest
from sentinel.runtime import SentinelRuntime
from sentinel.waf.engines import EngineManager
from sentinel.waf.engines.modsecurity import ModSecurityEngine
from sentinel.waf.engines.naxsi import NaxsiEngine

pytestmark = [pytest.mark.integration]

ATTACKS = [
    "/?id=1%20union%20select%201,2,3--",
    "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/?f=../../../../etc/passwd",
]
BENIGN = ["/?q=hello&page=2", "/?q=select+the+best+laptop", "/?q=union+station+hours"]


def request(target: str) -> HttpRequest:
    path, _, query = target.partition("?")
    return HttpRequest(method="GET", target=target, path=path or "/", query=query,
                       headers={"Host": "lab.local", "User-Agent": "Mozilla/5.0"},
                       remote_addr="127.0.0.1")


# --------------------------------------------------------------------------
# 驱动层: 无需任何外部依赖即可工作
# --------------------------------------------------------------------------
class TestEnginesAreSelfContained:
    def test_crs_engine_available_without_toolchain(self):
        assert ModSecurityEngine.available() is True
        driver = ModSecurityEngine(Config())
        assert driver.status().available is True
        assert driver.rule_count() > 300

    def test_naxsi_engine_available_without_toolchain(self):
        assert NaxsiEngine.available() is True
        driver = NaxsiEngine(Config())
        assert driver.rule_count() >= 40

    def test_interpreter_reports_no_regex_gaps(self):
        """解释器覆盖率的诚实指标: 有失败的正则就必须显式暴露出来.

        ``operators.FAILED_PATTERNS`` 是进程级的健康登记表 (故意如此, 便于
        在 TUI 里随时查看), 因此这里先清零再装载规则 —— 否则其它用例故意
        编译的坏正则会把计数带过来。
        """
        from sentinel.waf.secrule import operators

        operators.reset_health()
        driver = ModSecurityEngine(Config())
        health = driver.health()
        assert health["failed_patterns"] == 0, health.get("failed_samples")
        assert health["warnings"] == 0
        # 方言改写是**正常**的 (Python re 与 PCRE 本就不同), 记录但不报错
        assert health["translated_patterns"] >= 0

    def test_engines_report_vendor_provenance(self):
        driver = ModSecurityEngine(Config())
        assert "sentinel" in driver.upstream.lower() or "自研" in driver.upstream

    def test_manager_never_auto_selects_reference_engine(self):
        manager = EngineManager(Config())
        assert not manager.is_reference


# --------------------------------------------------------------------------
# 决策: 拦截 / 放行
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def crs():
    """经典 CRS 驱动 (模块内复用, 装载一次约 0.2s)."""
    return ModSecurityEngine(Config())


@pytest.fixture(scope="module")
def runtime(tmp_path_factory):
    """一体化运行时: 2 实例靶场 + 反向代理 (端口全随机)."""
    config = Config()
    config.listener.host = "127.0.0.1"
    config.listener.port = 0
    config.lab.base_port = 0
    config.lab.instances = 2
    config.waf.mode = "block"
    config.audit_path = str(tmp_path_factory.mktemp("audit") / "audit.jsonl")
    instance = SentinelRuntime(config, engine="modsecurity").start()
    yield instance
    instance.stop()


class TestDecisions:
    @pytest.mark.parametrize("target", ATTACKS)
    def test_crs_blocks_attacks(self, crs, target):
        decision = crs.inspect(request(target))
        assert decision.blocked and decision.matched_rules

    @pytest.mark.parametrize("target", BENIGN)
    def test_crs_passes_benign(self, crs, target):
        assert not crs.inspect(request(target)).blocked

    def test_naxsi_blocks_clear_attacks(self):
        driver = NaxsiEngine(Config())
        decision = driver.inspect(request("/?id=1 union select 1,2 from users"))
        assert decision.blocked and decision.anomaly_score >= 8

    def test_mode_detect_does_not_block(self):
        config = Config()
        config.waf.mode = "detect"
        driver = ModSecurityEngine(config)
        decision = driver.inspect(request(ATTACKS[0]))
        assert not decision.blocked
        assert decision.matched_rules, "detect 模式仍应记录命中"

    def test_mode_off_short_circuits(self):
        config = Config()
        config.waf.mode = "off"
        driver = ModSecurityEngine(config)
        assert not driver.inspect(request(ATTACKS[0])).matched_rules

    def test_paranoia_level_changes_decision_set(self):
        low_cfg, high_cfg = Config(), Config()
        high_cfg.waf.paranoia_level = 4
        low, high = ModSecurityEngine(low_cfg), ModSecurityEngine(high_cfg)
        target = "/?q=1%20or%20sleep(5)"
        assert high.inspect(request(target)).blocked
        assert high.inspect(request(target)).anomaly_score >= \
            low.inspect(request(target)).anomaly_score


# --------------------------------------------------------------------------
# 通过真实 HTTP 的端到端 (反向代理 + 靶场)
# --------------------------------------------------------------------------
class TestProxyEndToEnd:
    def test_proxy_blocks_and_passes(self, runtime, http):
        base = f"http://127.0.0.1:{runtime.front_port}"
        assert http(base + "/?q=hello").status == 200
        blocked = http(base + ATTACKS[0])
        assert blocked.status == 403
        assert blocked.header("X-Sentinel-Rule")

    def test_audit_and_metrics_recorded(self, runtime, http):
        base = f"http://127.0.0.1:{runtime.front_port}"
        before = runtime.audit.total
        for payload in ATTACKS:
            http(base + payload)
        assert runtime.audit.total > before
        records = runtime.audit.search("", limit=50)
        assert any(record.action == "block" for record in records)
        assert runtime.metrics.snapshot()["blocked"] >= 1

    def test_engine_hot_switch_keeps_serving(self, runtime, http):
        """热切换后代理必须继续可用 (监听端口可能变, 因此每次重取)."""
        original = runtime.engine_name
        try:
            assert runtime.switch_engine("naxsi") == "naxsi"
            base = f"http://127.0.0.1:{runtime.front_port}"
            assert http(base + "/?q=hello").status == 200
            assert runtime.switch_engine("python") == "python"
            base = f"http://127.0.0.1:{runtime.front_port}"
            assert http(base + ATTACKS[0]).status == 403
        finally:
            runtime.switch_engine(original)
        assert runtime.engine_name == original
        base = f"http://127.0.0.1:{runtime.front_port}"
        assert http(base + ATTACKS[0]).status == 403

    def test_reload_keeps_engine_consistent(self, runtime):
        before = runtime.rules_summary()["total"]
        runtime.reload_engine()
        assert runtime.rules_summary()["total"] == before
        assert runtime.engine.rule_count() == before

    def test_platform_snapshot_exposes_vendor_assets(self, runtime):
        platform = runtime.platform_snapshot()
        assert platform["vendor_missing"] == []
        keys = {item["key"] for item in platform["vendor"]["collections"]}
        assert {"crs", "naxsi", "nuclei-templates"} <= keys
        assert platform["in_process"] is True


@pytest.mark.parametrize("name", ["modsecurity", "naxsi"])
def test_engine_status_shape(name):
    """TUI / 报告依赖的字段必须齐全."""
    from sentinel.waf.engines import ENGINE_CLASSES
    driver = ENGINE_CLASSES[name](Config())
    status = driver.status()
    payload = status.as_dict()
    for key in ("name", "display", "upstream", "available", "running", "rules",
                "detail", "real_engine"):
        assert key in payload, key
    assert payload["real_engine"] is False


# --------------------------------------------------------------------------
# 事件广播 (TUI 的入侵检测面板 / 来源画像全靠它)
# --------------------------------------------------------------------------
class TestAlertEvents:
    def test_detection_publishes_ids_event_with_client(self):
        """命中必须广播 ids 事件, 且带上真实来源 IP.

        少了这个事件, 入侵检测面板是「告警总数很大、表格一行没有」,
        来源 IP 排行也永远是空的 —— 原生引擎早期就是这样。
        """
        from sentinel.core.config import Config
        from sentinel.core.events import EventBus

        bus = EventBus()
        alerts: list[dict] = []
        bus.subscribe("ids", lambda event: alerts.append(event.payload))
        driver = ModSecurityEngine(Config(), bus=bus)
        driver.inspect(request(ATTACKS[1]))
        assert alerts, "命中未广播 ids 事件"
        alert = alerts[0]
        assert alert["client"] == "127.0.0.1"
        assert alert["rule_id"] and alert["severity"]

    def test_evidence_explains_the_decision(self):
        """evidence 要说明「为什么拦」(评分 / 规则号), 而不是复述描述."""
        from sentinel.core.config import Config
        from sentinel.core.events import EventBus

        bus = EventBus()
        alerts: list[dict] = []
        bus.subscribe("ids", lambda event: alerts.append(event.payload))
        ModSecurityEngine(Config(), bus=bus).inspect(request(ATTACKS[0]))
        evidence = alerts[0]["evidence"]
        assert "score=" in evidence and "rules=" in evidence
        assert evidence != alerts[0]["message"]

    def test_benign_request_publishes_nothing(self):
        from sentinel.core.config import Config
        from sentinel.core.events import EventBus

        bus = EventBus()
        seen: list = []
        bus.subscribe("*", lambda event: seen.append(event.topic))
        ModSecurityEngine(Config(), bus=bus).inspect(request("/?q=hello"))
        assert "ids" not in seen and "block" not in seen

    def test_blocked_request_publishes_block_event(self):
        from sentinel.core.config import Config
        from sentinel.core.events import EventBus

        bus = EventBus()
        seen: list = []
        bus.subscribe("block", lambda event: seen.append(event.payload))
        decision = ModSecurityEngine(Config(), bus=bus).inspect(request(ATTACKS[0]))
        assert decision.blocked and seen
