"""真实 nginx C 数据面端到端测试 (参考实现).

Sentinel 默认跑的是进程内的原生解释器 (见 tests/test_native_engines.py);
这里测的是**可选的参考数据面** —— 真实启动 nginx + libmodsecurity / Naxsi,
用于校对原生实现的语义。未构建时整组自动 skip。

验证:
  * 攻击载荷被真实 C 引擎拦截 (403), 正常流量放行 (200)
  * 拦截事件通过 error.log 回采进入事件总线 / 审计 / 指标
  * access.log 回采真实流量 (QPS / 延迟 / 状态码) 与上游负载均衡分布
  * 引擎热重载 (模式切换) 与引擎热切换
"""
from __future__ import annotations

import time

import pytest

from sentinel.core.config import BackendConfig, Config, WafConfig
from sentinel.core.events import EventBus
from sentinel.core.metrics import Metrics
from sentinel.lab.server import LabServer
from sentinel.waf.engines import EngineManager

pytestmark = [pytest.mark.slow, pytest.mark.integration]

ATTACKS = [
    "/?id=1%20union%20select%201,2,3--",
    "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/?f=../../../../etc/passwd",
]


def wait_for(predicate, timeout: float = 8.0, interval: float = 0.1) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


@pytest.fixture(scope="module")
def lab_backends():
    servers = [LabServer("127.0.0.1", 0, f"e2e-{i}") for i in range(1, 3)]
    for server in servers:
        server.start()
    yield [BackendConfig(s.name, s.host, s.bound_port) for s in servers]
    for server in servers:
        server.stop()


def build_engine(name: str, backends, *, mode: str = "block",
                 paranoia_level: int = 1) -> tuple[EngineManager, EventBus]:
    config = Config()
    config.listener.port = 0
    config.waf.mode = mode
    config.waf.paranoia_level = paranoia_level
    config.backends = list(backends)
    bus = EventBus()
    manager = EngineManager(config, bus=bus, metrics=Metrics(), engine=name)
    return manager, bus


# --------------------------------------------------------------------------
# 拦截能力
# --------------------------------------------------------------------------
@pytest.mark.parametrize("engine_name", ["nginx-modsecurity", "nginx-naxsi"])
def test_real_engine_blocks_attacks(engine_name, reference_engine_runtimes, http):
    runtime = reference_engine_runtimes.get(engine_name)
    if runtime is None:
        pytest.skip(f"{engine_name} 未构建")
    base = f"http://127.0.0.1:{runtime.front_port}"
    clean = http(base + "/?q=hello&page=2")
    assert clean.status == 200, f"{engine_name} 误拦正常请求"
    for payload in ATTACKS:
        response = http(base + payload)
        assert response.status == 403, f"{engine_name} 未拦截 {payload}"


@pytest.mark.parametrize("engine_name", ["nginx-modsecurity", "nginx-naxsi"])
def test_real_engine_records_events_audit_and_metrics(engine_name, reference_engine_runtimes, http):
    runtime = reference_engine_runtimes.get(engine_name)
    if runtime is None:
        pytest.skip(f"{engine_name} 未构建")
    base = f"http://127.0.0.1:{runtime.front_port}"
    before_audit = runtime.audit.total
    for payload in ATTACKS:
        http(base + payload)

    driver = runtime.engine_manager.current
    assert wait_for(lambda: driver.blocks >= len(ATTACKS)), "引擎未回采到拦截事件"

    # 事件总线
    blocks = runtime.bus.history("block", 50)
    assert len(blocks) >= len(ATTACKS)
    payload = blocks[-1].payload
    assert payload["rule_id"] > 0 and payload["severity"]
    assert payload["category"] in ("crs", "modsecurity", "naxsi")

    # 审计日志 (回采为异步, 需等待)
    assert wait_for(lambda: runtime.audit.total > before_audit), "审计日志未增长"
    recent = runtime.audit.search("", limit=50)
    assert any(record.action == "block" for record in recent)
    assert any(record.extra.get("engine") == engine_name for record in recent)

    # 指标
    assert wait_for(lambda: runtime.metrics.snapshot()["blocked"] >= len(ATTACKS))
    metrics = runtime.metrics.snapshot()
    assert metrics["blocked"] >= len(ATTACKS)
    assert metrics["requests"] >= len(ATTACKS)


@pytest.mark.parametrize("engine_name", ["nginx-modsecurity", "nginx-naxsi"])
def test_real_engine_traffic_and_load_balancing(engine_name, reference_engine_runtimes, http):
    runtime = reference_engine_runtimes.get(engine_name)
    if runtime is None:
        pytest.skip(f"{engine_name} 未构建")
    base = f"http://127.0.0.1:{runtime.front_port}"
    for _ in range(6):
        http(base + "/?q=round-robin")
    driver = runtime.engine_manager.current
    assert wait_for(lambda: sum(driver.backend_stats().values()) >= 6)
    distribution = driver.backend_stats()
    assert len(distribution) >= 2, "负载均衡未分发到多个后端"
    status = driver.status()
    assert status.running and status.front_port
    traffic = driver.traffic()
    assert traffic.get("requests", 0) > 0


# --------------------------------------------------------------------------
# 模式 / 热切换
# --------------------------------------------------------------------------
def test_modsecurity_detect_mode_does_not_block(lab_backends, http):
    from sentinel.waf.engines.nginx_dataplane import NginxModSecurityEngine
    if not NginxModSecurityEngine.available():
        pytest.skip("nginx + ModSecurity 未构建")
    manager, _ = build_engine("nginx-modsecurity", lab_backends, mode="detect")
    driver = manager.start()
    try:
        base = f"http://127.0.0.1:{driver.front_port}"
        assert http(base + ATTACKS[0]).status == 200       # DetectionOnly
        assert wait_for(lambda: driver.events > 0)          # 仍产生告警
    finally:
        manager.stop()


def test_engine_reload_applies_new_config(lab_backends):
    from sentinel.waf.engines.nginx_dataplane import NginxNaxsiEngine
    if not NginxNaxsiEngine.available():
        pytest.skip("nginx + Naxsi 未构建")
    manager, _ = build_engine("nginx-naxsi", lab_backends)
    driver = manager.start()
    try:
        assert driver.status().running
        manager.config.waf.paranoia_level = 4
        manager.reload()
        assert driver.check_thresholds()["SQL"] == 5
        assert driver.status().running
    finally:
        manager.stop()


def test_runtime_switches_between_real_engines(reference_engine_runtimes):
    names = [name for name in ("nginx-modsecurity", "nginx-naxsi")
             if name in reference_engine_runtimes]
    if len(names) < 2:
        pytest.skip("需要构建两个真实 nginx 数据面")
    runtime = reference_engine_runtimes[names[0]]
    original = runtime.engine_name
    other = names[1] if names[1] != original else names[0]
    try:
        assert runtime.switch_engine(other) == other
        assert runtime.engine_name == other
        assert runtime.engine_manager.is_real
    finally:
        runtime.switch_engine(original)
    assert runtime.engine_name == original


def test_engine_unavailable_raises_clear_error():
    """未构建时, 参考引擎必须抛出**能指明怎么办**的错误."""
    from sentinel.waf.engines.base import EngineUnavailable
    from sentinel.waf.engines.nginx_dataplane import NginxNaxsiEngine

    engine = NginxNaxsiEngine(Config())
    engine.install = None
    with pytest.raises(EngineUnavailable, match="build_engines"):
        engine.start()
