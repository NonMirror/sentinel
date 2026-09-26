"""运行时 (SentinelRuntime) 引擎集成测试.

覆盖统一入口端口、快照结构、引擎热切换、多引擎扫描编排与扫描目标构造。
"""
from __future__ import annotations

import pytest

from sentinel.core.config import Config
from sentinel.runtime import SentinelRuntime

ATTACK = "/?id=1%20union%20select%201,2,3--"


# --------------------------------------------------------------------------
# 便携引擎 (python) — 快速, 无 nginx 依赖
# --------------------------------------------------------------------------
def test_runtime_python_engine_blocks_and_writes_audit(runtime, http):
    base = f"http://127.0.0.1:{runtime.front_port}"
    assert runtime.engine_name == "python"
    assert not runtime.engine_manager.is_real
    assert http(base + "/?q=hello").status == 200
    blocked = http(base + ATTACK)
    assert blocked.status == 403
    assert blocked.header("X-Sentinel-Rule")

    snapshot = runtime.snapshot()
    assert snapshot["engine"]["name"] == "python"
    assert snapshot["engine"]["real_engine"] is False
    assert snapshot["engine"]["rules_total"] > 0
    assert snapshot["rules"]["total"] == snapshot["engine"]["rules_total"]
    assert snapshot["metrics"]["blocked"] >= 1
    assert snapshot["front_port"] == runtime.proxy_port

    rules = runtime.rule_index()
    assert rules and runtime.rule_by_id(rules[0].id) is not None
    assert runtime.rules_summary()["by_category"]


def test_runtime_snapshot_has_all_panel_keys(runtime):
    snapshot = runtime.snapshot()
    for key in ("running", "uptime_s", "engine_name", "real_engine", "proxy_port",
                "front_port", "lab_ports", "metrics", "engine", "engines",
                "backends", "ids_top_clients", "audit_total", "rules"):
        assert key in snapshot, f"缺少快照键: {key}"
    assert len(snapshot["lab_ports"]) >= 1
    status = snapshot["engines"]["status"]
    assert status["name"] == runtime.engine_name


def test_runtime_scan_targets_and_lab_urls(runtime):
    base = "http://127.0.0.1:9000/"
    targets = runtime.scan_targets(base)
    assert targets[0] == base
    assert any("/search?q=" in t for t in targets)
    assert any("/admin" in t for t in targets)
    assert all(t.startswith("http://127.0.0.1:9000") for t in targets)
    assert runtime.lab_urls() and all(u.startswith("http://") for u in runtime.lab_urls())


def test_runtime_builtin_scan_finds_lab_vulns(runtime):
    report = runtime.scan(runtime.lab_urls()[0], deep=False)
    assert report.stats.findings > 0
    assert runtime.last_report is report
    assert report in runtime.scan_history
    assert report.risk_score > 0


def test_runtime_scanner_snapshot(runtime):
    snapshot = runtime.scanner_snapshot()
    names = {info["name"] for info in snapshot["engines"]}
    assert names == {"nuclei", "w13scan", "builtin"}
    assert snapshot["default"]
    assert runtime.scanner_manager.available()["builtin"] is True


def test_runtime_ids_aggregation(runtime):
    base = f"http://127.0.0.1:{runtime.front_port}"
    from tests.conftest import fetch
    for _ in range(2):
        fetch(base + ATTACK)
    top = runtime.top_clients(5)
    assert top and top[0][1] >= 1
    assert runtime.stats()["tracked_clients"] >= 1


# --------------------------------------------------------------------------
# 原生引擎 (modsecurity / naxsi) —— 进程内决策, 无需任何外部依赖
# --------------------------------------------------------------------------
@pytest.mark.slow
@pytest.mark.integration
@pytest.mark.parametrize("engine_name", ["modsecurity", "naxsi"])
def test_runtime_native_engine_snapshot(engine_name, native_engine_runtimes):
    runtime = native_engine_runtimes.get(engine_name)
    if runtime is None:
        pytest.skip(f"{engine_name} 不可用")
    snapshot = runtime.snapshot()
    assert snapshot["real_engine"] is False       # 原生引擎在进程内决策
    assert snapshot["engine_name"] == engine_name
    assert snapshot["engine"]["rules_total"] > 0
    assert snapshot["engine"]["in_process"] is True


@pytest.mark.slow
@pytest.mark.integration
@pytest.mark.parametrize("engine_name", ["modsecurity", "naxsi"])
def test_native_engine_blocks_attack_through_proxy(engine_name, native_engine_runtimes,
                                                   http):
    """原生引擎必须真的挂在代理上拦住攻击 (而不是只在自己内部判定)."""
    runtime = native_engine_runtimes.get(engine_name)
    if runtime is None:
        pytest.skip(f"{engine_name} 不可用")
    base = f"http://127.0.0.1:{runtime.front_port}"
    assert http(base + "/?q=hello&page=2").status == 200, "误拦正常请求"
    assert http(base + ATTACK).status == 403


@pytest.mark.slow
@pytest.mark.integration
def test_runtime_switch_python_and_native_engine(native_engine_runtimes, http):
    if "modsecurity" not in native_engine_runtimes:
        pytest.skip("modsecurity 不可用")
    runtime = native_engine_runtimes["modsecurity"]
    original = runtime.engine_name
    try:
        runtime.switch_engine("python")
        assert runtime.engine_name == "python"
        assert not runtime.engine_manager.is_real
        base = f"http://127.0.0.1:{runtime.front_port}"
        assert http(base + ATTACK).status == 403     # 便携引擎同样拦截
        runtime.switch_engine(original)
        assert runtime.engine_name == original
        assert not runtime.engine_manager.is_real
    finally:
        if runtime.engine_name != original:
            runtime.switch_engine(original)


@pytest.mark.slow
@pytest.mark.integration
def test_runtime_multi_engine_scan_against_lab(tmp_path):
    """运行时多引擎编排: 至少内置引擎产出结果, 并记录每次引擎执行."""
    config = Config()
    config.listener.port = 0
    config.lab.base_port = 0
    config.lab.instances = 1
    config.audit_path = str(tmp_path / "audit.jsonl")
    runtime = SentinelRuntime(config, engine="python").start()
    try:
        targets = runtime.scan_targets(runtime.lab_urls()[0])
        outcome = runtime.scan_multi(targets, engines=["builtin"], deep=False)
        assert outcome.findings
        assert outcome.runs and outcome.runs[0].engine == "builtin"
        assert runtime.last_report is not None
        assert runtime.last_report.stats.findings == len(outcome.findings)
        assert runtime.last_report.engine_runs[0].engine == "builtin"  # type: ignore[attr-defined]
    finally:
        runtime.stop()
