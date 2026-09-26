"""漏洞扫描引擎测试 (nuclei / w13scan / 内置).

单元部分使用真实引擎产生的 JSONL 样本验证解析与规范化; 端到端部分 (slow) 会真实
调用 nuclei 与 w13scan 扫描靶场。
"""
from __future__ import annotations

import json
import pathlib
import socket
from pathlib import Path

import pytest

from sentinel.core.models import Finding, Severity
from sentinel.lab.server import LabServer
from sentinel.scanner.engines import (
    BuiltinEngine,
    NucleiEngine,
    ScannerEngineManager,
    W13ScanEngine,
    dedupe,
)
from sentinel.scanner.engines.base import severity_by_type, severity_of


# --------------------------------------------------------------------------
# 单元: 严重级别映射
# --------------------------------------------------------------------------
@pytest.mark.parametrize("text,expected", [
    ("critical", Severity.CRITICAL), ("HIGH", Severity.HIGH),
    ("medium", Severity.MEDIUM), ("low", Severity.LOW), ("info", Severity.INFO),
    ("unknown-token", Severity.MEDIUM),
])
def test_severity_of(text, expected):
    assert severity_of(text) is expected


@pytest.mark.parametrize("vuln_type,expected", [
    ("sqli", Severity.HIGH), ("xss", Severity.MEDIUM), ("rce", Severity.CRITICAL),
    ("ssrf", Severity.HIGH), ("文件上传", Severity.CRITICAL),
])
def test_severity_by_type(vuln_type, expected):
    assert severity_by_type(vuln_type) is expected


# --------------------------------------------------------------------------
# nuclei 引擎 (原生模板解释器)
#
# 旧版这里测的是「nuclei 二进制的 JSONL 报告解析 / 空报告重试 / -duc 参数」,
# 现在已经没有子进程了 —— 相应的行为由 sentinel.scanner.templating 承担,
# 详细用例见 tests/test_templating.py。这里只守住驱动层的契约。
# --------------------------------------------------------------------------
def test_nuclei_engine_is_native():
    """nuclei 引擎不得再依赖任何外部二进制."""
    import sentinel.scanner.engines.nuclei as nuclei_mod

    source = pathlib.Path(nuclei_mod.__file__).read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "digger_pro" not in source
    assert "scanner_root" not in source
    assert NucleiEngine.available() is True     # 只有模板树就够用


def test_nuclei_engine_reports_template_inventory():
    engine = NucleiEngine()
    info = engine.info()
    assert info.available and info.tools["official_templates"] > 1000
    assert engine.template_count() > 1000


def test_nuclei_engine_is_honest_about_missing_templates(tmp_path):
    """没有模板树时必须明说原因, 而不是静默返回空列表."""
    engine = NucleiEngine(roots=[tmp_path / "nope"])
    assert engine.roots == [tmp_path / "nope"]
    assert engine.scan(["http://127.0.0.1:9000/"]) == []
    assert engine.last_error


def test_w13scan_engine_is_native():
    """w13scan 引擎不得再依赖子进程 / 独立 venv / 兄弟项目源码."""
    import pathlib as _pathlib

    import sentinel.scanner.engines.w13scan as w13_mod

    source = _pathlib.Path(w13_mod.__file__).read_text(encoding="utf-8")
    for needle in ("import subprocess", "digger_pro", "scanner_root", ".venv"):
        assert needle not in source, needle
    assert W13ScanEngine.available() is True


def test_w13scan_engine_reports_plugin_inventory():
    from sentinel.scanner.plugins import all_plugins

    engine = W13ScanEngine()
    info = engine.info()
    assert info.available
    assert info.tools["plugins"] == len(all_plugins()) >= 20
    assert "原生" in info.display


# 单元: 去重
# --------------------------------------------------------------------------
def test_dedupe_keeps_highest_confidence():
    rows = [
        Finding(vuln_type="sqli", url="http://x/a?p=1", severity=Severity.HIGH,
                param="p", confidence=0.5, conn_id="w13scan"),
        Finding(vuln_type="sqli", url="http://x/a?p=2", severity=Severity.HIGH,
                param="p", confidence=0.9, conn_id="nuclei"),
        Finding(vuln_type="xss", url="http://x/a?p=1", severity=Severity.MEDIUM,
                param="p", confidence=0.8, conn_id="nuclei"),
    ]
    merged = dedupe(rows)
    assert len(merged) == 2
    sqli = [f for f in merged if f.vuln_type == "sqli"][0]
    assert sqli.confidence == 0.9 and sqli.conn_id == "nuclei"


# --------------------------------------------------------------------------
# 引擎可用性 / 元信息
# --------------------------------------------------------------------------
def test_engine_registry_availability_and_infos():
    manager = ScannerEngineManager()
    flags = manager.available()
    assert set(flags) == {"nuclei", "w13scan", "builtin"}
    assert flags["builtin"] is True
    infos = {info.name: info for info in manager.infos()}
    assert infos["nuclei"].upstream.startswith("projectdiscovery/nuclei")
    assert infos["w13scan"].upstream.startswith("w-digital-scanner/w13scan")
    assert infos["builtin"].available is True


def test_builtin_engine_tags_provenance():
    engine = BuiltinEngine()
    assert engine.available() is True
    assert engine.info().detail


def test_manager_records_unavailable_engine_run(monkeypatch):
    manager = ScannerEngineManager()
    monkeypatch.setattr(manager.engines["nuclei"], "available", lambda: False)
    outcome = manager.scan(["http://127.0.0.1:1/"], engines=["nuclei"])
    assert outcome.findings == []
    assert outcome.runs and outcome.runs[0].ok is False
    assert "不可用" in outcome.runs[0].error


def test_manager_isolates_engine_failure(monkeypatch):
    manager = ScannerEngineManager()

    class Boom:
        name, display, upstream, deep_only = "boom", "Boom", "-", False

        @classmethod
        def available(cls):
            return True

        def scan(self, targets, *, deep=False, timeout_s=1.0):
            raise RuntimeError("引擎崩溃")

        def info(self):
            from sentinel.scanner.engines.base import EngineInfo
            return EngineInfo(name="boom", display="Boom", upstream="-", available=True)

    manager.engines = {"boom": Boom()}
    outcome = manager.scan(["http://127.0.0.1:1/"], engines=["boom"])
    assert outcome.findings == []
    assert outcome.runs[0].ok is False and "崩溃" in outcome.runs[0].error


# --------------------------------------------------------------------------
# 端到端: 真实引擎扫描靶场
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def lab_server():
    server = LabServer("127.0.0.1", 0, "scan-e2e")
    server.start()
    yield server
    server.stop()


@pytest.mark.slow
@pytest.mark.integration
def test_nuclei_engine_e2e(lab_server):
    if not NucleiEngine.available():
        pytest.skip("nuclei 未安装")
    engine = NucleiEngine()
    base = f"http://127.0.0.1:{lab_server.bound_port}"
    findings = engine.scan([base + "/"], deep=False, timeout_s=420)
    assert findings, "nuclei 未发现任何问题"
    types = {f.vuln_type for f in findings}
    assert types & {"sqli-error", "sqli-boolean", "admin-panel", "debug-exposure",
                    "jsonp-exposure", "xss-reflected", "open-redirect", "ssrf-internal"}
    assert all(f.conn_id == "nuclei" for f in findings)


@pytest.mark.slow
@pytest.mark.integration
def test_w13scan_engine_e2e(lab_server):
    if not W13ScanEngine.available():
        pytest.skip("w13scan 未安装依赖")
    engine = W13ScanEngine()
    base = f"http://127.0.0.1:{lab_server.bound_port}"
    findings = engine.scan([f"{base}/product?id=1", f"{base}/search?q=hello"],
                           timeout_s=240)
    assert findings, "w13scan 未发现任何问题"
    assert any(f.vuln_type == "sqli" for f in findings)


@pytest.mark.slow
@pytest.mark.integration
def test_multi_engine_manager_e2e(lab_server):
    manager = ScannerEngineManager()
    base = f"http://127.0.0.1:{lab_server.bound_port}"
    targets = [f"{base}/", f"{base}/search?q=test", f"{base}/product?id=1"]
    outcome = manager.scan(targets, engines=["nuclei", "builtin"], timeout_s=420)
    assert outcome.findings
    assert {run.engine for run in outcome.runs} == {"nuclei", "builtin"}
    sources = {f.conn_id for f in outcome.findings}
    assert "builtin" in sources
