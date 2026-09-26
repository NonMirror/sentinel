"""WAF 引擎驱动层测试.

Sentinel 有两类引擎, 测试也分两部分:

* **原生引擎** (modsecurity / naxsi / python) —— 进程内决策, 默认使用;
* **参考引擎** (nginx-modsecurity / nginx-naxsi) —— 真实 nginx C 数据面,
  可选, 其中「审计日志解析」这部分**不需要真的构建 nginx** 就能测。
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from sentinel.core.config import BackendConfig, Config, WafConfig
from sentinel.core.models import Severity
from sentinel.waf.engines import (
    ENGINE_CLASSES,
    EngineManager,
    ModSecurityEngine,
    NaxsiEngine,
    NginxHost,
    NginxInstall,
    PythonEngine,
    available_engines,
    default_engine,
)
from sentinel.waf.engines.base import RuleView
from sentinel.waf.engines.nginx_stack import LogTailer, render_nginx_conf


# --------------------------------------------------------------------------
# 引擎探测 / 选择
# --------------------------------------------------------------------------
def test_engine_registry_and_availability():
    from sentinel.waf.engines import NATIVE_ENGINES, REFERENCE_ENGINES
    assert set(NATIVE_ENGINES) == {"modsecurity", "naxsi", "python"}
    assert set(REFERENCE_ENGINES) == {"nginx-modsecurity", "nginx-naxsi"}
    assert set(ENGINE_CLASSES) == set(NATIVE_ENGINES) | set(REFERENCE_ENGINES)
    flags = available_engines()
    assert flags["python"] is True            # 便携引擎永远可用
    assert default_engine() in NATIVE_ENGINES  # 参考引擎不参与自动选择


def test_default_engine_is_native_even_when_reference_built():
    """参考引擎可用时也不应被自动选中 —— 它只在显式指定时启用."""
    manager = EngineManager(Config(), engine="nginx-modsecurity")
    assert manager.is_reference
    plain = EngineManager(Config())
    assert not plain.is_reference


def test_python_engine_always_available():
    assert PythonEngine.available() is True
    engine = PythonEngine(Config())
    status = engine.status()
    assert status.name == "python"
    assert status.rules > 0
    assert status.extra["real_engine"] is False


def test_manager_auto_selection_prefers_real_engine():
    manager = EngineManager(Config(), engine="modsecurity")
    assert manager.active_name == "modsecurity"
    snapshot = manager.snapshot()
    assert snapshot["active"] in ENGINE_CLASSES
    assert snapshot["available"]["python"] is True
    names = [item["name"] for item in snapshot["engines"]]
    assert names[:3] == ["modsecurity", "naxsi", "python"]


def test_manager_falls_back_to_python_when_unknown_engine():
    manager = EngineManager(Config(), engine="does-not-exist")
    assert manager.active_name == "python"
    manager.start()
    assert manager.current.name == "python"
    manager.stop()


def test_manager_start_python_engine_records_lifecycle():
    from sentinel.core.events import EventBus

    bus = EventBus()
    manager = EngineManager(Config(), bus=bus, engine="python")
    manager.start()
    try:
        events = [e.payload for e in bus.history("lifecycle")]
        assert any(e.get("event") == "engine_selected" for e in events)
    finally:
        manager.stop()


# --------------------------------------------------------------------------
# ModSecurity 事件解析
# --------------------------------------------------------------------------
DENY_LINE = (
    '2026/09/25 10:22:33 [error] 703170#703170: *4 [client 203.0.113.9] '
    'ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge\' with '
    'parameter `5\' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE\' (Value: `18\' ) '
    '[file "/home/u/waf_pro/coreruleset/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] '
    '[line "222"] [id "949110"] [rev ""] '
    '[msg "Inbound Anomaly Score Exceeded (Total Score: 18)"] [data ""] '
    '[severity "0"] [ver "OWASP_CRS/4.30.0-dev"] [maturity "0"] [accuracy "0"] '
    '[tag "anomaly-evaluation"] [tag "OWASP_CRS"] [hostname "127.0.0.1"] '
    '[uri "/?id=1 union select"] [unique_id "abc"]'
)
RULE_LINE = (
    '2026/09/25 10:22:33 [info] 703170#703170: *2 [client 198.51.100.7] '
    'ModSecurity: Warning. Matched "Operator `Rx\' with parameter `select\' '
    '[file "/home/u/waf_pro/coreruleset/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] '
    '[line "33"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] '
    '[data "Matched Data: union select found"] [severity "CRITICAL"] '
    '[tag "application-multi"] [tag "attack-sqli"] [uri "/product?id=1"] '
)


def test_modsecurity_parse_deny_line():
    from sentinel.waf.engines.nginx_dataplane import NginxModSecurityEngine
    engine = NginxModSecurityEngine(Config())
    alert = engine.parse_event(DENY_LINE)
    assert alert is not None
    assert alert.rule_id == 949110
    assert alert.client == "203.0.113.9"
    assert alert.severity is Severity.CRITICAL          # 数字级别 0 = EMERGENCY
    assert "anomaly_score=18" in alert.evidence
    assert "anomaly-evaluation" in alert.tags


def test_modsecurity_parse_rule_line_with_numeric_and_text_severity():
    from sentinel.waf.engines.nginx_dataplane import NginxModSecurityEngine
    engine = NginxModSecurityEngine(Config())
    alert = engine.parse_event(RULE_LINE)
    assert alert is not None
    assert alert.rule_id == 942100
    assert alert.severity is Severity.CRITICAL           # "CRITICAL" 文本级别
    assert alert.category == "crs"
    assert "attack-sqli" in alert.tags
    assert "union select" in alert.evidence


def test_modsecurity_ignores_unrelated_log_lines():
    from sentinel.waf.engines.nginx_dataplane import NginxModSecurityEngine
    engine = NginxModSecurityEngine(Config())
    assert engine.parse_event("2026/09/25 [notice] nginx started") is None
    assert engine.parse_event("ModSecurity: Warning. no rule id here") is None


# --------------------------------------------------------------------------
# Naxsi 事件解析
# --------------------------------------------------------------------------
NAXSI_LINE = (
    "2026/09/25 10:22:33 [error] 703170#703170: *7 [client 192.0.2.55] "
    "NAXSI_FMT: ip=192.0.2.55&server=127.0.0.1&uri=/?id=1%20union%20select"
    "&learning=0&vers=1.3&total_pts=8&zone0=ARGS&id0=1000&var_name0=id, "
    "client: 192.0.2.55, server: 127.0.0.1"
)


def test_naxsi_parse_event():
    from sentinel.waf.engines.nginx_dataplane import NginxNaxsiEngine
    engine = NginxNaxsiEngine(Config())
    alert = engine.parse_event(NAXSI_LINE)
    assert alert is not None
    assert alert.rule_id == 1000
    assert alert.client == "192.0.2.55"
    assert alert.severity is Severity.HIGH
    assert "total_pts=8" in alert.evidence
    assert "zone:ARGS" in alert.tags


def test_naxsi_ignores_other_lines():
    from sentinel.waf.engines.nginx_dataplane import NginxNaxsiEngine
    engine = NginxNaxsiEngine(Config())
    assert engine.parse_event("[error] unknown directive") is None


def test_naxsi_thresholds_tighten_with_paranoia_level():
    thresholds = {}
    for level in (1, 2, 3, 4):
        config = Config()
        config.waf.paranoia_level = level
        engine = NaxsiEngine(config)
        thresholds[level] = engine.rules_summary()["thresholds"]
    assert thresholds[1]["SQL"] == 8
    assert thresholds[4]["SQL"] == 5
    assert thresholds[4]["TRAVERSAL"] == 1
    # 单调收紧
    assert thresholds[1]["SQL"] >= thresholds[2]["SQL"] >= thresholds[4]["SQL"]


# --------------------------------------------------------------------------
# 规则清单
# --------------------------------------------------------------------------
def test_rule_view_dict_and_weight():
    view = RuleView(id=942100, description="SQLi", severity=Severity.CRITICAL,
                    category="sqli", tags=["attack-sqli"])
    data = view.to_dict()
    assert data["id"] == 942100 and data["severity"] == "critical"
    assert view.weight == Severity.CRITICAL.weight


def test_python_engine_rule_index_matches_ruleset():
    engine = PythonEngine(Config())
    index = engine.rule_index()
    assert index and all(isinstance(item, RuleView) for item in index)
    assert all(item.source == "builtin+rules/" for item in index)


@pytest.mark.skipif(not ModSecurityEngine.available(), reason="需要 vendor 中的 CRS 规则")
def test_modsecurity_rule_index_from_crs():
    engine = ModSecurityEngine(Config())
    index = engine.rule_index()
    assert len(index) > 100
    sqli = [rule for rule in index if rule.id == 942100]
    # 算子名以**小写规范名**存放 (operators.py 的分派键), 展示时用
    # OPERATOR_DISPLAY 还原成 @detectSQLi
    assert sqli and sqli[0].operator == "detectsqli"
    assert sqli[0].severity is Severity.CRITICAL
    assert "ARGS" in sqli[0].variables


@pytest.mark.skipif(not NaxsiEngine.available(), reason="需要 vendor 中的 Naxsi 规则")
def test_naxsi_rule_index():
    engine = NaxsiEngine(Config())
    index = engine.rule_index()
    assert len(index) >= 40
    assert {rule.category for rule in index} >= {"sql", "xss", "traversal"}


# --------------------------------------------------------------------------
# nginx 配置生成
# --------------------------------------------------------------------------
def _fake_host(tmp_path: Path, name: str = "test") -> NginxHost:
    install = NginxInstall(prefix=Path("/opt/nginx"), sbin=Path("/opt/nginx/sbin/nginx"),
                           version="1.22.1", modules=("modsecurity", "naxsi"))
    return NginxHost(name=name, install=install, base=tmp_path / name,
                     host="127.0.0.1", front_port=18080, status_port=18081)


def test_render_nginx_conf_core_directives(tmp_path):
    host = _fake_host(tmp_path)
    backends = [BackendConfig("a", "127.0.0.1", 9001, weight=2),
                BackendConfig("b", "127.0.0.1", 9002)]
    conf = render_nginx_conf(host=host, backends=backends,
                             waf=WafConfig(strategy="least_conn"))
    assert "worker_processes 1;" in conf
    assert "least_conn;" in conf
    assert "server 127.0.0.1:9001 weight=2" in conf
    assert f"listen 127.0.0.1:18080;" in conf
    assert "stub_status" in conf
    assert "log_format sentinel" in conf
    assert "$upstream_addr" in conf
    assert conf.count("{") == conf.count("}")


def test_render_nginx_conf_rate_limit_and_ip_rules(tmp_path):
    host = _fake_host(tmp_path)
    waf = WafConfig(rate_limit_rps=25, rate_limit_burst=50,
                    block_ips=["203.0.113.9"], allow_ips=["10.0.0.0/8"])
    conf = render_nginx_conf(host=host, backends=[BackendConfig()], waf=waf)
    assert "limit_req_zone $binary_remote_addr zone=sentinel_rl:10m rate=25r/s;" in conf
    assert "limit_req_status 429;" in conf
    assert "deny 203.0.113.9;" in conf
    assert "allow 10.0.0.0/8;" in conf


def test_render_nginx_conf_engine_directives_and_extra_location(tmp_path):
    host = _fake_host(tmp_path, "modsec")
    conf = render_nginx_conf(
        host=host, backends=[BackendConfig()], waf=WafConfig(),
        http_directives=["modsecurity on;", "modsecurity_rules_file /x.conf;"],
        location_directives=[],
        location_off_directives=["modsecurity off;"],
        extra_locations=['location /__denied { internal; return 403 "no\\n"; }'])
    assert "modsecurity on;" in conf
    assert "modsecurity off;" in conf          # 静态资源豁免
    assert "location /__denied" in conf


# --------------------------------------------------------------------------
# 日志增量回采
# --------------------------------------------------------------------------
def test_log_tailer_reads_appended_lines(tmp_path):
    log = tmp_path / "error.log"
    log.write_text("old line\n", encoding="utf-8")
    collected: list[str] = []
    tailer = LogTailer(log, collected.append, poll=0.02)
    tailer.start()
    try:
        with log.open("a", encoding="utf-8") as fh:
            fh.write("new line 1\nnew line 2\n")
        for _ in range(100):
            if len(collected) >= 2:
                break
            import time
            time.sleep(0.02)
    finally:
        tailer.stop()
    assert collected == ["new line 1", "new line 2"]


def test_log_tailer_handles_rotation(tmp_path):
    """模拟 nginx 日志轮转: 旧文件重命名后新建同名文件 (inode 变化)."""
    import time

    log = tmp_path / "access.log"
    log.write_text("a\nb\n", encoding="utf-8")
    collected: list[str] = []
    tailer = LogTailer(log, collected.append, poll=0.02)
    tailer.start()
    try:
        time.sleep(0.1)
        log.replace(tmp_path / "access.log.1")      # 轮转
        log.write_text("fresh\n", encoding="utf-8")  # 新文件
        for _ in range(150):
            if collected:
                break
            time.sleep(0.02)
    finally:
        tailer.stop()
    assert "fresh" in collected


def test_log_tailer_does_not_skip_lines_written_before_thread_starts(tmp_path):
    """构造与 run() 之间的写入不得丢失 (曾经的真实缺陷)."""
    import time

    log = tmp_path / "error.log"
    log.write_text("", encoding="utf-8")
    collected: list[str] = []
    tailer = LogTailer(log, collected.append, poll=0.02)
    with log.open("a", encoding="utf-8") as fh:      # start() 之前写入
        fh.write("early\n")
    tailer.start()
    try:
        for _ in range(100):
            if collected:
                break
            time.sleep(0.02)
    finally:
        tailer.stop()
    assert collected == ["early"]


# ---------------------------------------------------------------------------
# 运行目录回收 (被强杀的引擎进程不该把 reports/engine-run 越堆越大)
# ---------------------------------------------------------------------------
def test_pid_alive_detects_exited_process():
    from sentinel.waf.engines import base as engine_base

    assert engine_base._pid_alive(os.getpid()) is True
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    pid = proc.pid
    proc.wait()
    assert engine_base._pid_alive(pid) is False


def test_prune_run_dirs_reclaims_dead_process_leftovers(tmp_path, monkeypatch):
    from sentinel.waf.engines import base as engine_base

    live = tmp_path / f"modsecurity-{os.getpid()}-deadbeef"   # 本进程, 保留
    dead = tmp_path / "naxsi-424242-cafebabe"                 # 已退出, 回收
    fixed = tmp_path / "nuclei"                               # 扫描器固定目录, 保留
    loose = tmp_path / "random-dir"                           # 非引擎目录, 保留
    for path in (live, dead, fixed, loose):
        path.mkdir()
    (dead / "nginx.conf").write_text("worker_processes 1;", encoding="utf-8")

    monkeypatch.setattr(engine_base, "_pid_alive", lambda pid: pid != 424242)
    removed = engine_base.prune_run_dirs(tmp_path)

    assert removed == [dead]
    assert not dead.exists()
    assert live.is_dir() and fixed.is_dir() and loose.is_dir()


def test_prune_run_dirs_is_noop_for_missing_root(tmp_path):
    from sentinel.waf.engines import base as engine_base

    assert engine_base.prune_run_dirs(tmp_path / "nope") == []
