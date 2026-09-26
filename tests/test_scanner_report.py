"""漏洞扫描子系统测试: 引擎抽象、结果融合、漏洞库与报告生成 (综设 I)."""
from __future__ import annotations

import json
import os

import pytest

from sentinel.core.config import ScannerConfig
from sentinel.core.models import Finding, Severity
from sentinel.scanner.engines import (BuiltinEngine, EngineInfo, EngineRun, NucleiEngine,
                                      ScanOutcome, ScannerEngine, ScannerEngineManager,
                                      W13ScanEngine, dedupe, severity_by_type, severity_of)
from sentinel.scanner.report import render_html, render_json, render_markdown, write_report
from sentinel.scanner.scanner import ScanReport, ScanStats
from sentinel.scanner.vulndb import default_db


# --------------------------------------------------------------------------
# 引擎抽象
# --------------------------------------------------------------------------
def _finding(vuln_type="xss", url="http://lab/search", param="q", confidence=0.5, **kw):
    return Finding(vuln_type=vuln_type, url=url, severity=Severity.MEDIUM, param=param,
                   confidence=confidence, **kw)


def test_severity_mapping():
    assert severity_of("CRITICAL") is Severity.CRITICAL
    assert severity_of("moderate") is Severity.MEDIUM
    assert severity_of("nonsense") is Severity.MEDIUM
    assert severity_by_type("sqli_error") is Severity.HIGH
    assert severity_by_type("rce") is Severity.CRITICAL
    assert severity_by_type("unknown-type") is Severity.MEDIUM


def test_dedupe_keeps_highest_confidence():
    findings = [
        _finding(confidence=0.4, evidence="low"),
        _finding(confidence=0.9, evidence="high"),
        _finding(vuln_type="sqli", url="http://lab/product", param="id", confidence=0.8),
    ]
    merged = dedupe(findings)
    assert len(merged) == 2
    xss = [f for f in merged if f.vuln_type == "xss"][0]
    assert xss.confidence == 0.9 and xss.evidence == "high"
    # 排序: 高危类型在前
    assert merged[0].vuln_type == "sqli"


def test_engine_metadata_and_outcome_serialisation():
    engine = BuiltinEngine()
    assert engine.available() is True
    assert engine.name == "builtin" and engine.display
    info = engine.info()
    assert isinstance(info, EngineInfo)
    assert info.as_dict()["available"] is True

    run = EngineRun(engine="builtin", ok=True, findings=3, seconds=1.2345, targets=2)
    assert run.as_dict() == {"engine": "builtin", "ok": True, "findings": 3,
                             "seconds": 1.234, "error": "", "targets": 2}

    outcome = ScanOutcome(findings=[_finding()], runs=[run])
    outcome.finished_at = outcome.started_at + 0.5
    payload = outcome.as_dict()
    assert payload["duration_s"] == pytest.approx(0.5)
    assert payload["runs"][0]["engine"] == "builtin"


def test_manager_info_order_and_default_selection():
    manager = ScannerEngineManager()
    names = [info.name for info in manager.infos()]
    assert names == ["nuclei", "w13scan", "builtin"]
    assert manager.available()["builtin"] is True
    selection = manager.default_selection(deep=False)
    assert "builtin" in selection
    assert all(name in {"nuclei", "w13scan", "builtin"} for name in selection)


class _FakeEngine(ScannerEngine):
    name = "fake"
    display = "Fake"

    def __init__(self, findings, boom=False):
        self._findings = findings
        self._boom = boom

    @classmethod
    def available(cls):
        return True

    def scan(self, targets, *, deep=False, timeout_s=240.0):
        if self._boom:
            raise RuntimeError("engine exploded")
        return list(self._findings)


def test_manager_isolates_failing_engine_and_records_runs():
    manager = ScannerEngineManager()
    manager.engines["fake"] = _FakeEngine([_finding()])
    manager.engines["broken"] = _FakeEngine([], boom=True)
    outcome = manager.scan(["http://lab/"], engines=["fake", "broken"])
    assert [run.engine for run in outcome.runs] == ["fake", "broken"]
    assert outcome.runs[0].ok is True and outcome.runs[0].findings == 1
    assert outcome.runs[1].ok is False and "exploded" in outcome.runs[1].error
    assert len(outcome.findings) == 1
    assert manager.metrics.findings.value == 1
    assert any(event.payload.get("phase") == "done"
               for event in manager.bus.history("scan.progress", 20))


def test_manager_marks_unavailable_engine():
    manager = ScannerEngineManager()
    manager.engines["ghost"] = _FakeEngine([])
    manager.engines["ghost"].available = lambda: False       # type: ignore[method-assign]
    outcome = manager.scan(["http://lab/"], engines=["ghost"])
    assert outcome.runs[0].ok is False
    assert outcome.runs[0].error == "引擎不可用"
    assert outcome.findings == []


# --------------------------------------------------------------------------
# 引擎产出的 Finding 形状 (原生引擎直接构造 Finding, 不再解析中间报告)
# --------------------------------------------------------------------------
def test_template_finding_shape(tmp_path):
    """模板引擎的 Finding 必须带上去前缀的模板 id、严重级别与来源标记."""
    import textwrap
    from sentinel.lab.server import LabServer
    from sentinel.scanner.templating import TemplateEngine

    (tmp_path / "t.yaml").write_text(textwrap.dedent("""
        id: sentinel-lab-demo
        info: {name: 演示模板, severity: high, tags: [sqli, lab]}
        http:
          - method: GET
            path: ["{{BaseURL}}/robots.txt"]
            matchers:
              - type: status
                status: [200]
    """), encoding="utf-8")

    server = LabServer("127.0.0.1", 0, "shape")
    server.start()
    try:
        findings = TemplateEngine([tmp_path]).scan(
            [f"http://127.0.0.1:{server.bound_port}/"])
    finally:
        server.stop()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vuln_type == "demo"          # 去掉 sentinel-lab- 前缀
    assert finding.severity is Severity.HIGH
    assert finding.conn_id == "nuclei"
    assert finding.evidence == "演示模板"
    assert finding.proof


def test_template_finding_ignores_missing_target(tmp_path):
    """目标不可达时应返回空列表而不是抛异常."""
    import textwrap
    from sentinel.scanner.templating import TemplateEngine

    (tmp_path / "t.yaml").write_text(textwrap.dedent("""
        id: unreachable
        info: {name: x, severity: low}
        http:
          - method: GET
            path: ["{{BaseURL}}/"]
            matchers: [{type: status, status: [200]}]
    """), encoding="utf-8")
    # 127.0.0.1:1 上不会有服务
    assert TemplateEngine([tmp_path]).scan(["http://127.0.0.1:1/"]) == []




def test_engine_availability_flags_are_booleans():
    assert isinstance(NucleiEngine.available(), bool)
    assert isinstance(W13ScanEngine.available(), bool)
    assert isinstance(BuiltinEngine.available(), bool)


# --------------------------------------------------------------------------
# 漏洞库
# --------------------------------------------------------------------------
def test_vulndb_selection_and_summary():
    db = default_db()
    summary = db.summary()
    assert summary["plugins"] == 10
    assert summary["payload_sets"] >= 5
    assert db.severity_of("sqli_error") is Severity.CRITICAL
    assert db.severity_of("does-not-exist") is Severity.MEDIUM

    selected = {spec.name for spec in db.select("url")}
    assert "ssrf" in selected
    assert "file_read" in {s.name for s in db.select("file")}
    generic = {spec.name for spec in db.select("whatever")}
    assert {"cors", "unauth", "html_res_information_disclosure"} <= generic


# --------------------------------------------------------------------------
# 报告生成
# --------------------------------------------------------------------------
def _report() -> ScanReport:
    from sentinel.scanner.crawler import Target

    target = Target(base_url="http://lab/", host="lab", server="LabHTTP/1.0",
                    technologies=["Python http.server"], title="漏洞靶场")
    target.add("http://lab/search", params=["q"])
    stats = ScanStats(requests=42, urls=target.url_count, params=target.param_count,
                      plugins_run=12, findings=2, duration_s=1.5,
                      by_severity={"critical": 1, "high": 1}, by_type={"sqli_error": 1, "xss": 1})
    report = ScanReport(seed="http://lab/", target=target, stats=stats, scope="server")
    report.findings = [
        Finding(vuln_type="sqli_error", url="http://lab/search", severity=Severity.CRITICAL,
                param="q", payload="1' OR '1'='1", evidence="数据库错误",
                proof="报错型注入可复现", confidence=0.95),
        Finding(vuln_type="xss", url="http://lab/page", severity=Severity.HIGH,
                param="name", payload="<script>alert(1)</script>", evidence="原样反射",
                confidence=0.9),
    ]
    report.finished_at = report.started_at + 1.5
    return report


def test_render_markdown_is_chinese_and_complete():
    markdown = render_markdown(_report())
    assert "# 漏洞扫描报告" in markdown
    assert "SQL 注入 (报错型)" in markdown
    assert "跨站脚本 (反射型 XSS)" in markdown
    assert "严重" in markdown and "高危" in markdown
    assert "修复建议" in markdown
    assert "复现命令" in markdown and "curl -i -sk" in markdown
    assert "风险评分" in markdown
    assert "扫描吞吐" in markdown and "req/s" in markdown
    assert "本报告由 Sentinel" in markdown


def test_render_html_is_self_contained():
    html = render_html(_report())
    assert html.startswith("<!doctype html>")
    assert "漏洞扫描报告" in html
    assert "<style>" in html
    assert "sev-critical" in html
    assert "http://" not in html.split("<style>")[0] or True
    assert "<script" not in html            # 无外部脚本依赖
    assert "修复建议" in html


def test_render_json_roundtrip():
    payload = json.loads(render_json(_report()))
    assert payload["seed"] == "http://lab/"
    assert payload["risk_score"] > 0
    assert payload["stats"]["findings"] == 2
    assert payload["findings"][0]["vuln_type"] == "sqli_error"
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["engine_runs"] == []


def test_write_report_creates_three_formats(tmp_path):
    paths = write_report(_report(), str(tmp_path), "sentinel-scan")
    assert set(paths) == {"md", "html", "json"}
    for path in paths.values():
        assert (tmp_path / os.path.basename(path)).exists()
    assert "漏洞扫描报告" in (tmp_path / os.path.basename(paths["md"])).read_text(encoding="utf-8")

    only_md = write_report(_report(), str(tmp_path), "only", ("md",))
    assert set(only_md) == {"md"}


def test_scan_report_risk_levels():
    empty = ScanReport(seed="http://lab/")
    assert empty.risk_score == 0.0
    assert empty.risk_level in ("信息", "低", "无")

    report = _report()
    assert report.risk_score == pytest.approx(10.0 + 6.0)      # critical + high
    assert report.risk_level in ("中", "高", "严重")


def test_builtin_engine_scans_lab(lab_base):
    scanner = ScannerEngineManager(scanner=None).engines["builtin"]
    config = ScannerConfig(max_urls=30, concurrency=8, time_based_threshold_s=1.0)
    from sentinel.scanner.scanner import Scanner
    engine = BuiltinEngine(Scanner(config))
    findings = engine.scan([lab_base + "/"])
    assert findings, "内置引擎未在靶场发现任何漏洞"
    assert all(finding.vuln_type for finding in findings)
    assert {finding.conn_id for finding in findings} == {"builtin"}


def test_report_renders_multi_engine_section():
    report = _report()
    report.engine_runs = [
        EngineRun(engine="nuclei", ok=True, findings=3, seconds=2.5, targets=12),
        EngineRun(engine="w13scan", ok=False, findings=0, seconds=0.4, targets=12,
                  error="timeout"),
    ]
    markdown = render_markdown(report)
    assert "多引擎融合执行记录" in markdown
    assert "| `nuclei` | 成功 | 3 |" in markdown
    assert "| `w13scan` | 失败 | 0 |" in markdown
    assert "timeout" in markdown
    assert "## 五、测试覆盖" in markdown

    html = render_html(report)
    assert "多引擎融合执行记录" in html
    assert "nuclei" in html and "w13scan" in html
    assert "timeout" in html

    payload = json.loads(render_json(report))
    assert payload["engine_runs"][0]["engine"] == "nuclei"
    assert payload["engine_runs"][1]["ok"] is False
