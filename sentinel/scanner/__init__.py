"""综设I 漏洞扫描子系统.

目标识别模块 -> 漏洞检测模块 -> 漏洞库与规则引擎 -> 报告生成模块.

三条检测路径都是 Sentinel 自己的实现:

* :mod:`sentinel.scanner.templating` —— nuclei 模板解释器 (执行官方 YAML 模板);
* :mod:`sentinel.scanner.plugins` —— 插件式主动扫描 (设计参考 w13scan 的插件集);
* :mod:`sentinel.scanner.detectors` —— 内置轻量检测器 (靶场全类别覆盖).

内置检测器覆盖 10 类: sqli_error / sqli_time / xss / ssrf / cors / jsonp /
file_read / url_redirect / unauth / html_res_information_disclosure.
"""
from .client import HttpClient, HttpResult
from .crawler import TargetRecognizer, Target, Endpoint
from .vulndb import VulnDB, DetectorSpec, default_db
from .detectors import DETECTORS, DetectorContext, run_detectors
from .scanner import Scanner, ScanReport, ScanStats
from .report import render_markdown, render_html, render_json, write_report

__all__ = [
    "HttpClient", "HttpResult", "TargetRecognizer", "Target", "Endpoint",
    "VulnDB", "DetectorSpec", "default_db", "DETECTORS", "DetectorContext",
    "run_detectors", "Scanner", "ScanReport", "ScanStats",
    "render_markdown", "render_html", "render_json", "write_report",
]
