"""QingScan 固定路径漏洞规则适配器。"""
from __future__ import annotations

from urllib.parse import urlsplit

from ...core.models import Finding, Severity
from ..qingscan import QINGSCAN_EXPOSURE_RULES, QINGSCAN_WAF_RULES
from .base import A01, A05, SCOPE_SERVER, Plugin, PluginContext, register, snippet

_SEVERITY = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
_BACKUP_SUFFIXES = (".bak", ".old", ".orig", ".save", ".sql", ".sql.gz",
                    ".zip", ".rar", ".7z", ".tar.gz", ".tgz")


@register
class QingScanExposure(Plugin):
    """补齐 QingScan 固定路径规则中 Sentinel 原生插件尚未覆盖的部分。"""

    name = "qingscan_exposure"
    title = "QingScan 配置与服务暴露探测"
    category = "info"
    severity = Severity.HIGH
    cwe = "CWE-200"
    owasp = A01
    description = "探测配置、备份、路径遍历及 Druid/Nacos 未授权暴露"
    scope = SCOPE_SERVER
    references = ("https://github.com/daxia/QingScan",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        baseline = ctx.raw(ctx.absolute("/"))
        base_body = baseline.body if baseline.status else b""
        cache = {}

        for rule in QINGSCAN_EXPOSURE_RULES:
            if rule.native_plugin:
                continue
            for path in rule.paths:
                result = cache.get(path)
                if result is None:
                    result = ctx.raw(ctx.absolute(path))
                    cache[path] = result
                if result.status != 200 or (base_body and result.body == base_body):
                    continue

                marker = next((word for word in rule.keywords
                               if word.lower() in result.text.lower()), "")
                non_html = bool(result.content_type and
                                "text/html" not in result.content_type.lower())
                if not marker and not (rule.check_content_type and non_html):
                    continue

                evidence = snippet(result.text, marker, 60) if marker else \
                    f"Content-Type: {result.content_type}; {len(result.body)} 字节"
                ctx.add(
                    vuln_type=rule.vuln_type, url=result.url, method="GET", param="",
                    payload=path, evidence=evidence,
                    severity=_SEVERITY[rule.severity], confidence=0.82,
                    proof=f"QingScan 规则“{rule.name}”命中：{rule.description}")

        # QingScan 的目录/爬虫结果继续交给漏洞阶段：发现的备份文件本身也要判定，
        # 不能只尝试在端点名称后再拼一次 .bak。
        reported = {finding.url for finding in ctx.findings}
        for endpoint in ctx.target.endpoints.values():
            path = urlsplit(endpoint.url).path.lower()
            if path in ("/.gitignore", "/icons/readme"):
                result = ctx.raw(endpoint.url)
                marker = next((item for item in (".git", "dockerfile", "apache")
                               if item in result.text.lower()), "")
                if result.status == 200 and result.body and marker and not (
                        base_body and result.body == base_body):
                    ctx.add(
                        vuln_type="metadata_exposure", url=result.url, method="GET",
                        param="", payload=path,
                        evidence=snippet(result.text, marker, 100),
                        severity=Severity.LOW, confidence=0.85,
                        proof="工程忽略规则或服务器默认说明文件可公开读取，泄漏目录与部署结构")
                    reported.add(endpoint.url)
            if path.rstrip("/") == "/metrics":
                result = ctx.raw(endpoint.url)
                lower = result.text.lower()
                if result.status == 200 and "# help " in lower and "# type " in lower:
                    ctx.add(
                        vuln_type="metrics_exposure", url=result.url, method="GET",
                        param="", payload=path,
                        evidence=snippet(result.text, "# HELP", 100),
                        severity=Severity.LOW, confidence=0.9,
                        proof="Prometheus 指标端点未鉴权，可读取应用与进程运行数据")
                    reported.add(endpoint.url)
            if endpoint.url in reported or not path.endswith(_BACKUP_SUFFIXES):
                continue
            result = ctx.raw(endpoint.url)
            if result.status != 200 or not result.body or (base_body and result.body == base_body):
                continue
            marker = next((word for word in ("<?php", "INSERT INTO", "CREATE TABLE",
                                               "DB_HOST", "password")
                           if word.lower() in result.text.lower()), "")
            archive = result.body.startswith((b"PK\x03\x04", b"Rar!", b"\x1f\x8b", b"7z"))
            non_html = bool(result.content_type and
                            "text/html" not in result.content_type.lower())
            if not marker and not archive and not non_html:
                continue
            evidence = snippet(result.text, marker, 60) if marker else \
                f"Content-Type: {result.content_type}; {len(result.body)} 字节"
            ctx.add(
                vuln_type="backup_file", url=result.url, method="GET", param="",
                payload=path, evidence=evidence, severity=Severity.MEDIUM,
                confidence=0.84,
                proof="目录发现结果指向可直接下载的备份文件")
            reported.add(endpoint.url)
        return ctx.findings


@register
class QingScanWafDetect(Plugin):
    """移植 QingScan WafScan：先匹配指纹，未命中时发送一次主动探针。"""

    name = "qingscan_waf_detect"
    title = "QingScan WAF 识别"
    category = "info"
    severity = Severity.INFO
    cwe = "CWE-200"
    owasp = A05
    description = "通过响应头、Cookie、拦截页及差分探针识别上游 WAF"
    scope = SCOPE_SERVER
    references = ("https://github.com/daxia/QingScan",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        url = ctx.target.base_url
        baseline = ctx.raw(url)
        if not baseline.status:
            return []

        headers = {key.lower(): value.lower() for key, value in baseline.headers.items()}
        cookie = baseline.header("Set-Cookie").lower()
        body = baseline.text[:5000].lower()
        for rule in QINGSCAN_WAF_RULES:
            evidence = _match_waf_rule(rule.headers, rule.cookies, rule.body,
                                       headers, cookie, body)
            if evidence:
                return [self._finding(ctx, url, rule.firewall, rule.manufacturer, evidence)]

        separator = "&" if "?" in url else "?"
        payload = "id=1%27%20AND%201%3D1--%20" if separator == "&" else "a=1%27"
        probe = ctx.raw(url + separator + payload)
        if not probe.status:
            return []
        if probe.status in (403, 406, 503) and probe.status != baseline.status:
            return [self._finding(ctx, url, "unknown", "未知WAF",
                                  f"探针状态 {baseline.status} -> {probe.status}")]
        probe_body = probe.text[:5000].lower()
        for keyword in ("forbidden", "blocked", "拦截", "attack", "安全", "验证"):
            if keyword not in body and keyword in probe_body:
                return [self._finding(ctx, url, "unknown", "未知WAF",
                                      f"探针响应新增拦截词 {keyword!r}")]
        return []

    def _finding(self, ctx: PluginContext, url: str, firewall: str,
                 manufacturer: str, evidence: str) -> Finding:
        return ctx.add(
            vuln_type="waf_detected", url=url, method="GET", param="", payload="",
            evidence=evidence, severity=self.severity, confidence=0.8,
            proof=f"识别到 WAF：{firewall}（{manufacturer}）；这是资产信息，不是漏洞")


def _match_waf_rule(header_rules: tuple[str, ...], cookie_rules: tuple[str, ...],
                    body_rules: tuple[str, ...], headers: dict[str, str],
                    cookie: str, body: str) -> str:
    for pattern in header_rules:
        key, separator, value = pattern.lower().partition(":")
        if key in headers and (not separator or value in headers[key]):
            return f"响应头 {pattern}"
    for name in cookie_rules:
        if name.lower() in cookie:
            return f"Cookie {name}"
    for keyword in body_rules:
        if keyword.lower() in body:
            return f"响应体特征 {keyword}"
    return ""


__all__ = ["QingScanExposure", "QingScanWafDetect"]
