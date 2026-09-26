"""未授权访问 / 管理面板与接口文档探测插件族.

对应 w13scan 的 ``unauth.py`` (PerFile) 与 ``VulType.DIRSCAN``, 并补齐 Spring Boot
Actuator、Swagger/OpenAPI、phpMyAdmin 这三类在真实资产里出现频率极高的"默认开放面板"。
它们共享同一套探测模型: 一组固定路径 + 一组稳定的响应指纹, 命中即报。

``robots`` 是这一族里唯一的"信息收集"插件: ``robots.txt`` / ``sitemap.xml`` 本身不
是漏洞, 但会直接把后台、调试、备份路径列给攻击者, 因此按 INFO 级别登记, 供报告提示。
"""
from __future__ import annotations

import re

from ...core.models import Finding, Severity
from ..vulndb import UNAUTH_PATHS
from .base import A01, A05, SCOPE_SERVER, Plugin, PluginContext, register, snippet

#: 未授权访问路径 (vulndb 的通用集合 + 常见业务/运维接口)
UNAUTH_PROBE_PATHS: tuple[str, ...] = tuple(UNAUTH_PATHS) + (
    "/admin/", "/admin/index.php", "/admin/login", "/manage", "/management",
    "/api/v1/users", "/api/v2/users", "/api/user/list", "/api/config",
    "/api/health", "/swagger-ui.html", "/actuator", "/actuator/env",
    "/server-status", "/server-info", "/status", "/metrics", "/debug/pprof/",
    "/nginx_status", "/.env", "/config.json", "/api/orders", "/api/accounts",
)

#: 未授权访问的"业务数据"特征 —— 命中才说明真的拿到了东西, 而不是碰巧 200
UNAUTH_MARKERS: tuple[str, ...] = (
    "admin-panel", "管理后台", '"role": "admin"', '"role":"admin"',
    '"orders"', '"accounts"', '"users"', "actuator", "manager/html",
    "server-status", "nginx_status", "DB_PASSWORD", "FLAG{",
    "jdbc:", "spring.datasource", "AKIA",
)


@register
class Unauth(Plugin):
    """未授权访问 (w13scan ``unauth``)."""

    name = "unauth"
    title = "未授权访问"
    category = "auth"
    severity = Severity.HIGH
    cwe = "CWE-306"
    owasp = A01
    description = "无凭据访问敏感接口, 依据响应中的业务数据特征判定未授权访问"
    scope = SCOPE_SERVER
    references = ("https://owasp.org/Top10/A01_2021-Broken_Access_Control/",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        base = ctx.base_url.rstrip("/")
        findings: list[Finding] = []
        for path in UNAUTH_PROBE_PATHS:
            result = ctx.raw(base + path)
            if result.status != 200 or not result.body:
                continue
            marker = next((m for m in UNAUTH_MARKERS if m in result.text), "")
            if not marker:
                continue
            findings.append(ctx.add(
                vuln_type="unauth", url=base + path, method="GET", param="",
                payload="", evidence=snippet(result.text, marker, 60),
                severity=self.severity, confidence=0.8,
                proof=f"未携带任何凭据访问 {path} 返回业务数据 (命中 {marker!r})"))
        return findings


#: Spring Boot Actuator 端点 -> 指纹
ACTUATOR_PATHS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("/actuator", ('"_links"', '"self"', "actuator")),
    ("/actuator/env", ('"propertySources"', '"activeProfiles"')),
    ("/actuator/health", ('"status":"UP"', '"status": "UP"')),
    ("/actuator/beans", ('"beans"', '"type"')),
    ("/actuator/mappings", ('"mappings"', '"dispatcherServlets"')),
    ("/actuator/heapdump", ("JAVA PROFILE",)),
    ("/actuator/httptrace", ('"traces"',)),
    ("/actuator/configprops", ('"contexts"', '"beans"')),
    ("/env", ('"propertySources"',)),
    ("/jolokia/list", ('"value"', "jolokia")),
    ("/actuator/gateway/routes", ('"route_id"',)),
)


@register
class SpringActuator(Plugin):
    """Spring Boot Actuator 未授权 (常见的配置/凭据泄漏面)."""

    name = "spring_actuator"
    title = "Spring Boot Actuator 暴露"
    category = "info"
    severity = Severity.HIGH
    cwe = "CWE-497"
    owasp = A05
    description = "探测 Actuator 端点, 依据 Spring 特征 JSON 判定是否未授权暴露"
    scope = SCOPE_SERVER
    references = (
        "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        base = ctx.base_url.rstrip("/")
        for path, markers in ACTUATOR_PATHS:
            result = ctx.raw(base + path)
            if result.status != 200 or not result.body:
                continue
            marker = next((m for m in markers if m in result.text), "")
            if not marker:
                continue
            severity = Severity.CRITICAL if path.endswith(("env", "heapdump",
                                                           "configprops")) \
                else self.severity
            return [ctx.add(
                vuln_type="spring_actuator", url=base + path, method="GET",
                param="", payload=path, evidence=snippet(result.text, marker, 60),
                severity=severity, confidence=0.85,
                proof=f"Actuator {path} 未授权可访问 (命中 {marker!r}); "
                      f"env/heapdump 类端点通常直接泄漏数据源凭据")]
        return []


#: Swagger / OpenAPI 文档路径 -> 指纹
SWAGGER_PATHS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("/swagger-ui.html", ("swagger-ui", "Swagger UI")),
    ("/swagger-ui/index.html", ("swagger-ui",)),
    ("/swagger/index.html", ("swagger",)),
    ("/doc.html", ("knife4j", "swagger")),
    ("/v2/api-docs", ('"swagger":', '"paths":')),
    ("/v3/api-docs", ('"openapi":', '"paths":')),
    ("/v3/api-docs/swagger-config", ('"configUrl"',)),
    ("/openapi.json", ('"openapi":',)),
    ("/api-docs", ('"swagger":', '"apis"')),
    ("/swagger-resources", ('"swaggerVersion"', '"location"')),
)


@register
class SwaggerUi(Plugin):
    """Swagger / OpenAPI 文档暴露."""

    name = "swagger_ui"
    title = "Swagger/OpenAPI 文档暴露"
    category = "info"
    severity = Severity.MEDIUM
    cwe = "CWE-200"
    owasp = A05
    description = "探测 Swagger/OpenAPI 文档端点, 依据 API 描述文件特征判定"
    scope = SCOPE_SERVER

    def run(self, ctx: PluginContext) -> list[Finding]:
        base = ctx.base_url.rstrip("/")
        for path, markers in SWAGGER_PATHS:
            result = ctx.raw(base + path)
            if result.status != 200 or not result.body:
                continue
            lowered = result.text.lower()
            marker = next((m for m in markers if m.lower() in lowered), "")
            if not marker:
                continue
            paths = len(re.findall(r'"(?:get|post|put|delete|patch)"\s*:', lowered))
            return [ctx.add(
                vuln_type="swagger_ui", url=base + path, method="GET", param="",
                payload=path, evidence=snippet(result.text, marker, 60),
                severity=self.severity, confidence=0.85,
                proof=f"API 文档 {path} 公开可访问"
                      + (f", 描述文件暴露 {paths} 个接口" if paths else "")
                      + ", 泄漏全部接口与参数结构")]
        return []


#: phpMyAdmin / 数据库管理面板路径 -> 指纹
PMA_PATHS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("/phpmyadmin/", ("phpMyAdmin", "pma_", "phpmyadmin")),
    ("/phpMyAdmin/", ("phpMyAdmin", "pma_")),
    ("/pma/", ("phpMyAdmin", "pma_")),
    ("/mysql/", ("phpMyAdmin", "pma_")),
    ("/dbadmin/", ("phpMyAdmin",)),
    ("/adminer.php", ("adminer", "Adminer")),
    ("/adminer/", ("adminer",)),
    ("/phpmyadmin/index.php", ("phpMyAdmin", "pma_")),
    ("/phpMyAdmin/index.php", ("phpMyAdmin",)),
)


@register
class PhpMyAdmin(Plugin):
    """phpMyAdmin / Adminer 数据库管理面板暴露."""

    name = "phpmyadmin"
    title = "数据库管理面板暴露"
    category = "info"
    severity = Severity.MEDIUM
    cwe = "CWE-200"
    owasp = A05
    description = "探测 phpMyAdmin / Adminer 入口, 依据面板特征字符串判定"
    scope = SCOPE_SERVER

    def run(self, ctx: PluginContext) -> list[Finding]:
        base = ctx.base_url.rstrip("/")
        for path, markers in PMA_PATHS:
            result = ctx.raw(base + path)
            if result.status != 200 or not result.body:
                continue
            marker = next((m for m in markers if m in result.text), "")
            if not marker:
                continue
            return [ctx.add(
                vuln_type="phpmyadmin", url=base + path, method="GET", param="",
                payload=path, evidence=snippet(result.text, marker, 60),
                severity=self.severity, confidence=0.8,
                proof=f"数据库管理面板 {path} 暴露在公网, 可对数据库凭据做爆破")]
        return []


#: robots.txt / sitemap.xml
ROBOTS_PATHS: tuple[tuple[str, str], ...] = (
    ("/robots.txt", "robots.txt"),
    ("/sitemap.xml", "sitemap.xml"),
)
_DISALLOW_RE = re.compile(r"^\s*(Disallow|Allow|Sitemap)\s*:\s*(\S+)", re.I | re.M)


@register
class Robots(Plugin):
    """robots.txt / sitemap.xml 路径泄漏."""

    name = "robots"
    title = "robots.txt / sitemap 路径泄漏"
    category = "info"
    severity = Severity.INFO
    cwe = "CWE-200"
    owasp = A05
    description = "读取 robots.txt 与 sitemap.xml, 汇总其中暴露的敏感路径"
    scope = SCOPE_SERVER

    def run(self, ctx: PluginContext) -> list[Finding]:
        base = ctx.base_url.rstrip("/")
        findings: list[Finding] = []
        for path, label in ROBOTS_PATHS:
            result = ctx.raw(base + path)
            if result.status != 200 or not result.body:
                continue
            if label == "robots.txt":
                entries = _DISALLOW_RE.findall(result.text)
                if not entries:
                    continue
                rules = [f"{kind}: {value}" for kind, value in entries]
                sensitive = [value for _kind, value in entries
                             if _looks_sensitive(value)]
                findings.append(ctx.add(
                    vuln_type="robots", url=base + path, method="GET", param="",
                    payload="", evidence="; ".join(rules[:6]),
                    severity=self.severity, confidence=0.6,
                    proof=f"robots.txt 公开列出 {len(rules)} 条路径"
                          + (f", 其中 {sensitive[:5]} 指向管理/调试/备份入口"
                             if sensitive else "")))
            else:
                if "<urlset" not in result.text.lower():
                    continue
                locations = re.findall(r"<loc>\s*([^<\s]+)", result.text)
                findings.append(ctx.add(
                    vuln_type="sitemap", url=base + path, method="GET", param="",
                    payload="", evidence=f"共 {len(locations)} 条 URL: "
                                         f"{'; '.join(locations[:5])}",
                    severity=self.severity, confidence=0.6,
                    proof="sitemap.xml 公开站点全部 URL, 便于攻击者枚举接口"))
        return findings


def _looks_sensitive(path: str) -> bool:
    low = path.lower()
    return any(token in low for token in (
        "admin", "manage", "debug", "backup", "bak", "sql", "config", "env",
        "test", "internal", "private", "api", "console", "log", "tmp", "upload",
    ))


__all__ = ["ACTUATOR_PATHS", "PMA_PATHS", "ROBOTS_PATHS", "SWAGGER_PATHS",
           "UNAUTH_MARKERS", "UNAUTH_PROBE_PATHS", "PhpMyAdmin", "Robots",
           "SpringActuator", "SwaggerUi", "Unauth"]
