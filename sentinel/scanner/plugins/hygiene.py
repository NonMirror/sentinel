"""Active response hygiene checks adapted from Nuclei, Nikto and OWASP ZAP."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from ...core.models import Severity
from .base import A05, SCOPE_SERVER, Plugin, PluginContext, register

HEADER_POLICIES: tuple[tuple[str, Severity], ...] = (
    ("Content-Security-Policy", Severity.LOW),
    ("X-Frame-Options", Severity.LOW),
    ("X-Content-Type-Options", Severity.INFO),
    ("Referrer-Policy", Severity.INFO),
    ("Permissions-Policy", Severity.INFO),
    ("X-Permitted-Cross-Domain-Policies", Severity.INFO),
    ("Cross-Origin-Embedder-Policy", Severity.INFO),
    ("Cross-Origin-Opener-Policy", Severity.INFO),
    ("Cross-Origin-Resource-Policy", Severity.INFO),
)


@register
class ResponseHygiene(Plugin):
    """Report the response-header, cookie and stale-server findings of peer scanners."""

    name = "response_hygiene"
    title = "响应安全基线"
    category = "info"
    severity = Severity.LOW
    cwe = "CWE-693"
    owasp = A05
    description = "检查浏览器安全响应头、Cookie属性及明确过旧的服务器版本"
    scope = SCOPE_SERVER
    references = (
        "https://github.com/projectdiscovery/nuclei-templates",
        "https://github.com/zaproxy/zaproxy",
        "https://github.com/sullo/nikto",
    )

    def run(self, ctx: PluginContext) -> list:
        baseline = ctx.raw(ctx.target.base_url)
        if not baseline.status:
            return []
        page = baseline
        if 300 <= baseline.status < 400 and baseline.location:
            redirected = urljoin(ctx.target.base_url, baseline.location)
            if urlsplit(redirected).netloc == urlsplit(ctx.target.base_url).netloc:
                candidate = ctx.raw(redirected)
                if candidate.status:
                    page = candidate

        headers = {key.lower(): value for key, value in page.headers.items()}
        csp = headers.get("content-security-policy", "").lower()
        for name, severity in HEADER_POLICIES:
            present = name.lower() in headers
            if name == "X-Frame-Options" and "frame-ancestors" in csp:
                present = True
            if present:
                continue
            ctx.add(
                vuln_type="security_headers", url=page.url, method="GET",
                param=name, payload="", evidence=f"{name}: (missing)",
                severity=severity, confidence=0.95,
                proof=f"HTML响应缺少{name}；属于浏览器防护基线缺口")

        cookie_lines = [value for key, value in baseline.header_items
                        if key.lower() == "set-cookie"]
        if not cookie_lines and baseline.header("Set-Cookie"):
            cookie_lines = [baseline.header("Set-Cookie")]
        for line in cookie_lines:
            name = line.split("=", 1)[0].strip() or "cookie"
            lower = line.lower()
            for attribute in ("httponly", "secure", "samesite"):
                if re.search(rf"(?:^|;)\s*{attribute}(?:\s*=|\s*;|\s*$)", lower):
                    continue
                ctx.add(
                    vuln_type="cookie_flags", url=baseline.url, method="GET",
                    param=f"{name}:{attribute}", payload="",
                    evidence=f"Set-Cookie: {line[:220]}",
                    severity=Severity.LOW, confidence=0.95,
                    proof=f"Cookie {name!r} 缺少 {attribute} 属性")

        server = baseline.header("Server") or page.header("Server")
        apache = re.search(r"Apache/(\d+)\.(\d+)\.(\d+)", server, re.I)
        if apache and tuple(map(int, apache.groups())) < (2, 4, 68):
            ctx.add(
                vuln_type="outdated_server", url=baseline.url, method="GET",
                param="Server", payload="", evidence=f"Server: {server}",
                severity=Severity.LOW, confidence=0.9,
                proof="Nikto固定版本数据库将该Apache版本判定为过旧，需结合发行版回移补丁复核")
        return ctx.findings


__all__ = ["HEADER_POLICIES", "ResponseHygiene"]
