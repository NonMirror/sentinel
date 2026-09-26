"""漏洞检测模块 — 10 类主动/被动检测插件.

插件签名统一为 ``fn(ctx: DetectorContext) -> list[Finding]``, 便于组合、单测与扩展。
"""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from ..core.models import Finding, Severity
from .client import HttpClient, HttpResult
from .crawler import Endpoint, Target
from .vulndb import (FILE_READ_PAYLOADS, JSONP_MARKER, JSONP_PARAMS,
                     REDIRECT_MARKER, SECRET_RE, SSRF_MARKER, TRACEBACK_RE,
                     UNAUTH_PATHS, XSS_MARKER, XSS_PAYLOADS, VulnDB)


class OobRegistry:
    """带外 (out-of-band) 回调登记表, 用于 SSRF 主动验证."""

    def __init__(self) -> None:
        self._hits: dict[str, float] = {}
        self._lock = threading.Lock()

    def record(self, token: str) -> None:
        with self._lock:
            self._hits[token] = time.time()

    def seen(self, token: str) -> bool:
        with self._lock:
            return token in self._hits

    def tokens(self) -> list[str]:
        with self._lock:
            return list(self._hits)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


@dataclass
class DetectorContext:
    client: HttpClient
    db: VulnDB
    target: Target
    endpoint: Endpoint
    param: str = ""
    position: str = "query"
    baseline_ms: float = 0.0
    time_delay: int = 3
    time_threshold_s: float = 2.4
    oob: OobRegistry = field(default_factory=OobRegistry)
    oob_host: str = "127.0.0.1"
    oob_port: int = 9999
    findings: list[Finding] = field(default_factory=list)

    # ---------------- 注入辅助 ----------------
    def inject(self, payload: str, param: str | None = None,
               position: str | None = None) -> HttpResult:
        param = param if param is not None else self.param
        position = position or self.position
        if position == "form":
            fields = {f: "1" for f in (self.endpoint.form_fields or [param])}
            fields[param] = payload
            body = urlencode(fields)
            return self.client.post(self.endpoint.url, body)
        return self.client.get(_with_param(self.endpoint.url, param, payload))

    def raw(self, url: str, headers: dict[str, str] | None = None) -> HttpResult:
        return self.client.get(url, headers)

    def add(self, **kwargs) -> Finding:
        finding = Finding(**kwargs)
        self.findings.append(finding)
        return finding


def _with_param(url: str, param: str, payload: str) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[param] = payload
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(query, quote_via=quote), parts.fragment))


def _evidence(text: str, needle: str, width: int = 90) -> str:
    idx = text.lower().find(needle.lower())
    if idx < 0:
        return text[:width]
    start = max(0, idx - 20)
    return text[start:idx + len(needle) + width][:220]


# --------------------------------------------------------------------------
# 1. SQL 注入 (报错型)
# --------------------------------------------------------------------------
def detect_sqli_error(ctx: DetectorContext) -> list[Finding]:
    for payload in ctx.db.payloads["sqli"]["error"] + ctx.db.payloads["sqli"]["union"]:
        res = ctx.inject(payload)
        if res.status == 0:
            continue
        body = res.text
        if ctx.db.matchers["sql_error"](body, res.header_text) or (
                res.status >= 500 and "sql" in body.lower()):
            return [ctx.add(
                vuln_type="sqli_error", url=res.url, method=res.method,
                param=ctx.param, payload=payload,
                evidence=_evidence(body, "sql", 60) or body[:120],
                severity=Severity.CRITICAL, confidence=0.95,
                proof=f"注入 {payload!r} 触发数据库报错 (HTTP {res.status})")]
    return []


# --------------------------------------------------------------------------
# 2. SQL 注入 (时间盲注)
# --------------------------------------------------------------------------
def detect_sqli_time(ctx: DetectorContext) -> list[Finding]:
    delay = max(1, int(ctx.time_delay))
    baseline = ctx.baseline_ms / 1000.0
    if baseline <= 0:
        baseline = ctx.client.request(ctx.endpoint.method, ctx.endpoint.url).elapsed_s
    for template in ctx.db.payloads["sqli"]["time"]:
        payload = template.format(n=delay)
        res = ctx.inject(payload)
        if res.status == 0:
            continue
        if res.elapsed_s >= max(ctx.time_threshold_s, baseline + delay * 0.7):
            return [ctx.add(
                vuln_type="sqli_time", url=res.url, method=res.method,
                param=ctx.param, payload=payload,
                evidence=f"响应耗时 {res.elapsed_s * 1000:.0f}ms (基线 {baseline * 1000:.0f}ms)",
                severity=Severity.CRITICAL, confidence=0.9,
                proof=f"时间盲注成功: SLEEP({delay}) 引发 {res.elapsed_s:.2f}s 延迟")]
    return []


# --------------------------------------------------------------------------
# 3. 跨站脚本 (反射型)
# --------------------------------------------------------------------------
def detect_xss(ctx: DetectorContext) -> list[Finding]:
    active = [p for p in XSS_PAYLOADS
              if p not in ("javascript:alert('" + XSS_MARKER + "')",)]
    for payload in active:
        res = ctx.inject(payload)
        if res.status == 0 or not res.body:
            continue
        body = res.text
        if XSS_MARKER not in body:
            continue
        escaped = ("&lt;script" in body and "<script" not in body
                   and "onerror=" not in body)
        if not escaped:
            return [ctx.add(
                vuln_type="xss", url=res.url, method=res.method, param=ctx.param,
                payload=payload, evidence=_evidence(body, XSS_MARKER, 60),
                severity=Severity.HIGH, confidence=0.92,
                proof="载荷未经过 HTML 实体编码直接回显到响应体")]
    return []


# --------------------------------------------------------------------------
# 4. 服务端请求伪造 (SSRF)
# --------------------------------------------------------------------------
def detect_ssrf(ctx: DetectorContext) -> list[Finding]:
    token = f"sentinel{int(time.time() * 1000) % 10_000_000}"
    payloads = [
        f"http://{ctx.oob_host}:{ctx.oob_port}/{token}",
        f"http://{ctx.oob_host}:{ctx.oob_port}/ssrf-probe",
    ] + [p for p in ctx.db.payloads["ssrf"] if "{oob}" not in p]
    for payload in payloads:
        res = ctx.inject(payload)
        if res.status == 0:
            continue
        body = res.text
        hit = SSRF_MARKER in body or ctx.oob.seen(token)
        if not hit:
            for marker in ("root:x:0:0:", "iam-credentials", "internal-service-reached"):
                if marker in body:
                    hit = True
                    break
        if hit:
            return [ctx.add(
                vuln_type="ssrf", url=res.url, method=res.method, param=ctx.param,
                payload=payload,
                evidence=_evidence(body, SSRF_MARKER) or body[:160],
                severity=Severity.HIGH, confidence=0.95,
                proof="服务端按用户可控地址发起请求并返回内网数据")]
    return []


# --------------------------------------------------------------------------
# 5. CORS 配置错误
# --------------------------------------------------------------------------
EVIL_ORIGIN = "http://evil.sentinel.test"


def detect_cors(ctx: DetectorContext) -> list[Finding]:
    res = ctx.raw(ctx.endpoint.url, {"Origin": EVIL_ORIGIN})
    if res.status == 0:
        return []
    acao = res.header("Access-Control-Allow-Origin")
    acac = res.header("Access-Control-Allow-Credentials").lower()
    if acao in (EVIL_ORIGIN, "*") and acac == "true":
        severity = Severity.HIGH if acao == EVIL_ORIGIN else Severity.MEDIUM
        return [ctx.add(
            vuln_type="cors", url=ctx.endpoint.url, method="GET", param="Origin",
            payload=f"Origin: {EVIL_ORIGIN}",
            evidence=f"Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}",
            severity=severity, confidence=0.9,
            proof="任意来源可跨域读取携带凭据的响应")]
    if acao == EVIL_ORIGIN:
        return [ctx.add(
            vuln_type="cors", url=ctx.endpoint.url, method="GET", param="Origin",
            payload=f"Origin: {EVIL_ORIGIN}",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            severity=Severity.MEDIUM, confidence=0.75,
            proof="跨域来源被原样反射")]
    return []


# --------------------------------------------------------------------------
# 6. JSONP 劫持
# --------------------------------------------------------------------------
def detect_jsonp(ctx: DetectorContext) -> list[Finding]:
    params = list(ctx.db.payloads["jsonp_params"])
    if ctx.param:
        params = [ctx.param] + [p for p in params if p != ctx.param]
    for param in params[:6]:
        res = ctx.inject(JSONP_MARKER, param=param)
        if res.status == 0:
            continue
        body = res.text.lstrip()
        if body.startswith(JSONP_MARKER + "(") or body.startswith(
                "try{" + JSONP_MARKER) or f"{JSONP_MARKER}(" in body[:80]:
            return [ctx.add(
                vuln_type="jsonp", url=res.url, method=res.method, param=param,
                payload=f"{param}={JSONP_MARKER}", evidence=body[:160],
                severity=Severity.MEDIUM, confidence=0.9,
                proof="callback 参数未经校验直接反射, 可被跨域脚本窃取数据")]
    return []


# --------------------------------------------------------------------------
# 7. 任意文件读取 (路径穿越)
# --------------------------------------------------------------------------
def detect_file_read(ctx: DetectorContext) -> list[Finding]:
    for payload in FILE_READ_PAYLOADS:
        res = ctx.inject(payload)
        if res.status == 0 or not res.body:
            continue
        body = res.text
        if ctx.db.matchers["file_read"](body, ""):
            return [ctx.add(
                vuln_type="file_read", url=res.url, method=res.method, param=ctx.param,
                payload=payload, evidence=_evidence(body, "root:x:0:0", 60) or body[:140],
                severity=Severity.HIGH, confidence=0.95,
                proof="路径穿越成功读取系统敏感文件")]
    return []


# --------------------------------------------------------------------------
# 8. 开放重定向
# --------------------------------------------------------------------------
def detect_url_redirect(ctx: DetectorContext) -> list[Finding]:
    for payload in ctx.db.payloads["url_redirect"]:
        res = ctx.inject(payload)
        if res.status == 0:
            continue
        if 300 <= res.status < 400 and REDIRECT_MARKER in res.location:
            return [ctx.add(
                vuln_type="url_redirect", url=res.url, method=res.method,
                param=ctx.param, payload=payload,
                evidence=f"HTTP {res.status} Location: {res.location}",
                severity=Severity.MEDIUM, confidence=0.95,
                proof="应用将用户可控参数作为跳转目标, 可被用于钓鱼")]
    return []


# --------------------------------------------------------------------------
# 9. 未授权访问
# --------------------------------------------------------------------------
UNAUTH_MARKERS = ("admin-panel", "orders", "\"role\": \"admin\"", "actuator",
                  "manager/html", "console", "FLAG{")


def detect_unauth(ctx: DetectorContext) -> list[Finding]:
    base = f"{urlsplit(ctx.target.base_url).scheme}://{urlsplit(ctx.target.base_url).netloc}"
    findings: list[Finding] = []
    for path in UNAUTH_PATHS:
        res = ctx.raw(base + path)
        if res.status != 200:
            continue
        body = res.text
        marker = next((m for m in UNAUTH_MARKERS if m.lower() in body.lower()), "")
        if marker:
            findings.append(ctx.add(
                vuln_type="unauth", url=base + path, method="GET", param="",
                payload="", evidence=_evidence(body, marker, 40),
                severity=Severity.HIGH, confidence=0.8,
                proof=f"未携带任何凭据访问敏感路径成功 (HTTP 200, 命中标记 {marker!r})"))
    return findings


# --------------------------------------------------------------------------
# 10. 信息泄露
# --------------------------------------------------------------------------
def detect_information_disclosure(ctx: DetectorContext) -> list[Finding]:
    res = ctx.raw(ctx.endpoint.url)
    if res.status == 0 or not res.body:
        return []
    body = res.text
    if TRACEBACK_RE.search(body):
        match = TRACEBACK_RE.search(body)
        return [ctx.add(
            vuln_type="html_res_information_disclosure", url=ctx.endpoint.url,
            method="GET", param="", payload="", evidence=_evidence(body, match.group(0), 80),
            severity=Severity.MEDIUM, confidence=0.8,
            proof="响应中泄露堆栈/异常信息, 可用于辅助攻击")]
    if SECRET_RE.search(body):
        match = SECRET_RE.search(body)
        return [ctx.add(
            vuln_type="html_res_information_disclosure", url=ctx.endpoint.url,
            method="GET", param="", payload="", evidence=_evidence(body, match.group(0), 40),
            severity=Severity.MEDIUM, confidence=0.75,
            proof="响应中泄露口令/密钥/敏感文件内容")]
    return []


DETECTORS: dict[str, Callable[[DetectorContext], list[Finding]]] = {
    "sqli_error": detect_sqli_error,
    "sqli_time": detect_sqli_time,
    "xss": detect_xss,
    "ssrf": detect_ssrf,
    "cors": detect_cors,
    "jsonp": detect_jsonp,
    "file_read": detect_file_read,
    "url_redirect": detect_url_redirect,
    "unauth": detect_unauth,
    "html_res_information_disclosure": detect_information_disclosure,
}

# 无需参数、按端点执行的插件
ENDPOINT_LEVEL = {"cors", "unauth", "html_res_information_disclosure"}


def run_detectors(ctx: DetectorContext, names: list[str] | None = None) -> list[Finding]:
    out: list[Finding] = list(ctx.findings)
    for name in (names or DETECTORS):
        func = DETECTORS.get(name)
        if func is None:
            continue
        out.extend(func(ctx) or [])
    ctx.findings = out
    return out
