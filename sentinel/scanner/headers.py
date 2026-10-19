"""Passive configuration observations from an already received HTTP response."""
from __future__ import annotations

import re

from ..core.models import Finding, Severity
from .client import HttpResult
from .structured_headers import inspect_structured_item

_PRIVATE_REFERRERS = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
_PUBLIC_REFERRERS = {"origin", "origin-when-cross-origin", "unsafe-url", "no-referrer-when-downgrade"}


def has_nosniff(value: str) -> bool:
    """Whether the received header value enables the nosniff policy."""
    # Fetch uses the first list value and trims only HTTP space/tab. A quoted
    # value cannot equal this token, even if its first comma is inside quotes.
    return value.partition(",")[0].strip(" \t").lower() == "nosniff"


def parse_referrer_policy(value: str) -> str:
    """Return the selected HTTP policy, or an empty string when none is valid."""
    policy = ""
    for token in value.split(","):
        token = token.strip(" \t")
        if not token:
            continue
        # Unknown extension tokens are allowed; malformed syntax invalidates the list.
        if re.fullmatch(r"[A-Za-z-]+", token) is None:
            return ""
        token = token.lower()
        if token in _PRIVATE_REFERRERS | _PUBLIC_REFERRERS:
            policy = token
    return policy


def inspect_security_headers(response: HttpResult) -> list[Finding]:
    """Check response headers; no requests, browser claims or exploit proof."""
    if response.status == 0:
        return []
    headers: dict[str, str] = {}
    for key, value in response.header_items or response.headers.items():
        key = key.lower()
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
    issues = []
    sniff = headers.get("x-content-type-options", "").strip(" \t").lower()
    if sniff != "nosniff":
        message = ("响应头格式不规范，但按 Fetch 首值规则仍启用 nosniff"
                   if has_nosniff(headers.get("x-content-type-options", ""))
                   else "缺少或无效的 nosniff 响应头")
        issues.append(("X-Content-Type-Options", message))
    referrer = headers.get("referrer-policy")
    if referrer is not None:
        policy = parse_referrer_policy(referrer)
        if policy not in _PRIVATE_REFERRERS:
            message = ("响应头策略无效，不能据此确认来源信息限制生效" if not policy
                       else "响应头所选策略可能向其他来源发送来源信息")
            issues.append(("Referrer-Policy", message))
    corp = headers.get("cross-origin-resource-policy", "").strip()
    if corp and corp not in {"same-site", "same-origin", "cross-origin"}:
        issues.append(("Cross-Origin-Resource-Policy", "响应头取值无效，无法按该头限制跨来源资源读取"))
    for name, allowed in (
        ("Cross-Origin-Opener-Policy", {"same-origin", "same-origin-allow-popups", "noopener-allow-popups", "unsafe-none"}),
        ("Cross-Origin-Embedder-Policy", {"require-corp", "credentialless", "unsafe-none"}),
    ):
        value = headers.get(name.lower())
        if value is not None:
            item = inspect_structured_item(value)
            if item is None or item[0] != "token" or item[1] not in allowed:
                issues.append((name, "响应头不是有效的结构化策略字段，浏览器可能忽略该策略"))
    return [Finding(vuln_type="security_headers", url=response.url, method=response.method,
                    param=name, payload="", evidence=f"{name}: {headers.get(name.lower(), '(missing)')[:220]}",
                    severity=Severity.INFO, confidence=0.95,
                    proof=f"{message}；仅检查 HTTP 响应头，未评估 HTML meta 或浏览器行为，未确认可利用漏洞")
            for name, message in issues]
