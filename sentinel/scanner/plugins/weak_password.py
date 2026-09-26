"""弱口令插件 (w13scan 无独立插件; 上游把登录爆破留给外部工具).

**深度扫描专用**: 会向登录接口提交多组凭据, 在真实目标上可能触发账号锁定或告警,
所以默认不启用。

判定采用"与失败基线对比"而非"看响应里有没有 success 字样":
  1. 先用一组必然错误的凭据建立失败基线 (状态码 / Set-Cookie / 正文);
  2. 再逐组尝试常见弱口令, 命中条件满足其一即判定成功 ——
     状态码类别变化 (200 -> 302)、出现了基线没有的会话 Cookie、
     或正文明显变化且不含失败关键词。
"""
from __future__ import annotations

import re
from urllib.parse import urlencode

from ...core.models import Finding, Severity
from .base import A07, SCOPE_ENDPOINT, Plugin, PluginContext, register, similarity

#: 用户名 / 口令字段名提示
USER_FIELD_HINTS: tuple[str, ...] = ("user", "username", "login", "account", "email",
                                     "uid", "name", "mobile", "phone", "uname")
PASS_FIELD_HINTS: tuple[str, ...] = ("pass", "pwd", "password", "passwd", "secret")

#: 常见弱口令 (对应 w13scan 的 brute 思路, 控制在最小必要集合内)
CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"), ("admin", "123456"), ("admin", "admin123"),
    ("admin", "password"), ("admin", "admin888"), ("test", "test"),
    ("root", "root"), ("guest", "guest"), ("admin", "12345678"),
)

#: 登录失败关键词 (出现在正文里说明这次尝试没成功)
FAILURE_HINTS: tuple[str, ...] = (
    "invalid", "incorrect", "failed", "failure", "wrong", "denied", "unauthorized",
    "bad credentials", "not match", "try again",
    "失败", "错误", "不正确", "无效", "用户名或密码", "密码错",
)

_PASSWORD_INPUT_RE = re.compile(
    r"""<input[^>]*type=["']password["'][^>]*>""", re.I)
_NAME_IN_INPUT_RE = re.compile(r"""name=["']([^"']+)["']""", re.I)


@register
class WeakPassword(Plugin):
    """弱口令 / 登录爆破 (深度扫描)."""

    name = "weak_password"
    title = "弱口令"
    category = "auth"
    severity = Severity.HIGH
    cwe = "CWE-521"
    owasp = A07
    description = "定位登录表单并用常见弱口令尝试登录, 依据与失败基线的差异判定"
    scope = SCOPE_ENDPOINT
    deep_only = True
    references = ("https://owasp.org/www-community/vulnerabilities/Weak_authentication",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        fields = self._locate_fields(ctx)
        if not fields:
            return []
        user_field, pass_field = fields
        baseline = self._submit(ctx, user_field, pass_field, "sentinel_no_such_user",
                                "sentinel_wrong_password_9137")
        if not baseline.status:
            return []
        for username, password in CREDENTIALS:
            result = self._submit(ctx, user_field, pass_field, username, password)
            if not result.status:
                continue
            reason = _success_reason(baseline, result)
            if not reason:
                continue
            return [ctx.add(
                vuln_type="brute_force", url=result.url, method=result.method,
                param=f"{user_field}/{pass_field}",
                payload=f"{username}:{password}",
                evidence=f"正确凭据后 {reason} (HTTP {result.status}); "
                         f"失败基线 HTTP {baseline.status}",
                severity=self.severity, confidence=0.85,
                proof=f"使用弱口令 {username}:{password} 登录成功, 可接管账户")]
        return []

    def _submit(self, ctx: PluginContext, user_field: str, pass_field: str,
                username: str, password: str):
        data = {name: "sentinel" for name in ctx.endpoint.form_fields}
        data[user_field] = username
        data[pass_field] = password
        body = urlencode(data)
        return ctx.request(ctx.endpoint.method or "POST", ctx.endpoint.url, body,
                           {"Content-Type": "application/x-www-form-urlencoded"})

    def _locate_fields(self, ctx: PluginContext) -> tuple[str, str] | None:
        """定位 (用户名, 口令) 字段名."""
        names = list(ctx.endpoint.form_fields)
        page = ctx.raw(ctx.endpoint.url)
        if page.status:
            for tag in _PASSWORD_INPUT_RE.findall(page.text):
                match = _NAME_IN_INPUT_RE.search(tag)
                if match and match.group(1) not in names:
                    names.append(match.group(1))
        password_field = next(
            (n for n in names if any(h in n.lower() for h in PASS_FIELD_HINTS)), "")
        if not password_field:
            return None
        user_field = next(
            (n for n in names
             if n != password_field and any(h in n.lower() for h in USER_FIELD_HINTS)),
            "username")
        return user_field, password_field


def _success_reason(baseline, result) -> str:
    """判断本次登录是否比失败基线更"成功"; 返回命中原因, 无则空串."""
    if baseline.status // 100 != result.status // 100 and result.status < 400:
        return f"状态码类别变化 ({baseline.status} -> {result.status})"
    base_cookie = baseline.header("Set-Cookie")
    cookie = result.header("Set-Cookie")
    if cookie and cookie != base_cookie:
        return "服务端下发了新的会话 Cookie"
    body = result.text.lower()
    if any(hint in body for hint in FAILURE_HINTS):
        return ""
    if similarity(baseline.text, result.text) < 0.8:
        return "响应正文与失败基线显著不同且无失败提示"
    return ""


__all__ = ["CREDENTIALS", "FAILURE_HINTS", "PASS_FIELD_HINTS", "USER_FIELD_HINTS",
           "WeakPassword"]
