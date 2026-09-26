"""模板执行器: 把一条 nuclei 模板跑在一个目标上, 产出 :class:`Finding`.

执行模型 (对齐 nuclei 的语义):

1. **载荷组合**: 按 ``attack`` 模式把 ``payloads`` 展开成变量组合。
2. **请求展开**: 每个变量组合 x 每个 ``path``/``raw`` 产生一次具体请求。
3. **布尔求值**: 块内 ``matchers`` 先按各自 ``condition`` 折叠, 再按块级
   ``matchers-condition`` 组合; 全部通过才算命中。
4. **提取**: 命中的块执行 ``extractors``, 结果既写入 ``Finding.proof``,
   也回灌到上下文供后续请求使用 (nuclei 的 ``internal`` 提取器)。

HTTP 复用 :class:`sentinel.scanner.client.HttpClient` —— 与内置扫描器同一套
连接与超时策略, 便于统一统计。
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Sequence
from urllib.parse import urlsplit

from ...core.models import Finding, Severity
from ..client import HttpClient, HttpResult
from .expression import ResponseContext, render
from .matchers import extract, match_block
from .model import Extractor, HttpBlock, Template


@dataclass(slots=True)
class RunStats:
    """模板执行的观测数据 (供引擎状态与报告)."""

    templates: int = 0
    requests: int = 0
    matched: int = 0
    errors: int = 0
    dsl_failures: int = 0
    seconds: float = 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            "templates": self.templates, "requests": self.requests,
            "matched": self.matched, "errors": self.errors,
            "dsl_failures": self.dsl_failures, "seconds": round(self.seconds, 3),
        }


@dataclass(slots=True)
class TargetVars:
    """目标 URL 拆解出的模板变量."""

    base_url: str
    scheme: str = "http"
    host: str = ""
    port: str = "80"
    path: str = "/"

    @classmethod
    def of(cls, url: str) -> "TargetVars":
        try:
            parts = urlsplit(url)
        except ValueError:
            parts = urlsplit("")
        scheme = parts.scheme or "http"
        try:
            host = parts.hostname or ""
            port = str(parts.port) if parts.port else ("443" if scheme == "https" else "80")
        except ValueError:
            host, port = "", "80"
        base = f"{scheme}://{host}" + (f":{parts.port}" if parts.port else "")
        return cls(base_url=base.rstrip("/"), scheme=scheme, host=host, port=port,
                   path=parts.path or "/")

    def variables(self) -> dict[str, str]:
        return {
            "BaseURL": self.base_url, "RootURL": self.base_url,
            "Hostname": self.host, "Host": self.host, "Port": self.port,
            "Scheme": self.scheme, "Path": self.path,
        }


def expand_payloads(block: HttpBlock,
                    base: dict[str, str]) -> list[dict[str, str]]:
    """按攻击模式展开载荷, 返回若干份变量表."""
    if not block.payloads:
        return [dict(base)]
    names = list(block.payloads)
    mode = block.effective_attack
    combos: list[dict[str, str]] = []

    if mode == "batteringram":
        # 所有变量取同一份载荷
        length = max(len(block.payloads[n]) for n in names)
        for index in range(length):
            combo = dict(base)
            for name in names:
                values = block.payloads[name]
                combo[name] = values[index % len(values)]
            combos.append(combo)
    elif mode == "pitchfork":
        # 各变量并行推进 (同步迭代)
        length = max(len(block.payloads[n]) for n in names)
        for index in range(length):
            combo = dict(base)
            for name in names:
                values = block.payloads[name]
                combo[name] = values[index % len(values)]
            combos.append(combo)
    elif mode == "sniper":
        # 一次只放一个变量, 其余留空; 单变量时退化为逐条替换
        if len(names) == 1:
            name = names[0]
            for value in block.payloads[name]:
                combo = dict(base)
                combo[name] = value
                combos.append(combo)
        else:
            for name in names:
                for value in block.payloads[name]:
                    combo = dict(base)
                    for other in names:
                        combo.setdefault(other, "")
                    combo[name] = value
                    combos.append(combo)
    else:  # clusterbomb (笛卡尔积)
        pools = [[(name, v) for v in block.payloads[name]] for name in names]
        for combination in itertools.product(*pools):
            combo = dict(base)
            combo.update(dict(combination))
            combos.append(combo)
    return combos


class TemplateRunner:
    """在目标上执行模板."""

    #: 响应缓存上限 (条). 官方模板树里 ``/.git/config``、``/robots.txt``
    #: 这类路径会被几十上百条模板重复请求, 缓存能把请求数砍掉一大半。
    CACHE_LIMIT = 4096

    def __init__(self, client: HttpClient, *, max_requests: int = 512,
                 allowed_hosts: set[str] | None = None) -> None:
        self.client = client
        self.max_requests = max_requests
        self.stats = RunStats()
        #: (method, url, headers, body) -> HttpResult; 只缓存无副作用的 GET/HEAD
        self._cache: dict[tuple, HttpResult] = {}
        self.cache_hits = 0
        #: 允许访问的主机集合 (空 = 不限制). 见 :meth:`_host_allowed`.
        self.allowed_hosts = {h.lower() for h in (allowed_hosts or set()) if h}
        self.blocked_external = 0

    # ------------------------------------------------------------------
    def run(self, template: Template, target: str) -> list[Finding]:
        """执行一条模板, 返回全部发现."""
        self.stats.templates += 1
        variables = dict(template.variables)
        variables.update(TargetVars.of(target).variables())
        findings: list[Finding] = []
        budget = self.max_requests

        for block in template.blocks:
            variables.update(block.variables)
            for combo in expand_payloads(block, variables):
                for url, method, body, headers in self._requests(block, combo):
                    if budget <= 0:
                        return findings
                    budget -= 1
                    result = self._send(method, url, headers, body, block)
                    if result is None:
                        continue
                    context = self._context(result, template, combo,
                                            method, url, headers, body)
                    ok, _hit = match_block(block.matchers, block.matchers_condition,
                                           context)
                    if not ok:
                        continue
                    self.stats.matched += 1
                    proof = self._extract(block.extractors, context)
                    variables.update(context.extracted)
                    findings.append(self._finding(template, context, method,
                                                  proof, body))
                    if block.stop_at_first_match:
                        return findings
        return findings

    # ------------------------------------------------------------------
    def _requests(self, block: HttpBlock, variables: dict[str, str]):
        """把请求块展开为 (url, method, body, headers) 序列."""
        headers = {k: render(v, variables) for k, v in block.headers.items()}
        body = render(block.body, variables)
        for raw in block.raw:
            parsed = self._parse_raw(raw.lines, variables)
            if parsed is not None:
                yield parsed
        for path in block.path:
            url = render(path, variables)
            if url.startswith("/"):
                # 允许模板写相对路径: 补上目标主机
                url = variables.get("BaseURL", "").rstrip("/") + url
            if not url.startswith(("http://", "https://")):
                continue
            yield url, block.method, body, headers

    @staticmethod
    def _parse_raw(lines: Sequence[str], variables: dict[str, str]):
        """解析 ``raw:`` 块 (首行 + 头部 + 空行 + body)."""
        if not lines:
            return None
        first = render(lines[0], variables).split()
        if len(first) < 2:
            return None
        method, path = first[0].upper(), first[1]
        headers: dict[str, str] = {}
        body_lines: list[str] = []
        in_body = False
        for line in lines[1:]:
            if in_body:
                body_lines.append(render(line, variables))
                continue
            if not line.strip():
                in_body = True
                continue
            name, sep, value = line.partition(":")
            if sep:
                headers[name.strip()] = render(value.strip(), variables)
        if path.startswith("/"):
            path = variables.get("BaseURL", "").rstrip("/") + path
        if not path.startswith(("http://", "https://")):
            return None
        return path, method, "\n".join(body_lines), headers

    # ------------------------------------------------------------------
    def _send(self, method: str, url: str, headers: dict[str, str],
              body: str, block: HttpBlock) -> HttpResult | None:
        if not self._host_allowed(url):
            self.blocked_external += 1
            return None
        cacheable = method in ("GET", "HEAD") and not body
        key = (method, url, tuple(sorted(headers.items()))) if cacheable else None
        if key is not None:
            cached = self._cache.get(key)
            if cached is not None:
                self.cache_hits += 1
                return cached

        self.stats.requests += 1
        try:
            result = self.client.request(method, url, body=body.encode("utf-8"),
                                         headers=headers or None)
        except Exception:                                  # noqa: BLE001 - 单请求失败
            self.stats.errors += 1
            return None
        if result is None or (result.error and not result.status):
            # 连接失败 / 超时: 没有响应可匹配, 直接跳过而不是拿空 body 去比
            self.stats.errors += 1
            return None
        if key is not None and len(self._cache) < self.CACHE_LIMIT:
            self._cache[key] = result
        return result

    def _host_allowed(self, url: str) -> bool:
        """请求目标是否在允许范围内.

        官方模板里有相当一批把**外部主机写死**在 ``path`` 里 (SSRF/OAST 探测:
        ``http://169.254.169.254/...``、``http://<vendor>.oast.pro/...``、
        ``https://generativelanguage.googleapis.com/...``)。扫描一个内网靶场时
        这些请求只会:

        * 悄悄把「谁在扫描」告诉第三方域名 —— 对授权测试而言是不可接受的副作用;
        * 各卡在超时上 (实测 31 条这样的请求吃掉 151 秒, 其中一条 DNS 挂了 40 秒)。

        因此默认只允许访问**本次扫描的目标主机**。需要放行更多主机时, 由调用方
        显式传 ``allowed_hosts``; 传空集合表示不限制 (保持库的通用性)。
        """
        if not self.allowed_hosts:
            return True
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:
            return False
        return host.lower() in self.allowed_hosts

    @staticmethod
    def _context(result: HttpResult, template: Template, combo: dict[str, str],
                 method: str, url: str, headers: dict[str, str],
                 body: str) -> ResponseContext:
        request_text = "\n".join(
            [f"{method} {url}", *(f"{k}: {v}" for k, v in headers.items()), "", body])
        return ResponseContext(
            url=result.url or url,
            status_code=result.status,
            body=result.text,
            body_bytes=result.body,
            headers=dict(result.headers),
            duration=result.elapsed_s or (result.elapsed_ms / 1000.0),
            request=request_text,
            template_id=template.id,
            variables=dict(combo),
        )

    @staticmethod
    def _extract(extractors: tuple[Extractor, ...],
                 context: ResponseContext) -> str:
        proofs: list[str] = []
        for extractor in extractors:
            values = extract(extractor, context)
            if not values:
                continue
            if extractor.name and not extractor.name.startswith("_"):
                context.extracted[extractor.name] = values[0]
            proofs.extend(values[:3])
        return " | ".join(proofs)[:400]

    @staticmethod
    def _finding(template: Template, context: ResponseContext, method: str,
                 proof: str, body: str) -> Finding:
        from ..engines.base import severity_by_type
        severity = template.severity
        if severity is Severity.MEDIUM and template.tags:
            severity = severity_by_type(" ".join(template.tags))
        return Finding(
            vuln_type=template.short_id,
            url=context.url,
            severity=severity,
            method=method,
            param="",
            payload="",
            evidence=template.name[:160],
            proof=proof or f"HTTP {context.status_code} / {context.content_length} bytes",
            confidence=0.9,
            conn_id="nuclei",
        )


def template_as_rule(template: Template) -> dict:
    """模板的规则视图 (供 TUI 的规则库面板展示)."""
    return {
        "id": template.id,
        "name": template.name,
        "severity": template.severity.value,
        "tags": list(template.tags),
        "requests": len(template.blocks),
        "matchers": sum(len(b.matchers) for b in template.blocks),
        "extractors": sum(len(b.extractors) for b in template.blocks),
        "path": template.path,
    }
