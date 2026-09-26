"""轻量级防火墙 — 反向代理 (asyncio HTTP/1.1).

职责:
  * 接收客户端请求 -> 协议解析 -> WAF 决策管道
  * 决策为放行时按负载均衡策略转发到后端 WEB 服务 (漏洞靶场)
  * 记录指标、审计日志、事件总线广播
  * 响应侧异常回显检测 (可选)
被拦截时直接返回 403 页面, 不触达后端.
"""
from __future__ import annotations

import asyncio
import time

from ..core.audit import AuditLog, AuditRecord
from ..core.config import Config
from ..core.events import EventBus, Topic
from ..core.metrics import Metrics
from ..core.models import Verdict
from .balancer import Backend, LoadBalancer
from .engine import WafEngine
from .ids import IdsTracker
from .parser import ParseError, parse_request

BLOCK_PAGE = (
    "<!doctype html><html lang=\"zh\"><head><meta charset=\"utf-8\">"
    "<title>403 - Sentinel WAF</title></head><body style=\"font-family:system-ui;"
    "background:#0b1021;color:#e6edf3;text-align:center;padding:12vh\">"
    "<h1 style=\"font-size:64px;margin:0\">403</h1>"
    "<p>请求已被 Sentinel 轻量级防火墙拦截</p>"
    "<p style=\"color:#8b949e\">Rule matches are logged for audit.</p></body></html>"
).encode("utf-8")
CHALLENGE_PAGE = (
    "<!doctype html><html lang=\"zh\"><head><meta charset=\"utf-8\">"
    "<title>429 - Sentinel WAF</title></head><body style=\"font-family:system-ui;"
    "background:#0b1021;color:#e6edf3;text-align:center;padding:12vh\">"
    "<h1 style=\"font-size:64px;margin:0\">429</h1><p>请求频率过高, 已被限速</p></body></html>"
).encode("utf-8")



class WafProxy:
    """反向代理服务器.

    数据面只要求 ``engine`` 提供 ``inspect(HttpRequest) -> Decision``, 因此
    三种引擎都能直接驱动它: 内置 ``WafEngine``、原生 SecRule 解释器
    (:class:`~sentinel.waf.engines.modsecurity.ModSecurityEngine`)、
    原生 Naxsi 评分器。IDS 状态由代理自己持有 —— 早先是向引擎借
    ``engine.ids``, 换成原生引擎后那条路径就不存在了。
    """

    def __init__(self, config: Config, engine: WafEngine | None = None,
                 bus: EventBus | None = None, audit: AuditLog | None = None,
                 metrics: Metrics | None = None, record_audit: bool = True) -> None:
        self.config = config
        self.bus = bus or EventBus()
        self.audit = audit if audit is not None else AuditLog(4096)
        self.metrics = metrics or Metrics()
        # IDS 必须先建: 内置引擎在构造时要接上它 (见 _builtin_engine)
        self.ids = IdsTracker(rate_limit_rps=config.waf.rate_limit_rps,
                              rate_limit_burst=config.waf.rate_limit_burst,
                              paranoia_level=config.waf.paranoia_level)
        self.engine = engine if engine is not None else self._builtin_engine()
        self.balancer = LoadBalancer(config.backends, config.waf.strategy)
        self.record_audit = record_audit
        self._server: asyncio.AbstractServer | None = None
        self.bound_port: int | None = None
        #: 上次绑定的端口, 重启时优先复用 (热切换不改变入口地址)
        self._last_port: int | None = None

    def _builtin_engine(self) -> WafEngine:
        from .rules import load_ruleset
        ruleset = load_ruleset(getattr(self.config, "rule_dir", None),
                               self.config.waf.paranoia_level)
        engine = WafEngine(self.config.waf, ruleset, bus=self.bus, audit=self.audit,
                           metrics=self.metrics)
        engine.bus = self.bus
        engine.metrics = self.metrics
        engine.ids = self.ids
        return engine

    def set_engine(self, inspector) -> None:
        """换用另一个判定器 (原生引擎热切换时由 runtime 调用)."""
        previous = self.engine
        self.engine = inspector
        ids = getattr(previous, "ids", None)
        if ids is not None:
            inspector.ids = ids                     # 保留既有 IDS 状态

    # ---------------- 生命周期 ----------------
    async def start(self) -> int:
        """启动监听.

        监听端口优先用配置值; 配置为 0 (随机) 时**沿用上次绑定的端口** ——
        引擎热切换会「停代理 -> 换引擎 -> 起代理」, 若每次重新随机, 调用方
        手里的入口地址会在切换瞬间失效。
        """
        self.balancer = LoadBalancer(self.config.backends, self.config.waf.strategy)
        host = self.config.listener.host
        wanted = self.config.listener.port or self._last_port or 0
        try:
            self._server = await asyncio.start_server(self._handle_client, host, wanted)
        except OSError:
            if not wanted:                      # pragma: no cover - 端口 0 不会失败
                raise
            self._server = await asyncio.start_server(self._handle_client, host, 0)
        self.bound_port = self._server.sockets[0].getsockname()[1]
        self._last_port = self.bound_port
        self.bus.publish(Topic.LIFECYCLE, {"event": "proxy_started", "port": self.bound_port})
        return self.bound_port

    async def serve_forever(self) -> None:
        await self.start()
        async with self._server:  # type: ignore[union-attr]
            await self._server.serve_forever()  # type: ignore[union-attr]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            # bound_port 保留为 None, 但 _last_port 记住它, 重启时复用
            self.bound_port = None
            self.bus.publish(Topic.LIFECYCLE, {"event": "proxy_stopped"})

    # ---------------- 核心处理 ----------------
    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        try:
            await self._serve_connection(reader, writer, peer)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:  # 兜底: 不因单连接异常拖垮代理
            self.metrics.errors.inc()
            self.bus.publish(Topic.LIFECYCLE, {"event": "proxy_error", "error": str(exc)})
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _read_request(self, reader: asyncio.StreamReader) -> bytes:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=15.0)
        except asyncio.LimitOverrunError as exc:
            # 请求头超过 StreamReader 缓冲上限: 规范化 400, 而不是静默断链
            raise ParseError("请求头过大") from exc
        except ValueError as exc:      # readuntil 分隔符自身超限
            raise ParseError("请求头过大") from exc
        length = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                try:
                    length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    length = 0
        if length:
            body = await asyncio.wait_for(reader.readexactly(length), timeout=15.0)
            return head + body
        return head

    async def _serve_connection(self, reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter,
                                peer: tuple[str, int]) -> None:
        t0 = time.perf_counter()
        while True:
            try:
                data = await self._read_request(reader)
                if not data:
                    return
                self.metrics.bytes_in.inc(len(data))
                req = parse_request(data, peer[0], peer[1],
                                    max_body=self.config.waf.max_body_bytes)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionResetError):
                return
            except ParseError as exc:
                self.metrics.errors.inc()
                self.bus.publish(Topic.LIFECYCLE, {"event": "parse_error", "error": str(exc)})
                await self._send_simple(writer, 400, b"Bad Request", "Sentinel-WAF")
                return

            self.metrics.requests.inc()
            self.metrics.qps.add(1.0)
            decision = self.engine.inspect(req)

            if decision.blocked:
                self.metrics.blocked.inc()
                self.metrics.blocked_window.add(1.0)
                status = 429 if decision.verdict is Verdict.RATE_LIMIT else 403
                page = CHALLENGE_PAGE if status == 429 else BLOCK_PAGE
                await self._send_simple(writer, status, page, "Sentinel-WAF",
                                        extra_rules=decision.matched_rules)
                if status == 429:
                    self.metrics.rate_limited.inc()
                await self._audit(req, status, decision.matched_rules, "local",
                                  (time.perf_counter() - t0) * 1000, len(page))
                if self.config.waf.mode != "detect":
                    return
                continue

            self.metrics.passed.inc()
            resp = await self._forward(req)
            if resp is None:
                await self._send_simple(writer, 502, b"Bad Gateway", "Sentinel-WAF")
                await self._audit(req, 502, (), "-", 0.0, 0)
                return
            await self._send_response(writer, resp)
            self.metrics.latency.observe(resp.elapsed_ms)
            self.metrics.bytes_out.inc(len(resp.body))
            self.ids.record_response(req.remote_addr, resp.status)
            await self._audit(req, resp.status, decision.matched_rules, resp.backend,
                              resp.elapsed_ms, len(resp.body))
            self.bus.publish(Topic.REQUEST, {
                "url": req.url, "client": req.remote_addr, "method": req.method,
                "status": resp.status, "backend": resp.backend,
                "latency_ms": resp.elapsed_ms, "verdict": decision.verdict.value,
            })

    # ---------------- 转发 ----------------
    async def _forward(self, req):
        backend = self.balancer.pick(req.remote_addr)
        if backend is None:
            return None
        self.balancer.acquire(backend)
        t1 = time.perf_counter()
        ok = True
        try:
            resp = await asyncio.wait_for(
                self._proxy_http(req, backend), timeout=self.config.waf.backend_timeout_s)
            if isinstance(resp, tuple):
                raw, status = resp
                elapsed = (time.perf_counter() - t1) * 1000
                from ..core.models import HttpResponse
                headers, body = _split_response(raw)
                self.balancer.release(backend, ok=status < 500, latency_ms=elapsed)
                return HttpResponse(status=status, headers=headers, body=body,
                                    backend=backend.address, elapsed_ms=elapsed)
            return None
        except (asyncio.TimeoutError, ConnectionError, OSError):
            ok = False
            self.balancer.release(backend, ok=False)
            self.metrics.errors.inc()
            return None
        except Exception as exc:
            self.balancer.release(backend, ok=False)
            self.metrics.errors.inc()
            self.bus.publish(Topic.LIFECYCLE,
                             {"event": "forward_error", "backend": backend.name,
                              "error": f"{type(exc).__name__}: {exc}"})
            return None

    async def _proxy_http(self, req, backend: Backend):
        reader, writer = await asyncio.open_connection(backend.config.host,
                                                       backend.config.port)
        try:
            raw = req.raw_head + b"\r\n\r\n" + req.body
            if self.config.waf.add_x_forwarded_for:
                raw = _inject_headers(raw, {
                    "X-Forwarded-For": req.remote_addr,
                    "X-Forwarded-Proto": req.scheme,
                    "X-Sentinel-Backend": backend.name,
                    "X-Real-IP": req.remote_addr,
                    "Connection": "keep-alive",
                })
            writer.write(raw)
            await writer.drain()
            head = await reader.readuntil(b"\r\n\r\n")
            status = _status_of(head)
            body = b""
            if b"content-length" in head.lower():
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        body = await reader.readexactly(int(line.split(b":", 1)[1]))
                        break
            elif status not in (204, 304):
                try:
                    body = await reader.read()
                except Exception:
                    body = b""
            return head + body, status
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # ---------------- 响应 ----------------
    async def _send_simple(self, writer: asyncio.StreamWriter, status: int, body: bytes,
                           server: str, extra_rules: list[int] | None = None) -> None:
        reason = {403: "Forbidden", 429: "Too Many Requests", 400: "Bad Request",
                  502: "Bad Gateway"}.get(status, "OK")
        headers = [
            f"HTTP/1.1 {status} {reason}",
            f"Content-Length: {len(body)}",
            "Content-Type: text/html; charset=utf-8",
            f"Server: {server}",
            "Connection: keep-alive",
        ]
        if extra_rules:
            headers.append("X-Sentinel-Rule: " + ",".join(str(r) for r in extra_rules[:5]))
        writer.write(("\r\n".join(headers) + "\r\n\r\n").encode() + body)
        await writer.drain()

    async def _send_response(self, writer: asyncio.StreamWriter, resp) -> None:
        headers = [f"HTTP/1.1 {resp.status} {_reason(resp.status)}"]
        for key, value in resp.headers.items():
            if key.lower() in ("connection", "transfer-encoding", "keep-alive"):
                continue
            headers.append(f"{key}: {value}")
        headers.append(f"Content-Length: {len(resp.body)}")
        headers.append(f"X-Sentinel-Backend: {resp.backend}")
        headers.append("X-Sentinel-Latency: %.2fms" % resp.elapsed_ms)
        headers.append("Connection: keep-alive")
        writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("latin-1") + resp.body)
        await writer.drain()

    async def _audit(self, req, status: int, rules, backend: str, latency: float,
                     size: int) -> None:
        if not self.record_audit:
            return
        action = "block" if status in (403, 429) else "pass"
        severity = "high" if status in (403, 429) else "info"
        self.audit.append(AuditRecord(
            action=action, client=req.remote_addr, method=req.method, url=req.url,
            status=status, severity=severity, rules=tuple(rules[:8]), backend=backend,
            latency_ms=latency, bytes_out=size,
        ))
        self.bus.publish(Topic.AUDIT, {
            "action": action, "client": req.remote_addr, "url": req.url,
            "status": status, "backend": backend,
        })

    def snapshot(self) -> dict:
        return {
            "engine": (self.engine.snapshot()
                       if hasattr(self.engine, "snapshot") else {}),
            "metrics": self.metrics.snapshot(),
            "backends": self.balancer.stats(),
            "audit_total": self.audit.total,
            "port": self.bound_port,
        }


def _inject_headers(raw: bytes, extra: dict[str, str]) -> bytes:
    head, sep, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    existing = {line.split(b":", 1)[0].strip().lower() for line in lines if b":" in line}
    additions = [f"{k}: {v}".encode("latin-1") for k, v in extra.items()
                 if k.lower().encode() not in existing]
    return b"\r\n".join(lines + additions) + sep + body


def _split_response(raw: bytes) -> tuple[dict[str, str], bytes]:
    head, _, body = raw.partition(b"\r\n\r\n")
    headers: dict[str, str] = {}
    for line in head.split(b"\r\n")[1:]:
        key, sep, value = line.decode("latin-1").partition(":")
        if sep:
            headers[key.strip()] = value.strip()
    headers.pop("Transfer-Encoding", None)
    headers.pop("Content-Length", None)
    return headers, body


def _status_of(head: bytes) -> int:
    try:
        return int(head.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return 502


def _reason(status: int) -> str:
    return {
        200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently",
        302: "Found", 304: "Not Modified", 400: "Bad Request", 401: "Unauthorized",
        403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
        429: "Too Many Requests", 500: "Internal Server Error",
        502: "Bad Gateway", 503: "Service Unavailable",
    }.get(status, "OK")
