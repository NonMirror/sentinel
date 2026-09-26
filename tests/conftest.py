"""pytest 共享夹具: 靶场、运行时、HTTP 客户端与语料."""
from __future__ import annotations

import http.client
import socket
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import pytest

from benchmarks.corpus import build_corpus
from sentinel.core.config import Config
from sentinel.lab.server import LabServer
from sentinel.runtime import SentinelRuntime


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="session")
def lab() -> LabServer:
    """单实例漏洞靶场 (随机端口)."""
    server = LabServer("127.0.0.1", 0, "app-test")
    server.start()
    yield server
    server.stop()


@pytest.fixture(scope="session")
def lab_base(lab: LabServer) -> str:
    return f"http://127.0.0.1:{lab.bound_port}"


@pytest.fixture(scope="session")
def runtime() -> SentinelRuntime:
    """一体化运行时: 3 实例靶场 + WAF 反向代理 (全随机端口)."""
    config = Config()
    config.listener.host = "127.0.0.1"
    config.listener.port = 0
    config.lab.base_port = 0
    config.lab.instances = 3
    config.waf.mode = "block"
    config.scanner.max_urls = 60
    config.scanner.concurrency = 8
    config.scanner.time_based_threshold_s = 1.0
    config.audit_path = "reports/test-audit.jsonl"
    rt = SentinelRuntime(config, engine="python").start()
    yield rt
    rt.stop()


def _make_runtime(name: str) -> SentinelRuntime:
    config = Config()
    config.listener.host = "127.0.0.1"
    config.listener.port = 0
    config.lab.base_port = 0
    config.lab.instances = 2
    config.waf.mode = "block"
    config.waf.paranoia_level = 1
    config.audit_path = f"reports/test-audit-{name}.jsonl"
    return SentinelRuntime(config, engine=name).start()


@pytest.fixture(scope="session")
def native_engine_runtimes():
    """原生引擎运行时 (modsecurity / naxsi) —— 进程内决策, 永远可用."""
    runtimes = {name: _make_runtime(name) for name in ("modsecurity", "naxsi")}
    yield runtimes
    for runtime in runtimes.values():
        runtime.stop()


@pytest.fixture(scope="session")
def reference_engine_runtimes():
    """真实 nginx C 数据面运行时, 未构建时为空 (用例自行 skip)."""
    from sentinel.waf.engines import available_engines

    available = available_engines()
    runtimes: dict[str, SentinelRuntime] = {}
    for name in ("nginx-modsecurity", "nginx-naxsi"):
        if not available.get(name):
            continue
        runtimes[name] = _make_runtime(name)
    yield runtimes
    for runtime in runtimes.values():
        runtime.stop()


@pytest.fixture(scope="session")
def proxy_base(runtime: SentinelRuntime) -> str:
    return f"http://127.0.0.1:{runtime.proxy_port}"


class HttpResponse:
    __slots__ = ("status", "headers", "body", "url")

    def __init__(self, status: int, headers: dict, body: bytes, url: str) -> None:
        self.status = status
        self.headers = headers
        self.body = body
        self.url = url

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str, default: str = "") -> str:
        low = name.lower()
        for key, value in self.headers.items():
            if key.lower() == low:
                return value
        return default


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # 不跟随跳转
        return None


def fetch(url: str, method: str = "GET", headers: dict | None = None,
          body: bytes | None = None, timeout: float = 10.0) -> HttpResponse:
    """发起请求, 不跟随重定向, 返回统一响应对象."""
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, data=body, method=method,
                                     headers=headers or {})
    try:
        with opener.open(request, timeout=timeout) as response:
            return HttpResponse(response.status, dict(response.headers),
                                response.read(), url)
    except urllib.error.HTTPError as exc:
        return HttpResponse(exc.code, dict(exc.headers), exc.read(), url)


@pytest.fixture(scope="session")
def http():
    return fetch


@pytest.fixture(scope="session")
def corpus():
    return build_corpus()


@pytest.fixture()
def fresh_engine():
    """每个测试获得全新引擎 (无跨用例 IDS 状态)."""
    from sentinel.core import EventBus, Metrics
    from sentinel.waf.engine import WafEngine
    from sentinel.waf.rules import load_ruleset

    def factory(mode: str = "block", **kwargs):
        from sentinel.core.config import WafConfig
        config = WafConfig(mode=mode, **kwargs)
        return WafEngine(config, load_ruleset("rules", config.paranoia_level),
                         EventBus(), None, Metrics())
    return factory


def raw_request(method: str, target: str, headers: dict | None = None,
                body: bytes = b"", host: str = "test.local") -> bytes:
    base = {"Host": host, "User-Agent": "pytest-agent/1.0"}
    base.update(headers or {})
    head = [f"{method} {target} HTTP/1.1"] + [f"{k}: {v}" for k, v in base.items()]
    if body:
        head.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body


def raw_socket_request(host: str, port: int, payload: bytes,
                       timeout: float = 10.0) -> bytes:
    """通过裸 socket 发送报文并读取响应 (用于 keep-alive/畸形报文测试)."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(payload)
        chunks: list[bytes] = []
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if b"\r\n\r\n" in b"".join(chunks):
                data = b"".join(chunks)
                head, _, body = data.partition(b"\r\n\r\n")
                length = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1])
                if len(body) >= length and length:
                    break
        return b"".join(chunks)
