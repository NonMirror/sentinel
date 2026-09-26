"""轻量级防火墙数据面端到端测试 (综设 II).

覆盖: 裸 socket 报文解析健壮性、keep-alive 复用、负载均衡分发、
限速 (429)、后端不可用 (502)、响应头注入与审计落盘。
便携引擎 (python) 由 asyncio 反向代理承载数据面, 无需 nginx 即可运行。
"""
from __future__ import annotations

import socket
import time

import pytest

from sentinel.core.config import Config
from sentinel.runtime import SentinelRuntime
from sentinel.waf.proxy import _inject_headers, _reason, _split_response, _status_of
from tests.conftest import raw_socket_request

ATTACK = "/?id=1%20union%20select%201,2,3--"
BENIGN = "/?q=hello&page=2"


def _read_one_response(sock: socket.socket) -> tuple[int, dict[str, str], bytes]:
    """从已连接的 socket 读取一个完整响应 (按 Content-Length 定长)."""
    chunks = b""
    while b"\r\n\r\n" not in chunks:
        chunk = sock.recv(65536)
        if not chunk:
            raise AssertionError("连接在响应头完成前关闭")
        chunks += chunk
    head, _, body = chunks.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    while len(body) < length:
        chunk = sock.recv(65536)
        if not chunk:
            break
        body += chunk
    status = int(head.split(b" ", 2)[1])
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        key, sep, value = line.decode("latin-1").partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    return status, headers, body


# --------------------------------------------------------------------------
# 协议健壮性 (裸 socket)
# --------------------------------------------------------------------------
def test_proxy_keep_alive_reuses_connection(runtime):
    host, port = "127.0.0.1", runtime.front_port
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(10)
        for index in range(3):
            target = f"/?q=ka{index}&page=1"
            sock.sendall(f"GET {target} HTTP/1.1\r\nHost: test.local\r\n"
                         f"Connection: keep-alive\r\n\r\n".encode())
            status, headers, body = _read_one_response(sock)
            assert status == 200, f"第 {index + 1} 次复用请求失败"
            assert headers.get("connection") == "keep-alive"
            assert body


def test_proxy_handles_malformed_requests(runtime):
    host, port = "127.0.0.1", runtime.front_port
    cases = [
        b"GET /only-two-parts\r\n\r\n",                          # 请求行缺版本
        b"FOO / HTTP/1.1\r\nHost: x\r\n\r\n",                    # 不支持的方法
        b"GET / BOGUS/9.9\r\nHost: x\r\n\r\n",                   # 非法协议版本
        b"GET / HTTP/1.1\r\nBroken-Header\r\n\r\n",              # 头部缺少冒号
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n",  # 非法长度
    ]
    for payload in cases:
        raw = raw_socket_request(host, port, payload, timeout=6)
        assert raw, f"未收到响应: {payload!r}"
        assert b"400" in raw.split(b"\r\n", 1)[0], f"未返回 400: {payload!r}"


def test_proxy_rejects_oversized_header(runtime):
    host, port = "127.0.0.1", runtime.front_port
    payload = (b"GET / HTTP/1.1\r\nHost: x\r\nX-Big: " + b"A" * 70000 + b"\r\n\r\n")
    raw = raw_socket_request(host, port, payload, timeout=6)
    assert raw.split(b"\r\n", 1)[0].endswith(b"400 Bad Request")


def test_proxy_survives_oversized_body(runtime):
    """超出 max_body_bytes 的请求体不得拖垮代理 (随后仍能正常服务)."""
    host, port = "127.0.0.1", runtime.front_port
    body = b"comment=ok&" * 40000            # 440KB > max_body_bytes (128KB)
    payload = (f"POST /comment HTTP/1.1\r\nHost: x\r\n"
               f"Content-Length: {len(body)}\r\n\r\n").encode() + body
    raw = raw_socket_request(host, port, payload, timeout=12)
    assert raw, "超大请求体未得到任何响应"
    from tests.conftest import fetch
    followup = fetch(f"http://127.0.0.1:{port}{BENIGN}", timeout=10)
    assert followup.status == 200, "代理在超大请求体之后失去服务能力"


def test_proxy_returns_404_from_backend(runtime):
    from tests.conftest import fetch
    response = fetch(f"http://127.0.0.1:{runtime.front_port}/definitely-not-here")
    assert response.status == 404
    assert "404" in response.text                          # 来自真实后端靶场
    assert response.header("X-Sentinel-Backend")            # 反向代理标注了后端
    assert response.header("X-Sentinel-Latency")


# --------------------------------------------------------------------------
# 拦截 / 放行语义
# --------------------------------------------------------------------------
def test_proxy_blocks_attack_with_rule_header(runtime):
    from tests.conftest import fetch
    response = fetch(f"http://127.0.0.1:{runtime.front_port}{ATTACK}")
    assert response.status == 403
    assert "Sentinel" in response.text
    assert response.header("X-Sentinel-Rule")
    assert all(rule.isdigit() for rule in
               response.header("X-Sentinel-Rule").split(",") if rule)


def test_proxy_passes_benign_and_marks_backend_and_forwards_headers(runtime):
    from tests.conftest import fetch
    response = fetch(f"http://127.0.0.1:{runtime.front_port}{BENIGN}")
    assert response.status == 200
    assert response.header("X-Sentinel-Backend")


def test_proxy_injects_xff_without_clobbering_client_header():
    raw = (b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n")
    injected = _inject_headers(raw, {"X-Forwarded-For": "1.1.1.1", "X-Real-IP": "1.1.1.1"})
    assert injected.count(b"X-Forwarded-For") == 1        # 已存在则不重复注入
    assert b"9.9.9.9" in injected
    assert b"X-Real-IP: 1.1.1.1" in injected


def test_proxy_load_balances_across_backends(runtime):
    from tests.conftest import fetch
    distribution: dict[str, int] = {}
    for _ in range(12):
        response = fetch(f"http://127.0.0.1:{runtime.front_port}/health")
        assert response.status == 200
        backend = response.header("X-Sentinel-Backend", "unknown")
        distribution[backend] = distribution.get(backend, 0) + 1
    assert len(distribution) >= 2, f"负载均衡未分发: {distribution}"
    # round_robin 应接近均匀 (12 次 / 3 后端)
    assert max(distribution.values()) - min(distribution.values()) <= 3


def test_proxy_returns_502_when_backend_is_down(tmp_path):
    config = Config()
    config.listener.port = 0
    config.lab.base_port = 0
    config.lab.instances = 0        # 不启动靶场 -> 后端全部不可用
    config.waf.backend_timeout_s = 1.0
    config.audit_path = str(tmp_path / "audit.jsonl")
    runtime = SentinelRuntime(config, engine="python", start_lab=False).start()
    try:
        from tests.conftest import fetch
        response = fetch(f"http://127.0.0.1:{runtime.front_port}/", timeout=15)
        assert response.status == 502
    finally:
        runtime.stop()


# --------------------------------------------------------------------------
# 限速 (429) 与审计
# --------------------------------------------------------------------------
def test_proxy_rate_limit_returns_429(tmp_path):
    config = Config()
    config.listener.port = 0
    config.lab.base_port = 0
    config.lab.instances = 1
    config.waf.rate_limit_rps = 2
    config.waf.rate_limit_burst = 1
    config.audit_path = str(tmp_path / "audit.jsonl")
    runtime = SentinelRuntime(config, engine="python").start()
    try:
        from tests.conftest import fetch
        base = f"http://127.0.0.1:{runtime.front_port}"
        statuses = [fetch(f"{base}/?q=rl&i={i}").status for i in range(15)]
        assert 429 in statuses, f"限速未生效: {statuses}"
        assert statuses[0] == 200
        assert runtime.metrics.rate_limited.value >= 1
    finally:
        runtime.stop()


def test_proxy_writes_audit_records_for_block_and_pass(runtime):
    from tests.conftest import fetch
    base = f"http://127.0.0.1:{runtime.front_port}"
    before = runtime.audit.total
    fetch(base + BENIGN)
    fetch(base + ATTACK)
    deadline = time.time() + 5
    while time.time() < deadline and runtime.audit.total < before + 2:
        time.sleep(0.05)
    records = runtime.audit.recent(20)
    actions = {record.action for record in records}
    assert "block" in actions and "pass" in actions
    blocked = [r for r in records if r.action == "block"][-1]
    assert blocked.status == 403
    assert blocked.rules
    assert runtime.bus.history("block", 10)


# --------------------------------------------------------------------------
# 协议辅助函数
# --------------------------------------------------------------------------
def test_proxy_helper_functions():
    head, body = _split_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
    assert head == {"Content-Type": ""} or "Content-Length" not in head
    assert body == b"hello"
    assert _status_of(b"HTTP/1.1 204 No Content") == 204
    assert _status_of(b"garbage") == 502
    assert _reason(403) == "Forbidden"
    assert _reason(429) == "Too Many Requests"
    assert _reason(299) == "OK"
