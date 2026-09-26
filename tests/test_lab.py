"""漏洞靶场 (后端 WEB 服务) 测试."""
from __future__ import annotations

import time

import pytest


def test_health_and_home(lab_base, http):
    health = http(lab_base + "/health")
    assert health.status == 200 and health.text.strip() == "ok"
    home = http(lab_base + "/")
    assert home.status == 200 and "漏洞靶场" in home.text
    assert home.header("X-Lab-Instance")


def test_robots_and_404(lab_base, http):
    robots = http(lab_base + "/robots.txt")
    assert robots.status == 200 and "Disallow: /admin" in robots.text
    missing = http(lab_base + "/nope")
    assert missing.status == 404


def test_sqli_error_endpoint(lab_base, http):
    resp = http(lab_base + "/search?q=hello%27")
    assert resp.status == 500 and "SQL syntax" in resp.text


def test_sqli_boolean_endpoint(lab_base, http):
    resp = http(lab_base + "/search?q=1+OR+1%3D1")
    assert resp.status == 200 and "secret-row" in resp.text


def test_sqli_time_endpoint(lab_base, http):
    started = time.perf_counter()
    resp = http(lab_base + "/search?q=1+sleep(2)")
    elapsed = time.perf_counter() - started
    assert resp.status == 200 and elapsed >= 1.9


def test_reflected_xss_endpoint(lab_base, http):
    resp = http(lab_base + "/page?name=%3Cscript%3Ealert(1)%3C/script%3E")
    assert "<script>alert(1)</script>" in resp.text


def test_stored_xss_endpoint(lab_base, http):
    http(lab_base + "/comment", method="POST",
         headers={"Content-Type": "application/x-www-form-urlencoded"},
         body=b"name=bob&message=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E")
    listing = http(lab_base + "/comments")
    assert "<img src=x onerror=alert(1)>" in listing.text


def test_open_redirect(lab_base, http):
    resp = http(lab_base + "/go?next=http://evil.example/")
    assert resp.status == 302 and resp.header("Location") == "http://evil.example/"


def test_cors_misconfiguration(lab_base, http):
    resp = http(lab_base + "/api/user", headers={"Origin": "http://evil.example"})
    assert resp.header("Access-Control-Allow-Origin") == "http://evil.example"
    assert resp.header("Access-Control-Allow-Credentials") == "true"


def test_jsonp_reflection(lab_base, http):
    resp = http(lab_base + "/api/jsonp?callback=myCb")
    assert resp.status == 200 and resp.text.startswith("myCb(")


def test_path_traversal_and_flag(lab_base, http):
    absolute = http(lab_base + "/download?file=/etc/passwd")
    assert absolute.status == 200 and "root:x:0:0:" in absolute.text
    flag = http(lab_base + "/download?file=../vault/flag.txt")
    assert "FLAG{" in flag.text


def test_unauth_admin_and_debug(lab_base, http):
    admin = http(lab_base + "/admin")
    assert admin.status == 200 and "admin-panel" in admin.text
    debug = http(lab_base + "/debug")
    assert "FLAG{" in debug.text and "Traceback" in debug.text


def test_ssrf_markers(lab_base, http):
    internal = http(lab_base + "/fetch?url=http://169.254.169.254/latest/meta-data/")
    assert "sentinel-ssrf-ok" in internal.text and "iam-credentials" in internal.text
    local = http(lab_base + "/fetch?url=http://127.0.0.1:80/")
    assert "sentinel-ssrf-ok" in local.text
    file_read = http(lab_base + "/fetch?url=file:///etc/passwd")
    assert "sentinel-ssrf-ok" in file_read.text


def test_fetch_rejects_invalid_url(lab_base, http):
    assert http(lab_base + "/fetch?url=").status == 400
    assert http(lab_base + "/fetch?url=notaurl").status == 400


def test_jsonp_rejects_bad_callback(lab_base, http):
    assert http(lab_base + "/api/jsonp?callback=bad-cb!").status == 400


def test_orders_api_leaks_debug_error(lab_base, http):
    resp = http(lab_base + "/api/orders")
    assert resp.status == 200 and "SQL syntax" in resp.text


def test_multi_instance_fleet_isolated():
    from sentinel.lab.server import start_lab_fleet

    fleet = start_lab_fleet(0 if False else 0, 3)
    try:
        ports = [s.bound_port for s in fleet]
        assert len(set(ports)) == 3
        assert {s.name for s in fleet} == {"app-1", "app-2", "app-3"}
    finally:
        for server in fleet:
            server.stop()

def test_lab_backlog_survives_scanner_burst():
    """扫描器洪峰下靶场必须及时 accept 连接 (listen backlog 回归测试).

    ``socketserver.TCPServer.request_queue_size`` 默认仅 5, 而 nuclei 这类
    扫描器会瞬时开出上百条并发连接: backlog 顶满后内核静默丢弃 SYN, 客户端
    按 ``tcp_syn_retries`` 退避重试, 单连接握手从毫秒级退化到秒级. 实测 64
    条并发连接: backlog=5 需 7.18 s, backlog=512 仅 17.9 ms; 而 nuclei 的
    ``-timeout 5`` 会因此判定模板超时, 让多引擎评测结果在 122/133 之间抖动.
    """
    import socket
    import time

    from sentinel.lab.server import _QuietThreadingHTTPServer, start_lab

    assert _QuietThreadingHTTPServer.request_queue_size >= 128

    server = start_lab(0, "burst")
    peer = ("127.0.0.1", server.bound_port)
    conns: list[socket.socket] = []
    try:
        # 先建立全部连接 (此时靶场线程都在等待请求行), 把 backlog 顶满
        started = time.perf_counter()
        for _ in range(64):
            sock = socket.socket()
            sock.settimeout(10.0)
            sock.connect(peer)
            conns.append(sock)
        handshake_s = time.perf_counter() - started
        assert handshake_s < 2.0, f"64 条并发握手耗时 {handshake_s:.2f} s, backlog 过小"

        for sock in conns:
            sock.sendall(b"GET /robots.txt HTTP/1.1\r\nHost: lab\r\n"
                         b"Connection: close\r\n\r\n")
        statuses = [sock.recv(64).split(b"\r\n", 1)[0] for sock in conns]
        assert all(b"200" in line for line in statuses), statuses[:3]
    finally:
        for sock in conns:
            sock.close()
        server.stop()
