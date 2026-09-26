"""漏洞靶场 — 后端 WEB 服务.

一个刻意保留漏洞的多实例 Web 服务, 用于:
  * 编排出 "反向代理 -> 负载均衡 -> 多后端" 的真实拓扑
  * 作为漏洞扫描子系统的靶场, 提供 10 类可复现漏洞

每个漏洞端点都带有稳定的 "特征字符串", 便于扫描器与自动化测试断言.
"""
from __future__ import annotations

import html
import io
import json
import os
import re
import sys
import threading
import time
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

LAB_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.join(LAB_DIR, "vault")
FLAG = "FLAG{sentinel_waf_and_scanner_united}"

SQL_ERROR = "You have an error in your SQL syntax; check the manual near '''"

COMMENTS: list[dict] = []

USER_DB = {"1": {"name": "alice", "role": "user"},
           "2": {"name": "bob", "role": "user"},
           "3": {"name": "root", "role": "admin"}}


class LabApp:
    """纯函数式路由, 便于单元测试直接调用."""

    def __init__(self, name: str = "app-1") -> None:
        self.name = name
        os.makedirs(VAULT, exist_ok=True)
        with open(os.path.join(VAULT, "flag.txt"), "w", encoding="utf-8") as fh:
            fh.write(FLAG + "\n")

    # ---------------- 路由 ----------------
    def handle(self, method: str, target: str, headers: dict[str, str],
               body: bytes) -> tuple[int, dict[str, str], bytes]:
        split = urlsplit(target)
        path = unquote(split.path)
        query = {k: v[0] for k, v in parse_qs(split.query, keep_blank_values=True).items()}
        form = {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace"),
                                            keep_blank_values=True).items()}

        route = self._route(path, method, query, form, headers)
        if route is None:
            return 404, {"Content-Type": "text/html; charset=utf-8"}, (
                "<h1>404 Not Found</h1><p>Wat?</p>").encode()
        status, extra, payload = route
        resp_headers = {"Content-Type": "text/html; charset=utf-8",
                        "Server": f"LabHTTP/1.0 ({self.name})",
                        "X-Lab-Instance": self.name}
        resp_headers.update(extra or {})
        if isinstance(payload, bytes):
            return status, resp_headers, payload
        return status, resp_headers, payload.encode("utf-8")

    def _route(self, path, method, q, form, headers):
        routes = {
            "/health": lambda: (200, {"Content-Type": "text/plain"}, "ok"),
            "/": lambda: (200, None, _HOME.format(name=self.name)),
            "/robots.txt": lambda: (200, {"Content-Type": "text/plain"},
                                    "User-agent: *\nDisallow: /admin\nDisallow: /debug\n"),
            "/search": lambda: self._search(q.get("q", "")),
            "/product": lambda: self._product(q.get("id", "1")),
            "/comments": lambda: self._comments(),
            "/comment": lambda: self._comment(method, form),
            "/page": lambda: self._page(q.get("name", "")),
            "/fetch": lambda: self._fetch(q.get("url", "")),
            "/api/user": lambda: self._cors(headers),
            "/api/jsonp": lambda: self._jsonp(q.get("callback", "")),
            "/download": lambda: self._download(q.get("file", "")),
            "/go": lambda: self._redirect(q.get("next", "")),
            "/admin": lambda: (200, None,
                               "<h1 id='admin-panel'>管理后台</h1>"
                               "<p>admin-panel: 未鉴权可访问</p>"),
            "/debug": lambda: self._debug(),
            "/api/orders": lambda: self._orders(),
        }
        handler = routes.get(path)
        return handler() if handler else None

    # ---------------- 漏洞端点 ----------------
    def _search(self, q: str):
        if re.search(r"(?i)\bsleep\s*\(\s*(\d+)\s*\)", q):
            delay = int(re.search(r"(?i)\bsleep\s*\(\s*(\d+)\s*\)", q).group(1))
            time.sleep(min(delay, 10))
            return 200, None, f"<p>耗时查询完成 ({delay}s)</p>"
        if re.search(r"(?i)waitfor\s+delay", q):
            time.sleep(2.0)
            return 200, None, "<p>耗时查询完成</p>"
        if re.search(r"(?i)\bor\b\s+1\s*=\s*1|' ?or ?'?1'? ?= ?'?1", q):
            return 200, None, "<table><tr><td>alice</td><td>root</td><td>secret-row</td></tr></table>"
        if "'" in q or '"' in q or re.search(r"(?i)\bunion\b|\bselect\b|\bfrom\b", q):
            return 500, None, f"<h1>数据库错误</h1><pre>{SQL_ERROR}</pre>"
        return 200, None, f"<ul><li>结果: {html.escape(q) or 'all'}</li></ul>"

    def _product(self, pid: str):
        if re.search(r"(?i)sleep\s*\(\s*(\d+)", pid):
            time.sleep(min(int(re.search(r"\d+", pid.split("(")[1]).group()), 10))
            return 200, None, "<p>ok</p>"
        if pid.isdigit() and pid in USER_DB:
            item = USER_DB[pid]
            return 200, None, f"<h2>product</h2><p>{item['name']} / {item['role']}</p>"
        if "'" in pid or re.search(r"(?i)\bor\b\s+\d+\s*=\s*\d+|\bunion\b", pid):
            return 200, None, ("<h2>product</h2><p>alice</p><p>bob</p><p>root</p>")
        return 500, None, f"<pre>{SQL_ERROR}</pre>"

    def _comments(self):
        rows = "".join(f"<div class='c'>{c['message']}</div>" for c in COMMENTS)
        return 200, None, f"<h2>留言板</h2>{rows}"

    def _comment(self, method: str, form: dict[str, str]):
        if method != "POST":
            return 405, None, "<p>仅支持 POST</p>"
        COMMENTS.append({"name": form.get("name", ""), "message": form.get("message", "")})
        return 200, None, (
            f"<h2>提交成功</h2><div class='c'>{form.get('message', '')}</div>"
            "<a href='/comments'>查看全部</a>")

    def _page(self, name: str):
        return 200, None, f"<h1>Hello</h1><div id='greet'>{name}</div>"

    def _fetch(self, url: str):
        if not url:
            return 400, None, "<p>缺少 url 参数</p>"
        low = url.lower()
        if low.startswith("file://"):
            try:
                with open(low[7:], "r", encoding="utf-8", errors="replace") as fh:
                    return 200, None, f"<pre>sentinel-ssrf-ok\n{html.escape(fh.read()[:256])}</pre>"
            except OSError as exc:
                return 500, None, f"<pre>sentinel-ssrf-error {exc}</pre>"
        if re.search(r"(?:127\.0\.0\.1|localhost|169\.254\.169\.254|10\.\d+\.\d+\.\d+|192\.168\.)", low):
            body = "sentinel-ssrf-ok internal-service-reached"
            if "169.254.169.254" in low:
                body += " iam-credentials(accessKeyId=AKIA-SENTINEL)"
            return 200, None, f"<pre>{body}</pre>"
        if "://" in url:
            return 200, None, f"<pre>external fetch simulated: {html.escape(url)}</pre>"
        return 400, None, "<p>URL 格式错误</p>"

    def _cors(self, headers: dict[str, str]):
        origin = ""
        for key, value in headers.items():
            if key.lower() == "origin":
                origin = value
        extra = {"Access-Control-Allow-Origin": origin or "*",
                 "Access-Control-Allow-Credentials": "true"}
        body = json.dumps({"user": "alice", "token": "sentinel-cors-token", "role": "user"})
        extra["Content-Type"] = "application/json"
        return 200, extra, body

    def _jsonp(self, callback: str):
        if not callback:
            return 200, {"Content-Type": "application/json"}, '{"error":"missing callback"}'
        if not re.fullmatch(r"[A-Za-z0-9_$.]{1,64}", callback):
            return 400, None, "<p>非法 callback</p>"
        body = f"{callback}({{\"user\":\"alice\",\"token\":\"sentinel-jsonp-token\"}});"
        return 200, {"Content-Type": "application/javascript"}, body

    def _download(self, name: str):
        if not name:
            return 400, None, "<p>缺少 file 参数</p>"
        base = os.path.join(LAB_DIR, "files")
        os.makedirs(base, exist_ok=True)
        with open(os.path.join(base, "readme.txt"), "w", encoding="utf-8") as fh:
            fh.write("sentinel-lab readme\n")
        candidate = os.path.join(base, name)          # 故意不做规范化
        try:
            with open(candidate, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError as exc:
            return 404, None, f"<p>读取失败: {type(exc).__name__}</p>"
        return 200, {"Content-Type": "text/plain"}, content

    def _redirect(self, target: str):
        if not target:
            return 400, None, "<p>缺少 next 参数</p>"
        return 302, {"Location": target}, "<p>redirecting</p>"

    def _debug(self):
        try:
            raise RuntimeError("sentinel-lab debug endpoint")
        except RuntimeError:
            tb = traceback.format_exc()
        body = (
            "<h1>调试信息</h1>"
            f"<pre>FLAG{sorted(os.environ.items())[:0]}{FLAG}</pre>"
            f"<pre>DB_PASSWORD=sentinel-db-pass-2026</pre>"
            f"<pre>{tb[:600]}</pre>")
        return 200, None, body

    def _orders(self):
        return 200, {"Content-Type": "application/json"}, json.dumps(
            {"orders": [{"id": 1, "amount": 42}], "debug_error": SQL_ERROR})


_HOME = """<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>漏洞靶场 {name}</title></head><body>
<h1>后端 WEB 服务 漏洞靶场 ({name})</h1>
<p>Sentinel 综合安全平台实验靶场</p>
<ul>
  <li><a href="/search?q=hello">搜索</a></li>
  <li><a href="/product?id=1">商品</a></li>
  <li><a href="/page?name=guest">问候</a></li>
  <li><a href="/comments">留言板</a></li>
  <li><a href="/fetch?url=http://example.com">URL 抓取</a></li>
  <li><a href="/api/user">用户 API</a></li>
  <li><a href="/api/jsonp?callback=cb">JSONP</a></li>
  <li><a href="/download?file=readme.txt">下载</a></li>
  <li><a href="/go?next=/">跳转</a></li>
  <li><a href="/admin">管理后台</a></li>
  <li><a href="/debug">调试</a></li>
  <li><a href="/api/orders">订单 API</a></li>
</ul></body></html>"""


class _QuietThreadingHTTPServer(ThreadingHTTPServer):
    """静默处理客户端提前断开 (扫描器/压测常见) 的 ThreadingHTTPServer.

    ``request_queue_size`` 默认只有 5 (``socketserver.TCPServer``), 而 nuclei
    一类扫描器会瞬时开出上百条并发连接; 在 5 的 backlog 下内核会直接拒绝
    尚未 accept 的连接, 表现为扫描器偶发 "connection refused", 模板命中
    结果随之抖动. 这里放大到 512, 让靶场在扫描洪峰下表现稳定可复现.
    """

    daemon_threads = True
    request_queue_size = 512

    def handle_error(self, request, client_address) -> None:  # noqa: ANN001
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, TimeoutError)):
            return
        super().handle_error(request, client_address)


class LabServer:
    """单实例漏洞靶场服务 (线程内运行, 便于测试与多实例编排)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9001,
                 name: str = "app-1") -> None:
        self.host = host
        self.port = port
        self.name = name
        self.app = LabApp(name)
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.bound_port: int | None = None
        self.requests = 0

    def start(self) -> int:
        app = self.app
        counter = {"n": 0}

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "LabHTTP/1.0"
            sys_version = ""

            def log_message(self, *args):  # 静音
                return

            @staticmethod
            def _header_value(value) -> str:
                """把头部值压到 latin-1 可编码范围.

                HTTP 头部按 RFC 7230 是 latin-1; 靶场会刻意把用户输入回显到
                ``Location`` / ``Content-Disposition`` 等头部 (漏洞演示),
                因此这里对非 latin-1 输入按原始 UTF-8 字节透传, 而不是让
                ``send_header`` 抛 ``UnicodeEncodeError`` 把连接打断.
                """
                text = str(value)
                try:
                    text.encode("latin-1")
                    return text
                except UnicodeEncodeError:
                    return text.encode("utf-8", "replace").decode("latin-1")

            def _serve(self, method: str) -> None:
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    body = self.rfile.read(length) if length else b""
                    counter["n"] += 1
                    status, headers, payload = app.handle(
                        method, self.path, dict(self.headers.items()), body)
                    self.send_response(status)
                    for key, value in (headers or {}).items():
                        self.send_header(str(key), self._header_value(value))
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    if method != "HEAD":
                        self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    # 客户端提前断开 (扫描器/压测常见): 静默收尾, 不打堆栈
                    self.close_connection = True

            def do_GET(self):  # noqa: N802
                self._serve("GET")

            def do_POST(self):  # noqa: N802
                self._serve("POST")

            def do_HEAD(self):  # noqa: N802
                self._serve("HEAD")

            def do_PUT(self):  # noqa: N802
                self._serve("PUT")

            def __getattr__(self, name: str):
                # 未实现的方法 (TRACE/DELETE/自定义方法) 由 BaseHTTPRequestHandler
                # 通过 ``do_<METHOD>`` 查找; 这里统一兜底, 避免 socketserver 打印堆栈.
                if name.startswith("do_"):
                    return self._unsupported
                raise AttributeError(name)

            def _unsupported(self, *_args) -> None:
                try:
                    self.send_error(HTTPStatus.NOT_IMPLEMENTED, "Unsupported method")
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True

        self._httpd = _QuietThreadingHTTPServer((self.host, self.port), Handler)
        self.bound_port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        name=f"lab-{self.name}", daemon=True)
        self._thread.start()
        return self.bound_port

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    def __enter__(self) -> "LabServer":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


def start_lab(port: int = 9001, name: str = "app-1", host: str = "127.0.0.1") -> LabServer:
    server = LabServer(host=host, port=port, name=name)
    server.start()
    return server


def start_lab_fleet(base_port: int = 9001, instances: int = 3,
                    host: str = "127.0.0.1") -> list[LabServer]:
    """启动多实例靶场. ``base_port=0`` 表示全部使用随机端口 (测试/并行场景)."""
    ports = [0] * instances if base_port == 0 else [base_port + i - 1
                                                    for i in range(1, instances + 1)]
    return [start_lab(port, f"app-{i}", host) for i, port in enumerate(ports, 1)]
