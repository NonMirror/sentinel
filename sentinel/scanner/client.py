"""扫描器 HTTP 客户端 (标准库实现, 支持超时/不跟随重定向/并发)."""
from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

DEFAULT_UA = "Sentinel-Scanner/1.0 (+https://sentinel.local)"


@dataclass(slots=True)
class HttpResult:
    url: str
    method: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed_ms: float = 0.0
    error: str = ""
    raw_request: bytes = b""
    elapsed_s: float = 0.0

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    @property
    def header_text(self) -> str:
        return "\n".join(f"{k}: {v}" for k, v in self.headers.items())

    def header(self, name: str, default: str = "") -> str:
        low = name.lower()
        for key, value in self.headers.items():
            if key.lower() == low:
                return value
        return default

    @property
    def location(self) -> str:
        return self.header("Location")

    @property
    def content_type(self) -> str:
        return self.header("Content-Type")


class HttpClient:
    """极简 HTTP/1.1 客户端. 不自动跟随重定向, 便于检测开放重定向."""

    def __init__(self, timeout: float = 5.0, user_agent: str = DEFAULT_UA,
                 cookie: str = "", headers: dict[str, str] | None = None,
                 max_body: int = 1 << 20) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.cookie = cookie
        self.extra_headers = dict(headers or {})
        self.max_body = max_body
        self.request_count = 0

    def request(self, method: str, url: str, body: bytes | None = None,
                headers: dict[str, str] | None = None) -> HttpResult:
        parts = urlsplit(url)
        scheme = parts.scheme or "http"
        host = parts.hostname or "127.0.0.1"
        port = parts.port or (443 if scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"

        merged = {
            "Host": parts.netloc,
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        if self.cookie:
            merged["Cookie"] = self.cookie
        merged.update(self.extra_headers)
        merged.update(headers or {})
        if body is not None:
            merged["Content-Length"] = str(len(body))
            merged.setdefault("Content-Type", "application/x-www-form-urlencoded")

        head = [f"{method} {path} HTTP/1.1"] + [f"{k}: {v}" for k, v in merged.items()]
        raw = ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + (body or b"")
        result = HttpResult(url=url, method=method, raw_request=raw)

        t0 = time.perf_counter()
        conn = None
        try:
            if scheme == "https":
                conn = http.client.HTTPSConnection(
                    host, port, timeout=self.timeout,
                    context=ssl.create_default_context())
            else:
                conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for key, value in merged.items():
                conn.putheader(key, value)
            conn.endheaders(body or None)
            resp = conn.getresponse()
            result.status = resp.status
            result.headers = {k: v for k, v in resp.getheaders()}
            result.body = resp.read(self.max_body)
        except (socket.timeout, TimeoutError):
            result.error = "timeout"
        except (ConnectionError, OSError) as exc:
            result.error = f"{type(exc).__name__}: {exc}"
        except http.client.HTTPException as exc:
            result.error = f"HTTPException: {exc}"
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            result.elapsed_s = time.perf_counter() - t0
            result.elapsed_ms = result.elapsed_s * 1000.0
            self.request_count += 1
        return result

    def get(self, url: str, headers: dict[str, str] | None = None) -> HttpResult:
        return self.request("GET", url, None, headers)

    def post(self, url: str, data: bytes | str | None = None,
             headers: dict[str, str] | None = None) -> HttpResult:
        payload = data.encode() if isinstance(data, str) else (data or b"")
        return self.request("POST", url, payload, headers)
