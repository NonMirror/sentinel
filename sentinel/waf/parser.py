"""协议解析和配置模块 — HTTP/1.1 报文解析与变量提取.

设计目标: 纯标准库、对畸形报文健壮、单次解析微秒级. 解析结果供规则引擎
(变量选择器) 与反向代理复用.
"""
from __future__ import annotations

import json
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from ..core.models import HttpRequest

MAX_HEADERS = 200
MAX_HEADER_BYTES = 65536
SUPPORTED_METHODS = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT",
}


class ParseError(ValueError):
    """报文格式非法."""


def parse_request(data: bytes, remote_addr: str = "0.0.0.0", remote_port: int = 0,
                  max_body: int = 1 << 20) -> HttpRequest:
    """将原始 HTTP/1.1 请求字节解析为 :class:`HttpRequest`."""
    if not data:
        raise ParseError("空请求")
    head, _, rest = data.partition(b"\r\n\r\n")
    if not _:
        # 容忍仅以 \n\n 分隔的客户端
        head, _, rest = data.partition(b"\n\n")
        if not _:
            raise ParseError("缺少头部终止符")
    if len(head) > MAX_HEADER_BYTES:
        raise ParseError("头部过大")

    lines = head.split(b"\r\n") if b"\r\n" in head else head.split(b"\n")
    request_line = lines[0].decode("latin-1")
    parts = request_line.split(" ")
    if len(parts) != 3:
        raise ParseError(f"请求行非法: {request_line!r}")
    method, target, version = parts
    method = method.upper()
    if method not in SUPPORTED_METHODS:
        raise ParseError(f"不支持的方法: {method}")
    if version not in ("HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0", "HTTP/3"):
        raise ParseError(f"协议版本非法: {version}")

    headers: dict[str, str] = {}
    for raw in lines[1:]:
        if not raw:
            continue
        name, sep, value = raw.decode("latin-1").partition(":")
        if not sep:
            raise ParseError(f"头部非法: {raw!r}")
        name = name.strip()
        if not name or name in headers:
            # 重复头部按逗号合并, 保留原始顺序语义
            if name in headers:
                headers[name] = f"{headers[name]}, {value.strip()}"
            continue
        headers[name] = value.strip()
        if len(headers) > MAX_HEADERS:
            raise ParseError("头部字段过多")

    truncated = False
    body = b""
    length_hdr = _get(headers, "content-length")
    if length_hdr and not length_hdr.strip().isdigit():
        raise ParseError(f"Content-Length 非法: {length_hdr}")
    if method not in ("GET", "HEAD") or rest:
        te = _get(headers, "transfer-encoding").lower()
        if "chunked" in te:
            body, truncated = _read_chunked(rest, max_body)
        elif length_hdr:
            length = int(length_hdr)
            if length > max_body:
                truncated = True
                length = max_body
            body = rest[:length]

    split = urlsplit(target)
    req = HttpRequest(
        method=method,
        target=target,
        version=version,
        headers=headers,
        body=body,
        remote_addr=remote_addr,
        remote_port=remote_port,
        host=_get(headers, "host"),
        path=unquote_plus(split.path) or "/",
        query=split.query,
        raw_head=head,
        truncated=truncated,
    )
    return req


def _read_chunked(data: bytes, max_body: int) -> tuple[bytes, bool]:
    out = bytearray()
    pos = 0
    truncated = False
    while pos < len(data):
        nl = data.find(b"\r\n", pos)
        if nl == -1:
            break
        try:
            size = int(data[pos:nl].split(b";")[0], 16)
        except ValueError:
            break
        pos = nl + 2
        if size == 0:
            break
        chunk = data[pos:pos + size]
        out.extend(chunk)
        pos += size + 2
        if len(out) > max_body:
            truncated = True
            del out[max_body:]
            break
    return bytes(out), truncated


def _get(headers: dict[str, str], name: str) -> str:
    low = name.lower()
    for key, value in headers.items():
        if key.lower() == low:
            return value
    return ""


def _parse_body_args(req: HttpRequest, limit: int = 1 << 17) -> list[tuple[str, str]]:
    """解析请求体参数: urlencoded / JSON / multipart / 裸文本."""
    ctype = req.content_type.lower()
    body = req.body_text(limit)
    if not body:
        return []
    sniffed = body.lstrip()[:1]
    if "application/json" in ctype or (sniffed in ("{", "[") and "json" not in ctype):
        try:
            obj = json.loads(body)
        except (ValueError, RecursionError):
            obj = None
        if obj is not None:
            args: list[tuple[str, str]] = []
            _flatten_json(obj, args)
            return args
    if "application/x-www-form-urlencoded" in ctype or (not ctype and "=" in body):
        return parse_qsl(body, keep_blank_values=True)
    if "application/json" in ctype:
        args: list[tuple[str, str]] = []
        try:
            obj = json.loads(body)
        except (ValueError, RecursionError):
            return [("BODY", body)]
        _flatten_json(obj, args)
        return args
    if "multipart/form-data" in ctype:
        return _parse_multipart(body)
    return [("BODY", body)]


def _flatten_json(obj, out: list[tuple[str, str]], prefix: str = "", depth: int = 0) -> None:
    if depth > 8:
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            _flatten_json(value, out, f"{prefix}.{key}" if prefix else str(key), depth + 1)
    elif isinstance(obj, (list, tuple)):
        for idx, value in enumerate(obj):
            _flatten_json(value, out, f"{prefix}[{idx}]", depth + 1)
    else:
        out.append((prefix, "" if obj is None else str(obj)))


def _parse_multipart(body: str) -> list[tuple[str, str]]:
    args: list[tuple[str, str]] = []
    import re

    for part in re.split(r"-{2,}[^\r\n]{0,120}", body):
        if "Content-Disposition" not in part:
            continue
        name_match = re.search(r'name="([^"]*)"', part)
        if not name_match:
            continue
        _, _, content = part.partition("\r\n\r\n")
        if not content:
            _, _, content = part.partition("\n\n")
        args.append((name_match.group(1), content.strip()))
    return args


def collect_arguments(req: HttpRequest) -> dict[str, str]:
    """合并 query + body 参数 (重复键取首个, 与 ARGS 语义一致)."""
    args: dict[str, str] = {}
    for key, value in parse_qsl(req.query, keep_blank_values=True):
        args.setdefault(key, value)
    for key, value in _parse_body_args(req):
        args.setdefault(key, value)
    return args


def iter_variable_values(req: HttpRequest, selector: str) -> list[str]:
    """解析 ModSecurity 风格变量选择器并返回匹配值列表.

    支持: ``ARGS``/``ARGS_NAMES``/``ARGS:<name>``/``REQUEST_URI``/``REQUEST_LINE``/
    ``REQUEST_METHOD``/``REQUEST_PROTOCOL``/``REQUEST_HEADERS``/``REQUEST_HEADERS:<name>``/
    ``REQUEST_BODY``/``REQUEST_COOKIES``/``REQUEST_COOKIES:<name>``/``REMOTE_ADDR``/
    ``QUERY_STRING``/``PATH_INFO``/``URL``/``USER_AGENT``/``XML``.
    """
    name, _, arg = selector.partition(":")
    name = name.strip().upper()
    arg = arg.strip()

    if name == "ARGS":
        args = collect_arguments(req)
        if arg:
            key = _match_key(args, arg)
            return [args[key]] if key is not None else []
        return list(args.values())
    if name == "ARGS_NAMES":
        return list(collect_arguments(req).keys())
    if name in ("REQUEST_URI", "URL"):
        return [req.target]
    if name == "REQUEST_LINE":
        return [f"{req.method} {req.target} {req.version}"]
    if name == "REQUEST_METHOD":
        return [req.method]
    if name == "REQUEST_PROTOCOL":
        return [req.version]
    if name == "QUERY_STRING":
        return [req.query]
    if name == "PATH_INFO":
        return [req.path]
    if name == "REQUEST_BODY":
        return [req.body_text()]
    if name == "REQUEST_HEADERS":
        if not arg:
            return list(req.headers.values())
        value = _get(req.headers, arg)
        return [value] if value else []
    if name == "USER_AGENT":
        return [req.user_agent] if req.user_agent else []
    if name == "REQUEST_COOKIES":
        cookie = _get(req.headers, "cookie")
        if not cookie:
            return []
        pairs = [c.strip() for c in cookie.split(";") if c.strip()]
        if not arg:
            return pairs
        for pair in pairs:
            key, _, value = pair.partition("=")
            if key.strip().lower() == arg.lower():
                return [value]
        return []
    if name == "REMOTE_ADDR":
        return [req.remote_addr]
    if name in ("XML", "REQUEST_XML"):
        return [req.body_text()] if "xml" in req.content_type.lower() else []
    if name == "FILES_NAMES":
        return [k for k, _ in parse_qsl(req.body_text(), keep_blank_values=True)]
    return []


def _match_key(args: dict[str, str], wanted: str) -> str | None:
    if wanted in args:
        return wanted
    low = wanted.lower()
    for key in args:
        if key.lower() == low:
            return key
    return None


def collect_cookies(req: HttpRequest) -> dict[str, str]:
    cookie = _get(req.headers, "cookie")
    out: dict[str, str] = {}
    for pair in cookie.split(";"):
        key, _, value = pair.partition("=")
        if key.strip():
            out[key.strip()] = value.strip()
    return out
