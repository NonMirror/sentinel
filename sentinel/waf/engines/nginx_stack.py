"""真实 nginx 数据面的配置生成 / 进程托管 / 日志回采.

本模块只负责"跑起真实的 nginx"; 具体启用哪个 WAF 引擎 (ModSecurity 还是 Naxsi)
由 :mod:`sentinel.waf.engines.modsecurity` / :mod:`sentinel.waf.engines.naxsi`
提供指令片段. 所有生成物均落在 ``~/Projects`` 工作区内.
"""
from __future__ import annotations

import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

from ...core.config import BackendConfig, WafConfig
from ...vendor import naxsi_core_rules as vendored_naxsi_rules
from .base import build_root, run_capture

_UPSTREAM_STRATEGY = {
    "round_robin": "",
    "least_conn": "least_conn;",
    "ip_hash": "ip_hash;",
    "random": "random two;",
}


def free_port(host: str = "127.0.0.1") -> int:
    """申请一个空闲 TCP 端口 (用于状态页等辅助监听)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


# --------------------------------------------------------------------------
# 已构建的 nginx 安装
# --------------------------------------------------------------------------
@dataclass(slots=True)
class NginxInstall:
    """一份已编译好的 nginx (含静态模块)."""

    prefix: Path
    sbin: Path
    version: str = ""
    modules: tuple[str, ...] = ()

    CANDIDATES = ("nginx-sentinel", "nginx-naxsi")

    @classmethod
    def locate(cls, root: Path | None = None) -> "NginxInstall | None":
        """在 ``sentinel/build`` 下寻找已构建的 nginx (没有任何外部目录)."""
        base = root or build_root()
        for name in cls.CANDIDATES:
            sbin = base / name / "sbin" / "nginx"
            if sbin.exists():
                install = cls(prefix=base / name, sbin=sbin)
                install.version, install.modules = install._probe()
                return install
        return None

    # -- 探测 --
    def _probe(self) -> tuple[str, tuple[str, ...]]:
        code, out = run_capture([str(self.sbin), "-V"], timeout=15)
        version = ""
        match = re.search(r"nginx version: nginx/(\S+)", out)
        if match:
            version = match.group(1)
        modules = tuple(sorted(set(re.findall(r"--add-module=(\S+?)(?:/|\s|$)", out))))
        extra = []
        if "modsecurity-nginx" in out:
            extra.append("modsecurity")
        if "naxsi" in out:
            extra.append("naxsi")
        return version or "unknown", tuple(extra) if extra else modules

    @property
    def has_modsecurity(self) -> bool:
        return "modsecurity" in self.modules

    @property
    def has_naxsi(self) -> bool:
        return "naxsi" in self.modules

    @property
    def conf_dir(self) -> Path:
        return self.prefix / "conf"

    def naxsi_core_rules(self) -> Path | None:
        """Naxsi 核心规则取自 ``sentinel/vendor`` (与原生引擎同一份数据)."""
        path = vendored_naxsi_rules()
        return path if path.exists() else None


# --------------------------------------------------------------------------
# nginx 进程 + 运行目录
# --------------------------------------------------------------------------
@dataclass
class NginxHost:
    """托管一个 nginx 进程 (配置 / 日志 / 生命周期)."""

    name: str
    install: NginxInstall
    base: Path
    host: str = "127.0.0.1"
    front_port: int = 0
    status_port: int = 0
    conf_path: Path | None = None
    _pid: int | None = None
    _started_at: float = 0.0

    # -- 目录 --
    @property
    def dirs(self) -> dict[str, Path]:
        return {
            "base": self.base,
            "conf": self.base / "conf",
            "logs": self.base / "logs",
            "tmp": self.base / "tmp",
            "data": self.base / "data",
        }

    @property
    def error_log(self) -> Path:
        return self.base / "logs" / "error.log"

    @property
    def access_log(self) -> Path:
        return self.base / "logs" / "access.log"

    def prepare(self) -> None:
        for path in self.dirs.values():
            path.mkdir(parents=True, exist_ok=True)
        for sub in ("body", "proxy", "fastcgi", "uwsgi", "scgi"):
            (self.dirs["tmp"] / sub).mkdir(parents=True, exist_ok=True)

    # -- 配置 --
    def write_conf(self, text: str, filename: str = "nginx.conf") -> Path:
        self.prepare()
        target = self.dirs["conf"] / filename
        target.write_text(text, encoding="utf-8")
        self.conf_path = target
        return target

    def test(self) -> tuple[bool, str]:
        assert self.conf_path is not None
        code, out = run_capture([str(self.install.sbin), "-c", str(self.conf_path), "-t"])
        return code == 0, out.strip()

    # -- 生命周期 --
    def start(self) -> int:
        assert self.conf_path is not None
        ok, out = self.test()
        if not ok:
            raise RuntimeError(f"nginx 配置校验失败: {out}")
        code, out = run_capture([str(self.install.sbin), "-c", str(self.conf_path)])
        if code != 0:
            raise RuntimeError(f"nginx 启动失败: {out}")
        self._started_at = time.time()
        deadline = time.time() + 10
        while time.time() < deadline and self._pid is None:
            self._pid = self.pid()
            time.sleep(0.05)
        return self._pid or 0

    def stop(self) -> None:
        if self.conf_path is None:
            return
        run_capture([str(self.install.sbin), "-c", str(self.conf_path), "-s", "stop"])
        deadline = time.time() + 5
        while time.time() < deadline and self.running:
            time.sleep(0.05)
        self._pid = None

    def reload(self) -> bool:
        if self.conf_path is None:
            return False
        code, _ = run_capture([str(self.install.sbin), "-c", str(self.conf_path), "-s", "reload"])
        return code == 0

    def pid(self) -> int | None:
        pid_file = self.base / "nginx.pid"
        try:
            text = pid_file.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if not text.isdigit():
            return None
        pid = int(text)
        return pid if Path(f"/proc/{pid}").exists() else None

    @property
    def running(self) -> bool:
        return self.pid() is not None

    # -- 观测 --
    def stub_status(self) -> dict[str, int]:
        """读取 nginx stub_status 页."""
        if not self.status_port:
            return {}
        try:
            with socket.create_connection((self.host, self.status_port), timeout=2) as sock:
                sock.sendall(b"GET /status HTTP/1.0\r\nHost: sentinel\r\n\r\n")
                chunks = []
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
        except OSError:
            return {}
        body = b"".join(chunks).decode("utf-8", "replace")
        tail = body.split("\r\n\r\n", 1)[-1]
        numbers = [int(n) for n in re.findall(r"\d+", tail)]
        if len(numbers) < 7:
            return {}
        return {
            "active": numbers[0],
            "accepts": numbers[1],
            "handled": numbers[2],
            "requests": numbers[3],
            "reading": numbers[4],
            "writing": numbers[5],
            "waiting": numbers[6],
        }

    def wait_ready(self, timeout: float = 10.0) -> bool:
        """等待前端端口可连接."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection((self.host, self.front_port), timeout=0.5):
                    return True
            except OSError:
                time.sleep(0.05)
        return False

    # -- 日志 --
    def tail_errors(self, on_line: Callable[[str], None], poll: float = 0.15) -> "LogTailer":
        tailer = LogTailer(self.error_log, on_line, poll=poll)
        tailer.start()
        return tailer


class LogTailer(threading.Thread):
    """增量读取日志文件 (支持截断/轮转)."""

    def __init__(self, path: Path, on_line: Callable[[str], None], poll: float = 0.15,
                 from_start: bool = False) -> None:
        super().__init__(name=f"tail-{path.name}", daemon=True)
        self.path = path
        self.on_line = on_line
        self.poll = poll
        self._stop = threading.Event()
        # 起始偏移在构造时同步确定, 避免 start() 与 run() 之间新写入的行被跳过
        self._pos = 0 if from_start else self._probe().get("size", 0)
        self._inode = self._probe().get("inode")
        self.lines = 0
        self.from_start = from_start

    def _probe(self) -> dict:
        try:
            info = self.path.stat()
        except OSError:
            return {}
        return {"size": info.st_size, "inode": info.st_ino}

    def run(self) -> None:  # pragma: no cover - 线程体
        while not self._stop.is_set():
            try:
                self._pump()
            except Exception:  # noqa: BLE001 - 日志线程不得中断
                pass
            self._stop.wait(self.poll)

    def _pump(self) -> None:
        info = self._probe()
        if not info:
            return
        size = info["size"]
        # 日志轮转 (重命名 + 新建) 会改变 inode; 截断会使 size 变小
        if info["inode"] != self._inode:
            self._inode = info["inode"]
            self._pos = 0
        if size < self._pos:
            self._pos = 0
        if size == self._pos:
            return
        with self.path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(self._pos)
            # 注意: 文本模式下 for-迭代 中调用 tell() 会抛
            # "telling position disabled by next() call", 故显式 readline().
            while True:
                line = fh.readline()
                if not line or not line.endswith("\n"):
                    break
                self._pos = fh.tell()
                self.lines += 1
                self.on_line(line.rstrip("\n"))

    def stop(self) -> None:
        self._stop.set()
        self.join(timeout=2)


# --------------------------------------------------------------------------
# nginx.conf 渲染
# --------------------------------------------------------------------------
def render_nginx_conf(
    *,
    host: NginxHost,
    backends: Sequence[BackendConfig],
    waf: WafConfig,
    http_directives: Sequence[str] = (),
    location_directives: Sequence[str] = (),
    location_off_directives: Sequence[str] = (),
    extra_locations: Sequence[str] = (),
    front_host: str | None = None,
    upstream_name: str = "sentinel_backend",
) -> str:
    """渲染完整的 nginx.conf (数据面 + WAF 引擎指令 + 负载均衡 + 限速)."""
    install = host.install
    listen_host = front_host or host.host
    lines: list[str] = [
        f"# Sentinel 自动生成 — 引擎数据面 ({host.name})",
        f"# nginx {install.version} | 模块: {', '.join(install.modules) or 'core'}",
        "worker_processes 1;",
        f"pid {host.base / 'nginx.pid'};",
        f"error_log {host.error_log} info;",
        "events { worker_connections 2048; }",
        "http {",
        f"    include {install.conf_dir / 'mime.types'};",
        "    default_type application/octet-stream;",
        "    sendfile on;",
        "    tcp_nopush on;",
        # 结构化访问日志: 供 Sentinel 回采真实数据面指标 (QPS / 延迟 / 状态码)
        "    log_format sentinel '$remote_addr|$request_method|$request_uri|$status"
        "|$body_bytes_sent|$request_time|$upstream_response_time|$upstream_addr"
        "|$http_user_agent';",
        f"    access_log {host.access_log} sentinel;",
        f"    client_body_temp_path {host.dirs['tmp'] / 'body'};",
        f"    proxy_temp_path {host.dirs['tmp'] / 'proxy'};",
        f"    fastcgi_temp_path {host.dirs['tmp'] / 'fastcgi'};",
        f"    uwsgi_temp_path {host.dirs['tmp'] / 'uwsgi'};",
        f"    scgi_temp_path {host.dirs['tmp'] / 'scgi'};",
        f"    client_max_body_size {max(1, waf.max_body_bytes // 1024)}k;",
        "",
        "    # ---- 状态页 (仅本地可见) ----",
        "    server {",
        f"        listen 127.0.0.1:{host.status_port};",
        "        access_log off;",
        "        location /status { stub_status; }",
        "        location /healthz { return 200 'ok\\n'; }",
        "    }",
        "",
        "    # ---- 负载均衡 ----",
        f"    upstream {upstream_name} {{",
    ]
    strategy = _UPSTREAM_STRATEGY.get(waf.strategy, "")
    if strategy:
        lines.append(f"        {strategy}")
    for backend in backends:
        lines.append(
            f"        server {backend.host}:{backend.port} weight={backend.weight} "
            "max_fails=3 fail_timeout=3s;"
        )
    lines += ["    }", ""]

    if waf.rate_limit_rps and waf.rate_limit_rps > 0:
        rate = max(1, int(waf.rate_limit_rps))
        lines += [
            "    # ---- 限速 (429) ----",
            f"    limit_req_zone $binary_remote_addr zone=sentinel_rl:10m rate={rate}r/s;",
            "    limit_req_status 429;",
            "",
        ]
    if waf.block_ips:
        lines += ["    # ---- IP 黑名单 ----", "    deny " + "; deny ".join(waf.block_ips) + ";", ""]

    if http_directives:
        lines += ["    # ---- WAF 引擎 ----", *(f"    {d}" for d in http_directives), ""]

    lines += [
        "    server {",
        f"        listen {listen_host}:{host.front_port};",
        "        server_name _;",
    ]
    if waf.allow_ips:
        lines += [f"        allow {ip};" for ip in waf.allow_ips]
        lines.append("        deny all;")
    lines += [
        "        location / {",
    ]
    if waf.rate_limit_rps and waf.rate_limit_rps > 0:
        lines.append(f"            limit_req zone=sentinel_rl burst={max(1, waf.rate_limit_burst or 5)} nodelay;")
    lines += [*(f"            {d}" for d in location_directives)]
    lines += [
        f"            proxy_pass http://{upstream_name};",
        "            proxy_http_version 1.1;",
        f"            proxy_set_header Host $host;",
        f"            proxy_set_header X-Real-IP $remote_addr;",
    ]
    if waf.add_x_forwarded_for:
        lines.append("            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
    lines += [
        "            proxy_set_header X-Forwarded-Proto $scheme;",
        f"            proxy_connect_timeout {max(1, int(waf.backend_timeout_s))}s;",
        f"            proxy_read_timeout {max(1, int(waf.backend_timeout_s))}s;",
        "        }",
    ]
    if waf.static_assets_exempt and location_off_directives:
        lines += [
            "        # ---- 静态资源豁免 (架构图: 静态资源直接放行) ----",
            "        location ~* \\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)$ {",
            *(f"            {d}" for d in location_off_directives),
            f"            proxy_pass http://{upstream_name};",
            "            expires 1h;",
            "        }",
        ]
    # 引擎自定义 location (如 Naxsi 的 DeniedUrl) 必须位于 server 块内
    for block in extra_locations:
        for raw in block.strip("\n").splitlines():
            lines.append(f"        {raw}" if raw.strip() else "")
    lines += ["    }", "}", ""]
    return "\n".join(lines)
