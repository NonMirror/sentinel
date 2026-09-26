"""配置管理模块: 数据类配置 + 载入/校验/导出 (JSON / 极简 YAML / TOML)."""
from __future__ import annotations

import json
import os
import tomllib
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from typing import Any


@dataclass
class BackendConfig:
    name: str = "app-1"
    host: str = "127.0.0.1"
    port: int = 9001
    weight: int = 1
    health_path: str = "/health"

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class WafConfig:
    enabled: bool = True
    mode: str = "block"                # block | detect | off
    anomaly_threshold: int = 5         # CRS 风格异常阈值
    block_above_threshold: bool = True
    inspect_body: bool = True
    max_body_bytes: int = 131072
    max_uri_length: int = 8192
    rate_limit_rps: float = 0.0        # 0 = 关闭
    rate_limit_burst: int = 0
    strategy: str = "round_robin"      # round_robin | least_conn | random | ip_hash
    add_x_forwarded_for: bool = True
    backend_timeout_s: float = 5.0
    health_check_interval_s: float = 3.0
    paranoia_level: int = 1            # 1..4 (OWASP CRS PL)
    allow_ips: list[str] = field(default_factory=list)
    block_ips: list[str] = field(default_factory=list)
    static_assets_exempt: bool = True
    rule_files: list[str] = field(default_factory=list)


@dataclass
class ListenerConfig:
    host: str = "127.0.0.1"
    port: int = 8080


@dataclass
class ScannerConfig:
    max_depth: int = 3
    max_urls: int = 400
    concurrency: int = 16
    timeout_s: float = 5.0
    delay_ms: float = 0.0
    user_agent: str = "Sentinel-Scanner/1.0 (+https://sentinel.local)"
    follow_redirects: bool = False
    time_based_threshold_s: float = 3.0
    oob_host: str = "127.0.0.1"
    oob_port: int = 9999
    scan_scope: str = "server"        # file | folder | server
    cookie: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    exclude_ext: list[str] = field(default_factory=list)


@dataclass
class LabConfig:
    host: str = "127.0.0.1"
    base_port: int = 9001
    instances: int = 3
    vuln_mode: bool = True


@dataclass
class TuiConfig:
    theme: str = "sentinel-dark"
    refresh_hz: float = 4.0
    vim_mode: bool = True
    audit_tail: int = 500


@dataclass
class Config:
    listener: ListenerConfig = field(default_factory=ListenerConfig)
    waf: WafConfig = field(default_factory=WafConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    lab: LabConfig = field(default_factory=LabConfig)
    tui: TuiConfig = field(default_factory=TuiConfig)
    backends: list[BackendConfig] = field(
        default_factory=lambda: [BackendConfig(name=f"app-{i}", port=9000 + i) for i in (1, 2, 3)]
    )
    audit_path: str = "reports/audit.jsonl"
    rule_dir: str = "rules"

    # ---- 序列化 ----
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())

    # ---- 反序列化 ----
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        return cls(
            listener=_build(ListenerConfig, data.get("listener")),
            waf=_build(WafConfig, data.get("waf")),
            scanner=_build(ScannerConfig, data.get("scanner")),
            lab=_build(LabConfig, data.get("lab")),
            tui=_build(TuiConfig, data.get("tui")),
            backends=[_build(BackendConfig, b) for b in data.get("backends", [])]
            or cls().backends,
            audit_path=data.get("audit_path", "reports/audit.jsonl"),
            rule_dir=data.get("rule_dir", "rules"),
        )

    @classmethod
    def load(cls, path: str) -> "Config":
        if not os.path.exists(path):
            return cls()
        if path.endswith(".toml"):
            with open(path, "rb") as fh:
                return cls.from_dict(tomllib.load(fh))
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        if path.endswith(".json"):
            return cls.from_dict(json.loads(text))
        return cls.from_dict(_mini_yaml(text))

    def validate(self) -> list[str]:
        problems: list[str] = []
        if self.waf.mode not in ("block", "detect", "off"):
            problems.append(f"waf.mode 非法: {self.waf.mode}")
        if self.waf.strategy not in ("round_robin", "least_conn", "random", "ip_hash"):
            problems.append(f"waf.strategy 非法: {self.waf.strategy}")
        if not 1 <= self.waf.paranoia_level <= 4:
            problems.append("waf.paranoia_level 必须在 1..4")
        if not (1 <= self.listener.port <= 65535):
            problems.append("listener.port 越界")
        if not self.backends:
            problems.append("至少需要一个后端服务")
        for backend in self.backends:
            if not (1 <= backend.port <= 65535):
                problems.append(f"后端 {backend.name} 端口越界")
        if self.scanner.concurrency < 1:
            problems.append("scanner.concurrency 必须 >= 1")
        return problems


def _build(dc_type, data: dict[str, Any] | None):
    if data is None:
        return dc_type()
    if not is_dataclass(data):
        valid = {f.name for f in fields(dc_type)}
        return dc_type(**{k: v for k, v in data.items() if k in valid})
    return data


def _mini_yaml(text: str) -> dict[str, Any]:
    """极简 YAML 子集解析 (支持两级嵌套、列表、标量), 避免额外依赖."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    pending_lists: dict[str, list[Any]] = {}
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if line.startswith("- "):
            item = line[2:].strip()
            if isinstance(parent, list):
                parent.append(_scalar(item))
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if value == "":
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
            pending_lists[key] = []
        else:
            parent[key] = _scalar(value)
    _expand_lists(root)
    return root


def _expand_lists(node: Any) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, dict):
                _expand_lists(value)


def _scalar(token: str) -> Any:
    token = token.strip().strip('"').strip("'")
    low = token.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~", ""):
        return None
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        pass
    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1].strip()
        return [] if not inner else [_scalar(p) for p in inner.split(",")]
    return token


def load_config(path: str | None = None) -> Config:
    """载入配置并抛出校验错误."""
    cfg = Config.load(path) if path else Config()
    problems = cfg.validate()
    if problems:
        raise ValueError("配置校验失败: " + "; ".join(problems))
    return cfg
