"""共享数据模型: HTTP 报文、WAF 决策、告警与漏洞发现."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """严重级别 (与告警/漏洞报告共用)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    @classmethod
    def from_weight(cls, weight: int) -> "Severity":
        order = [cls.INFO, cls.LOW, cls.MEDIUM, cls.HIGH, cls.CRITICAL]
        return order[max(0, min(len(order) - 1, weight))]


class Verdict(str, Enum):
    """WAF 处置动作."""

    PASS = "pass"          # 放行
    LOG = "log"            # 仅记录
    BLOCK = "block"        # 拦截 (403)
    DROP = "drop"          # 直接断链
    RATE_LIMIT = "rate_limit"  # 限速/挑战
    REDIRECT = "redirect"


@dataclass(slots=True)
class HttpRequest:
    """协议解析后的请求对象."""

    method: str = "GET"
    target: str = "/"
    version: str = "HTTP/1.1"
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    remote_addr: str = "0.0.0.0"
    remote_port: int = 0
    scheme: str = "http"
    host: str = ""
    received_at: float = field(default_factory=time.time)
    # 由 parser 填充
    path: str = "/"
    query: str = ""
    raw_head: bytes = b""
    truncated: bool = False

    @property
    def uri(self) -> str:
        return self.target

    @property
    def url(self) -> str:
        host = self.host or self.headers.get("Host", "")
        if self.scheme and host:
            return f"{self.scheme}://{host}{self.target}"
        return self.target

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", self.headers.get("content-type", ""))

    @property
    def user_agent(self) -> str:
        for key, value in self.headers.items():
            if key.lower() == "user-agent":
                return value
        return ""

    def body_text(self, limit: int = 65536) -> str:
        return self.body[:limit].decode("utf-8", "replace")

    def get_header(self, name: str, default: str = "") -> str:
        low = name.lower()
        for key, value in self.headers.items():
            if key.lower() == low:
                return value
        return default


@dataclass(slots=True)
class HttpResponse:
    """上游/本地生成的响应对象."""

    status: int = 200
    reason: str = "OK"
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    backend: str = "local"
    elapsed_ms: float = 0.0

    @property
    def body_text(self) -> str:
        return self.body.decode("utf-8", "replace")


@dataclass(slots=True)
class Decision:
    """WAF 对单次请求的决策结果."""

    verdict: Verdict = Verdict.PASS
    severity: Severity = Severity.INFO
    anomaly_score: int = 0
    matched_rules: list[int] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)
    phase: int = 2
    elapsed_ms: float = 0.0
    inspect_body: bool = True

    @property
    def blocked(self) -> bool:
        return self.verdict in (Verdict.BLOCK, Verdict.DROP, Verdict.RATE_LIMIT)


@dataclass(slots=True)
class Alert:
    """入侵检测/规则命中告警."""

    rule_id: int
    message: str
    severity: Severity
    client: str
    url: str
    category: str = "waf"
    method: str = "GET"
    evidence: str = ""
    tags: tuple[str, ...] = ()
    created_at: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity.value,
            "client": self.client,
            "url": self.url,
            "method": self.method,
            "category": self.category,
            "evidence": self.evidence,
            "tags": list(self.tags),
            "created_at": self.created_at,
        }


@dataclass(slots=True)
class Finding:
    """漏洞扫描发现."""

    vuln_type: str
    url: str
    severity: Severity
    method: str = "GET"
    param: str = ""
    payload: str = ""
    evidence: str = ""
    proof: str = ""
    confidence: float = 0.8
    conn_id: str = ""
    created_at: float = field(default_factory=time.time)

    @property
    def fingerprint(self) -> str:
        return f"{self.vuln_type}|{self.url.split('?')[0]}|{self.param}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "vuln_type": self.vuln_type,
            "url": self.url,
            "severity": self.severity.value,
            "method": self.method,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
            "proof": self.proof,
            "confidence": round(self.confidence, 3),
            "created_at": self.created_at,
        }
