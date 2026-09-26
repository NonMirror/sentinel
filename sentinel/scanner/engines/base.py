"""漏洞扫描引擎抽象层 (综设 I 漏洞扫描子系统).

三个引擎全部是 Sentinel 自己的实现, 没有任何外部二进制:

================  ==========================================================
引擎              实现与数据来源
================  ==========================================================
``nuclei``        sentinel.scanner.templating 解释
                  ``sentinel/vendor/nuclei-templates`` 的官方 YAML 模板
``w13scan``       sentinel.scanner.plugins 插件集 (设计参考 w13scan)
``builtin``       Sentinel 内置检测器 (靶场全类别覆盖 / 离线可用)
================  ==========================================================
"""
from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from ...core.models import Finding, Severity


def sentinel_root() -> Path:
    """``~/Projects/sentinel`` (仓根, 所有运行产物都落在它下面)."""
    return Path(__file__).resolve().parents[3]


def engine_run_dir(name: str) -> Path:
    """扫描引擎工作目录 (中间产物 / 原始报告), 落在 ``reports/engine-run`` 内."""
    env = os.environ.get("SENTINEL_RUN_DIR")
    base = Path(env).expanduser() if env else sentinel_root() / "reports" / "engine-run"
    return base / name

_SEVERITY_WORDS = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
    "unknown": Severity.MEDIUM,
}

#: 依据漏洞类型推断严重级别 (w13scan 不返回 severity)
_TYPE_SEVERITY = {
    "sqli": Severity.HIGH, "rce": Severity.CRITICAL, "cmd": Severity.CRITICAL,
    "ssrf": Severity.HIGH, "lfi": Severity.HIGH, "traversal": Severity.HIGH,
    "xxe": Severity.HIGH, "文件上传": Severity.CRITICAL,
    "xss": Severity.MEDIUM, "csrf": Severity.MEDIUM, "jsonp": Severity.MEDIUM,
    "redirect": Severity.MEDIUM, "cors": Severity.MEDIUM, "idor": Severity.HIGH,
    "info": Severity.LOW, "敏感信息": Severity.MEDIUM,
}


def severity_of(text: str) -> Severity:
    return _SEVERITY_WORDS.get(str(text).strip().lower(), Severity.MEDIUM)


def severity_by_type(vuln_type: str) -> Severity:
    key = str(vuln_type).strip().lower()
    for token, severity in _TYPE_SEVERITY.items():
        if token in key:
            return severity
    return Severity.MEDIUM


@dataclass(slots=True)
class EngineInfo:
    """扫描引擎元信息 (TUI / 报告展示)."""

    name: str
    display: str
    upstream: str
    available: bool = False
    version: str = ""
    detail: str = ""
    tools: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "display": self.display, "upstream": self.upstream,
            "available": self.available, "version": self.version,
            "detail": self.detail, **self.tools,
        }


@dataclass(slots=True)
class EngineRun:
    """单次引擎执行记录 (用于报告/基准中的可复现证据)."""

    engine: str
    ok: bool
    findings: int = 0
    seconds: float = 0.0
    error: str = ""
    targets: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine, "ok": self.ok, "findings": self.findings,
            "seconds": round(self.seconds, 3), "error": self.error,
            "targets": self.targets,
        }


@dataclass
class ScanOutcome:
    """多引擎融合扫描结果."""

    findings: list[Finding] = field(default_factory=list)
    runs: list[EngineRun] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0

    @property
    def duration_s(self) -> float:
        return self.finished_at - self.started_at

    def as_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.as_dict() for f in self.findings],
            "runs": [r.as_dict() for r in self.runs],
            "duration_s": round(self.duration_s, 3),
        }


class ScannerEngine(ABC):
    """漏洞扫描引擎驱动接口."""

    name: str = "base"
    display: str = "Base"
    upstream: str = ""
    deep_only: bool = False
    # 最近一次执行的告警 (例如空报告/模板加载异常), 供报告观测
    last_error: str = ""

    @classmethod
    def available(cls) -> bool:
        return False

    def version(self) -> str:
        return ""

    @abstractmethod
    def scan(self, targets: Sequence[str], *, deep: bool = False,
             timeout_s: float = 240.0) -> list[Finding]:
        """扫描目标列表并返回规范化漏洞发现."""

    def info(self) -> EngineInfo:
        return EngineInfo(
            name=self.name, display=self.display, upstream=self.upstream,
            available=self.available(), version=self.version(),
            detail="就绪" if self.available() else "不可用",
        )


def which(*names: str) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def dedupe(findings: Sequence[Finding]) -> list[Finding]:
    """按 (类型, 路径, 参数) 指纹去重, 保留置信度最高者."""
    best: dict[str, Finding] = {}
    for finding in findings:
        key = finding.fingerprint
        current = best.get(key)
        if current is None or finding.confidence > current.confidence:
            best[key] = finding
    return sorted(best.values(), key=lambda f: (-f.severity.weight, f.vuln_type))
