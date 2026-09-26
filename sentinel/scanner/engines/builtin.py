"""内置检测器引擎: 包装 :class:`sentinel.scanner.scanner.Scanner`."""
from __future__ import annotations

from typing import Sequence

from ...core.models import Finding
from ..scanner import Scanner
from .base import EngineInfo, ScannerEngine


class BuiltinEngine(ScannerEngine):
    """Sentinel 内置检测器 (离线可用, 覆盖靶场全部漏洞类别)."""

    name = "builtin"
    display = "Sentinel 内置检测器"
    upstream = "sentinel builtin (自研, 覆盖靶场全类别 / 离线可用)"

    def __init__(self, scanner: Scanner | None = None) -> None:
        self.scanner = scanner

    @classmethod
    def available(cls) -> bool:
        return True

    def version(self) -> str:
        from ... import __version__

        return __version__

    def scan(self, targets: Sequence[str], *, deep: bool = False,
             timeout_s: float = 240.0) -> list[Finding]:
        if self.scanner is None:
            from ...core.config import ScannerConfig

            self.scanner = Scanner(ScannerConfig())
        out: list[Finding] = []
        for target in targets:
            report = self.scanner.scan(target, deep=deep)
            for finding in report.findings:
                if not finding.conn_id:
                    finding.conn_id = "builtin"
            out.extend(report.findings)
        return out

    def info(self) -> EngineInfo:
        info = super().info()
        info.detail = "靶场全类别覆盖 / 离线可用"
        return info
