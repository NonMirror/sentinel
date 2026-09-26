"""Nuclei 引擎驱动 (Sentinel 原生模板解释器).

**不再调用 nuclei 的 Go 二进制。** 模板语言由
:mod:`sentinel.scanner.templating` 自己解释, 模板数据来自
``sentinel/vendor/nuclei-templates`` (由 ``tools/vendor.py`` 收敛入仓)。

设计参考 projectdiscovery/nuclei 与 nuclei-templates; 覆盖它的 HTTP 协议子集:
``method`` / ``path`` / ``raw`` / ``headers`` / ``body`` / ``payloads`` /
``attack`` / ``matchers`` (status·size·word·regex·binary·dsl) /
``extractors`` (regex·kval·json·dsl) / ``variables`` / ``{{...}}`` 插值 / DSL 函数。

扫描面与旧版命令行参数保持一致, 便于历史数据可比:
  * 恒加载 Sentinel 自研靶场模板;
  * 默认加载官方 ``http/misconfiguration`` 与 ``http/exposures``;
  * ``deep=True`` 时扩展到 ``http/vulnerabilities`` / ``exposed-panels`` /
    ``default-logins`` / ``takeovers`` / ``cves`` / ``miscellaneous`` / ``iot``.
"""
from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ...core.models import Finding
from ...vendor import nuclei_templates_dir
from ..templating.engine import DEFAULT_SUBSETS, TemplateEngine
from .base import EngineInfo, ScannerEngine, engine_run_dir, sentinel_root


class NucleiEngine(ScannerEngine):
    """以 Sentinel 自研解释器执行 nuclei 模板."""

    name = "nuclei"
    display = "Nuclei 模板引擎 (Sentinel 原生解释器)"
    upstream = ("projectdiscovery/nuclei-templates (MIT) — 模板数据; "
                "模板语言由 sentinel.scanner.templating 自行实现")

    def __init__(self, roots: Sequence[Path | str] | None = None,
                 *, workers: int = 8, allow_external: bool = False) -> None:
        self.work = engine_run_dir(self.name)
        self.roots = [Path(r) for r in (roots or self.default_roots())]
        self._engine = TemplateEngine(
            self.roots, subset=DEFAULT_SUBSETS, cache_dir=self.work,
            workers=workers, allow_external=allow_external)
        self.last_error = ""

    # ---------------- 资源 ----------------
    @staticmethod
    def default_roots() -> list[Path]:
        """官方模板树 + Sentinel 自研靶场模板."""
        official = nuclei_templates_dir()
        lab = sentinel_root() / "templates" / "nuclei"
        roots = [r for r in (official, lab) if r.exists()]
        return roots

    @staticmethod
    def lab_templates_dir() -> Path:
        return sentinel_root() / "templates" / "nuclei"

    @property
    def engine(self) -> TemplateEngine:
        return self._engine

    # ---------------- 探测 ----------------
    @classmethod
    def available(cls) -> bool:
        """纯 Python 实现: 只要有模板树就可用 (无需任何外部二进制)."""
        return any(r.exists() for r in cls.default_roots())

    def version(self) -> str:
        """解释器版本 (模板条数放在 ``detail`` 里, 避免 TUI 行溢出)."""
        return "sentinel-template-engine/1.0"

    def template_count(self) -> int:
        return len(self._engine.loader.entries)

    def info(self) -> EngineInfo:
        info = super().info()
        lab = len(list(self.lab_templates_dir().glob("*.yaml"))) \
            if self.lab_templates_dir().exists() else 0
        if info.available:
            selection = self._engine.selection_summary(deep=False)
            info.detail = (f"原生解释器 · 模板 {self.template_count()} 条 / "
                           f"靶场 {lab} 条 · 本轮选中 {selection['count']} 条")
            info.tools = {
                "templates": str(self.roots[0]) if self.roots else "",
                "official_templates": self.template_count(),
                "lab_templates": lab,
                "selected": selection["count"],
                "interpreter": "sentinel.scanner.templating",
            }
        else:
            info.detail = "未找到模板树 (请运行 tools/vendor.py)"
        return info

    # ---------------- 扫描 ----------------
    def scan(self, targets: Sequence[str], *, deep: bool = False,
             timeout_s: float = 240.0) -> list[Finding]:
        if not targets:
            return []
        if not self.roots:
            self.last_error = "未找到模板树 (请运行 tools/vendor.py)"
            return []
        self.work.mkdir(parents=True, exist_ok=True)
        findings = self._engine.scan(targets, deep=deep, timeout_s=timeout_s)
        stats = self._engine.stats
        self.last_error = "" if findings else _empty_reason(stats)
        return findings

    def health(self) -> dict[str, object]:
        """解释器与模板库的健康指标 (供 TUI 引擎面板 / 报告)."""
        return self._engine.health()

    @property
    def allow_external(self) -> bool:
        """是否放行模板中写死的外部主机.

        默认 ``False``: 只扫本次目标。官方模板里的 SSRF/OAST 探测会把请求发往
        ``169.254.169.254``、``*.oast.pro`` 等第三方地址, 对授权测试而言既是
        不可接受的副作用, 也会各卡 5 秒超时 (实测 31 条这样的请求吃掉 151 秒)。
        需要时用 ``NucleiEngine(allow_external=True)`` 显式打开。
        """
        return self._engine.allow_external

    def rules_index(self) -> list[dict]:
        """模板清单 (供 TUI 的规则/漏洞库面板浏览)."""
        from ..templating.runner import template_as_rule
        out: list[dict] = []
        for template in self._engine.loader.load_many(self._engine.select()):
            out.append(template_as_rule(template))
        return out


def _empty_reason(stats) -> str:
    """0 发现时给出可诊断的原因, 而不是静默的空报告."""
    if stats.templates == 0:
        return "没有可用模板 (模板树为空或全部被过滤)"
    if stats.requests == 0:
        return "模板均未发出请求 (目标不可达或模板无 path/raw)"
    if stats.errors and stats.errors >= stats.requests:
        return f"全部 {stats.errors} 次请求失败 (目标不可达)"
    return ""
