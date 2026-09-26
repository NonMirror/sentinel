"""模板引擎: 模板选择、并发调度与统计.

「模板 x 目标」是一个天然可并行的笛卡尔积, 而每个单元都以网络等待为主,
所以用线程池并行 —— 这与内置扫描器的串行模型不同, 也是模板引擎能把
上千条模板跑完的原因。

并发度刻意保守 (默认 8): 靶场 / 内网目标是本项目的常态, 打满线程只会让
目标端的 backlog 溢出, 反而把结果变得不可复现。
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from ...core.models import Finding
from ..client import HttpClient
from .model import Template, TemplateLoader
from .runner import TemplateRunner, TargetVars

#: 非深度扫描默认选取的官方面 (与旧版 nuclei 命令行参数一致, 保证可比性)
DEFAULT_SUBSETS = ("http/misconfiguration", "http/exposures")
#: 深度扫描额外纳入的目录
DEEP_SUBSETS = ("http/vulnerabilities", "http/exposed-panels", "http/default-logins",
                "http/takeovers", "http/cves", "http/miscellaneous", "http/iot")

#: 非深度扫描的模板上限 (按严重级别从高到低截取).
#: 交互式命令要的是**几十秒内给出结论**, 不是把整个模板库跑一遍。
SHALLOW_TEMPLATE_CAP = 320


@dataclass
class TemplateScanStats:
    """一次模板扫描的统计 (供 TUI / 报告 / 基准)."""

    templates: int = 0
    requests: int = 0
    matched: int = 0
    errors: int = 0
    targets: int = 0
    #: 被响应缓存挡掉的重复请求数 (模板间大量重叠)
    cache_hits: int = 0
    #: 因指向外部主机而被跳过的请求数 (模板里写死的 SSRF/OAST 探测)
    blocked_external: int = 0
    warnings: list[str] = field(default_factory=list)
    seconds: float = 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            "templates": self.templates, "requests": self.requests,
            "matched": self.matched, "errors": self.errors,
            "targets": self.targets, "cache_hits": self.cache_hits,
            "blocked_external": self.blocked_external,
            "seconds": round(self.seconds, 3),
            "warnings": len(self.warnings),
        }


class TemplateEngine:
    """执行 nuclei 模板的引擎."""

    def __init__(self, roots: Sequence[Path | str] | None = None, *,
                 subset: Sequence[str] = (),
                 cache_dir: Path | None = None, workers: int = 8,
                 max_requests: int = 4096, allow_external: bool = False) -> None:
        self.roots = [Path(r) for r in (roots or [])]
        self.subset = tuple(subset)
        self.workers = max(1, int(workers))
        self.max_requests = int(max_requests)
        #: 是否放行模板里写死的外部主机 (默认否; 只扫本次目标)
        self.allow_external = bool(allow_external)
        self.loader = TemplateLoader(self.roots, cache_dir=cache_dir)
        self.stats = TemplateScanStats()
        self._lock = threading.Lock()
        self._last_selection: list[str] = []

    # ------------------------------------------------------------------
    # 模板选择
    # ------------------------------------------------------------------
    def select(self, *, deep: bool = False, limit: int | None = None) -> list[str]:
        """挑选要执行的模板 id.

        两类模板区别对待:

        * **官方模板树** —— 只取 ``subset``/深度开关覆盖的子目录 (1.1 万条全跑
          一遍在靶场上要十几分钟), 且**只有它们**受 ``limit`` 约束;
        * **非官方树** (Sentinel 自研靶场模板) —— 无条件参与, 且不占 ``limit``
          名额。

        后者很关键: 官方树里有 4,000+ 条 critical/high 模板, 按严重级别截断时
        会把自研靶场模板整批挤出去 —— 而它们恰恰是为这批目标写的, 是命中率
        最高的一批。**限额只用于削官方库的尾部。**
        """
        entries = self.loader.entries
        wanted = list(self.subset) + (list(DEEP_SUBSETS) if deep else [])

        local: list[str] = []
        official: list[str] = []
        for template_id, entry in entries.items():
            if _in_official_tree(entry.path):
                if _in_subsets(entry.path, wanted):
                    official.append(template_id)
            else:
                local.append(template_id)

        by_severity = lambda t: entries[t].severity.weight      # noqa: E731
        official.sort(key=by_severity, reverse=True)
        if limit and len(official) > limit:
            official = official[:limit]
        selected = local + official
        selected.sort(key=by_severity, reverse=True)
        self._last_selection = selected
        return selected

    def selection_summary(self, *, deep: bool = False) -> dict[str, object]:
        """本轮实际会执行的模板概览.

        必须和 :meth:`scan` 用**同一套限额**, 否则 TUI 会显示一个不会发生的
        数字 (「选中 1696 条」而实际只跑 320 条)。
        """
        limit = None if deep else SHALLOW_TEMPLATE_CAP
        ids = self.select(deep=deep, limit=limit)
        by_severity: dict[str, int] = {}
        for template_id in ids:
            entry = self.loader.entries[template_id]
            by_severity[entry.severity.value] = by_severity.get(entry.severity.value, 0) + 1
        return {"count": len(ids), "by_severity": by_severity,
                "limit": limit, "available": len(self.loader.entries),
                "roots": [str(r) for r in self.roots]}

    # ------------------------------------------------------------------
    # 扫描
    # ------------------------------------------------------------------
    def scan(self, targets: Sequence[str], *, deep: bool = False,
             timeout_s: float = 240.0, limit: int | None = None,
             client: HttpClient | None = None) -> list[Finding]:
        """在目标列表上执行模板.

        ``limit`` 缺省时, 非深度扫描会套用 :data:`SHALLOW_TEMPLATE_CAP` ——
        模板数 x 目标数是请求总量, 而 TUI 的 ``:scanall`` 是**交互式**命令:
        1,696 条模板 x 36 个目标 = 6 万次请求, 在靶场上要跑十几分钟。
        深度扫描 (``:scanall!`` / ``mise run bench``) 不受此限制。
        """
        started = time.time()
        stats = TemplateScanStats(targets=len(targets))
        findings: list[Finding] = []

        if limit is None and not deep:
            limit = SHALLOW_TEMPLATE_CAP
        template_ids = self.select(deep=deep, limit=limit)
        templates = [t for t in self.loader.load_many(template_ids)]
        stats.templates = len(templates)
        stats.warnings = list(self.loader.warnings)

        usable = [t for t in templates if _targetable(t, targets)]
        if not usable or not targets:
            self.stats = stats
            stats.seconds = time.time() - started
            return findings

        jobs = [(template, target) for template in usable for target in targets]
        # 单引擎请求预算: 模板 x 目标可能上万, 超时留有余量时提前收手
        deadline = started + timeout_s

        # 只允许访问本次扫描的目标主机 —— 官方模板里有写死外部域名的 SSRF/OAST
        # 探测, 放行会让扫描悄悄联系第三方 (见 TemplateRunner._host_allowed)
        allowed = {TargetVars.of(target).host for target in targets}
        allowed.discard("")

        def worker(index: int) -> tuple[list[Finding], TemplateRunner]:
            # 每个线程一个 HttpClient: 逐任务提交会让连接与调度开销压过收益
            runner = TemplateRunner(client or HttpClient(timeout=5.0),
                                    max_requests=self.max_requests,
                                    allowed_hosts=allowed if not self.allow_external
                                    else None)
            found: list[Finding] = []
            for template, target in _chunk(jobs, self.workers, index):
                if time.time() > deadline:
                    break
                try:
                    found.extend(runner.run(template, target))
                except Exception as exc:                    # noqa: BLE001 - 单模板失败
                    with self._lock:
                        stats.warnings.append(
                            f"{template.id}@{target}: {type(exc).__name__}: {exc}")
            return found, runner

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = [pool.submit(worker, i) for i in range(self.workers)]
            for future in as_completed(futures):
                try:
                    found, runner = future.result()
                except Exception as exc:                     # noqa: BLE001
                    stats.warnings.append(f"工作线程异常: {exc}")
                    continue
                findings.extend(found)
                stats.requests += runner.stats.requests
                stats.errors += runner.stats.errors
                stats.cache_hits += runner.cache_hits
                stats.blocked_external += runner.blocked_external

        stats.matched = len(findings)
        stats.seconds = time.time() - started
        self.stats = stats
        return findings

    def health(self) -> dict[str, object]:
        """引擎自身的健康指标 (算子/DSL 覆盖率与模板解析告警)."""
        from .expression import dsl_health
        return {
            **self.loader.summary(),
            **dsl_health(),
            "workers": self.workers,
            "last_runs": self.stats.as_dict(),
        }


# --------------------------------------------------------------------------
# 内部工具
# --------------------------------------------------------------------------
def _normalise(path: str) -> str:
    return "/" + path.replace("\\", "/").strip("/") + "/"


def _in_official_tree(path: str) -> bool:
    """是否位于官方模板树内 (``vendor/nuclei-templates/``)。"""
    return "/nuclei-templates/" in _normalise(path)


def _in_subsets(path: str, subsets: Sequence[str]) -> bool:
    if not subsets:
        return False
    normalised = _normalise(path)
    return any(f"/{name.strip('/')}/" in normalised for name in subsets)


def _targetable(template: Template, targets: Sequence[str]) -> bool:
    """模板是否可能适用于这批目标 (跳过显然无关的)."""
    if not template.blocks:
        return False
    for block in template.blocks:
        if block.path or block.raw:
            return True
    return False


def _chunk(jobs: list, parts: int, index: int) -> Iterable:
    """把任务按轮转切分给第 ``index`` 个线程 (确定性、无锁)."""
    if parts <= 1:
        return jobs
    return jobs[index::parts]
