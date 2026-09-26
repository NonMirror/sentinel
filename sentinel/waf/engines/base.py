"""WAF 引擎驱动抽象层 (综设 II 轻量级防火墙的核心).

Sentinel 的检测能力不重复实现, 而是直接驱动真实的上游开源引擎:

===============  ==========================================================
引擎             上游项目 (GitHub Stars)
===============  ==========================================================
``modsecurity``  owasp-modsecurity/ModSecurity (9,784★) +
                 owasp-modsecurity/ModSecurity-nginx (1,854★) +
                 coreruleset/coreruleset (3,277★, OWASP CRS)
``naxsi``        nbs-system/naxsi (4,809★), 原生 C 语言 nginx 模块
``python``       进程内 Python 引擎 (便携回退 / 单元测试, 无 nginx 依赖)
===============  ==========================================================

真实引擎共享同一个 nginx 数据面: 由 :mod:`sentinel.waf.engines.nginx_stack`
生成配置并托管 nginx 进程, 通过 nginx error log 中的引擎事件 (ModSecurity 审计行 /
Naxsi ``NAXSI_FMT`` 行) 反向构造统一的 :class:`~sentinel.core.models.Decision`.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...core.models import Severity


# --------------------------------------------------------------------------
# 路径解析: 全部落在 ~/Projects 工作区内
# --------------------------------------------------------------------------
def sentinel_root() -> Path:
    """``~/Projects/sentinel``."""
    return Path(__file__).resolve().parents[3]


def build_root() -> Path:
    """真实 C 数据面的构建根目录 (``sentinel/build``).

    Sentinel 只依赖**自己树内**的产物: 规则与模板在 ``sentinel/vendor``,
    编译出来的 nginx 在 ``sentinel/build``。``SENTINEL_BUILD_ROOT`` 可覆盖,
    用于把构建产物放到别处 (只读源码树 / CI 缓存)。
    """
    env = os.environ.get("SENTINEL_BUILD_ROOT")
    return Path(env).expanduser() if env else sentinel_root() / "build"


def run_dir() -> Path:
    """引擎运行目录 (配置 / 日志 / 临时文件)."""
    env = os.environ.get("SENTINEL_RUN_DIR")
    base = Path(env).expanduser() if env else sentinel_root() / "reports" / "engine-run"
    return base


_RUN_DIR_RE = re.compile(r"^(?P<name>.+)-(?P<pid>\d+)-(?P<token>[0-9a-f]{8})$")


def _pid_alive(pid: int) -> bool:
    """进程是否仍然存在 (无权限时视为存活, 避免误删)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def prune_run_dirs(base: Path | None = None) -> list[Path]:
    """清理**进程已退出**的引擎运行目录, 返回被删除的目录列表.

    ``NginxEngine`` 的自动运行目录本该在 :meth:`NginxEngine.stop` 里删除,
    但进程被 ``kill`` / 超时中断时不会走到那一步, ``reports/engine-run`` 会
    持续堆积上百 MB 的 nginx.conf 与日志. 这里在引擎启动时按目录名里的
    PID 兜底回收; 存活进程 (含当前进程) 与固定名目录 (``nuclei`` 等扫描器
    工作目录) 一律保留.
    """
    root = base or run_dir()
    removed: list[Path] = []
    if not root.is_dir():
        return removed
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        match = _RUN_DIR_RE.match(child.name)
        if match is None:
            continue
        pid = int(match.group("pid"))
        if pid == os.getpid() or _pid_alive(pid):
            continue
        shutil.rmtree(child, ignore_errors=True)
        removed.append(child)
    return removed


# --------------------------------------------------------------------------
# 状态模型
# --------------------------------------------------------------------------
@dataclass(slots=True)
class EngineStatus:
    """引擎运行状态快照 (TUI / 报告 / 健康检查共用)."""

    name: str
    display: str = ""
    upstream: str = ""
    available: bool = False
    running: bool = False
    version: str = ""
    rules: int = 0
    detail: str = ""
    front_port: int | None = None
    status_port: int | None = None
    pid: int | None = None
    blocks: int = 0
    requests: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "display": self.display,
            "upstream": self.upstream,
            "available": self.available,
            "running": self.running,
            "version": self.version,
            "rules": self.rules,
            "detail": self.detail,
            "front_port": self.front_port,
            "status_port": self.status_port,
            "pid": self.pid,
            "blocks": self.blocks,
            "requests": self.requests,
            **self.extra,
        }


class EngineUnavailable(RuntimeError):
    """引擎二进制 / 模块不可用."""


@dataclass(slots=True)
class RuleView:
    """统一规则视图 (供 TUI / 报告展示真实引擎的规则库)."""

    id: int
    description: str = ""
    severity: Severity = Severity.MEDIUM
    category: str = "generic"
    action: str = "block"
    enabled: bool = True
    source: str = ""
    variables: list[str] = field(default_factory=list)
    operator: str = ""
    operator_arg: str = ""
    transforms: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    secrule: str = ""

    @property
    def weight(self) -> int:
        return self.severity.weight

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "action": self.action,
            "enabled": self.enabled,
            "source": self.source,
            "variables": list(self.variables),
            "operator": self.operator,
            "operator_arg": self.operator_arg,
            "transforms": list(self.transforms),
            "tags": list(self.tags),
            "secrule": self.secrule,
        }


# --------------------------------------------------------------------------
# 驱动基类
# --------------------------------------------------------------------------
class WafEngineDriver(ABC):
    """WAF 引擎驱动接口.

    真实引擎 (ModSecurity / Naxsi) 的 ``decide()`` 抛出 :class:`NotImplementedError`,
    因为决策发生在其自身的 C 数据面中; 决策结果通过日志回采异步进入事件总线.
    """

    name: str = "base"
    display: str = "Base"
    upstream: str = ""
    real_engine: bool = False

    @classmethod
    def available(cls) -> bool:
        """引擎在本机是否可用 (二进制 / 模块已构建)."""
        return False

    @abstractmethod
    def start(self) -> None:
        """启动引擎数据面."""

    @abstractmethod
    def stop(self) -> None:
        """停止引擎并释放端口."""

    def reload(self) -> None:
        """热重载规则 / 配置 (默认等价于重启)."""
        self.stop()
        self.start()

    @abstractmethod
    def status(self) -> EngineStatus:
        """返回状态快照."""

    def decide(self, request):  # noqa: ANN001, ANN201
        raise NotImplementedError(f"{self.name} 引擎在进程外决策, 请订阅决策事件流")

    def rules_summary(self) -> dict:
        """规则的分类统计 (供 TUI / 报告)."""
        return {}

    def rule_index(self) -> list[RuleView]:
        """规则清单 (默认空; 真实引擎解析自身规则文件)."""
        return []

    @property
    def front_port(self) -> int | None:
        return self.status().front_port


def which_any(*names: str) -> str | None:
    """在 PATH 中查找任一可执行文件."""
    from shutil import which

    for name in names:
        found = which(name)
        if found:
            return found
    return None


def run_capture(argv: list[str], timeout: float = 10.0) -> tuple[int, str]:
    """执行命令并捕获输出 (失败不抛出)."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        return 1, str(exc)
