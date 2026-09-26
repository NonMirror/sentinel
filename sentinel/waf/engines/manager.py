"""WAF 引擎管理器: 引擎探测 / 选择 / 热切换 / 状态聚合.

默认优先使用**原生**引擎 (ModSecurity 规则语言解释器 > Naxsi 评分器),
它们全部是进程内实现, 因此 Sentinel 在任何环境下都能直接启动; 真实 C
数据面作为**参考引擎**保留, 需要显式 ``:engine nginx-modsecurity`` 才会启用,
且仅在已构建时可选。
"""
from __future__ import annotations

from typing import Any

from ...core.audit import AuditLog
from ...core.config import Config
from ...core.events import EventBus, Topic
from ...core.metrics import Metrics
from .base import EngineStatus, WafEngineDriver
from .modsecurity import ModSecurityEngine
from .naxsi import NaxsiEngine
from .nginx_dataplane import NginxModSecurityEngine, NginxNaxsiEngine
from .python_engine import PythonEngine

#: 原生引擎: 进程内决策, 无外部依赖
NATIVE_ENGINES: dict[str, type[WafEngineDriver]] = {
    ModSecurityEngine.name: ModSecurityEngine,
    NaxsiEngine.name: NaxsiEngine,
    PythonEngine.name: PythonEngine,
}

#: 参考引擎: 真实 nginx C 数据面 (需 tools/build_engines.sh 预先构建)
REFERENCE_ENGINES: dict[str, type[WafEngineDriver]] = {
    NginxModSecurityEngine.name: NginxModSecurityEngine,
    NginxNaxsiEngine.name: NginxNaxsiEngine,
}

ENGINE_CLASSES: dict[str, type[WafEngineDriver]] = {
    **NATIVE_ENGINES, **REFERENCE_ENGINES,
}

#: 优先级: 规则覆盖最全 -> 轻量 -> 便携回退; 参考引擎不参与自动选择
DEFAULT_ORDER = (ModSecurityEngine.name, NaxsiEngine.name, PythonEngine.name)


def available_engines() -> dict[str, bool]:
    """探测本机各引擎可用性."""
    return {name: cls.available() for name, cls in ENGINE_CLASSES.items()}


def default_engine() -> str:
    """返回首个可用的原生引擎 (默认 modsecurity)."""
    for name in DEFAULT_ORDER:
        if ENGINE_CLASSES[name].available():
            return name
    return PythonEngine.name


def is_reference(name: str) -> bool:
    return name in REFERENCE_ENGINES


class EngineManager:
    """持有当前生效的 WAF 引擎并支持热切换."""

    def __init__(self, config: Config, *, bus: EventBus | None = None,
                 audit: AuditLog | None = None, metrics: Metrics | None = None,
                 engine: str | None = None) -> None:
        self.config = config
        self.bus = bus or EventBus()
        self.audit = audit if audit is not None else AuditLog(4096)
        self.metrics = metrics or Metrics()
        self.requested = engine or default_engine()
        self.active_name = (self.requested if self.requested in ENGINE_CLASSES
                            else PythonEngine.name)
        self.driver: WafEngineDriver = self._build(self.active_name)
        self.fallback_reason = ""
        self.running = False

    # ---------------- 构造 ----------------
    def _build(self, name: str) -> WafEngineDriver:
        cls = ENGINE_CLASSES.get(name, PythonEngine)
        return cls(self.config, bus=self.bus, audit=self.audit, metrics=self.metrics)

    # ---------------- 生命周期 ----------------
    def start(self) -> WafEngineDriver:
        """启动当前引擎, 失败时按优先级回退 (参考引擎不自动回退到)."""
        order = [self.active_name]
        if not is_reference(self.active_name):
            order += [n for n in DEFAULT_ORDER if n != self.active_name]
        last_error = ""
        for name in order:
            if name != self.active_name:
                if not ENGINE_CLASSES[name].available() and name != PythonEngine.name:
                    continue
                self.driver = self._build(name)
            try:
                self.driver.start()
            except Exception as exc:                  # noqa: BLE001 - 逐个引擎回退
                last_error = f"{name}: {exc}"
                continue
            self.active_name = name
            self.running = True
            self.fallback_reason = last_error
            self.bus.publish(Topic.LIFECYCLE, {
                "event": "engine_selected", "engine": name,
                "fallback": bool(last_error), "reason": last_error,
                "in_process": not self.is_real,
            })
            return self.driver
        raise RuntimeError(f"所有 WAF 引擎均不可用: {last_error}")

    def stop(self) -> None:
        try:
            self.driver.stop()
        except Exception:                             # noqa: BLE001 - 关闭阶段不得抛出
            pass
        self.running = False

    def reload(self) -> None:
        self.driver.reload()

    def switch(self, name: str) -> WafEngineDriver:
        """热切换引擎 (停旧启新)."""
        if name not in ENGINE_CLASSES:
            raise KeyError(f"未知引擎: {name}")
        if name == self.active_name and self.running:
            return self.driver
        self.stop()
        self.driver = self._build(name)
        self.active_name = name
        return self.start()

    # ---------------- 观测 ----------------
    @property
    def current(self) -> WafEngineDriver:
        return self.driver

    @property
    def is_real(self) -> bool:
        """是否需要进程外数据面 (仅真实 nginx 引擎为真)."""
        return bool(getattr(self.driver, "real_engine", False))

    @property
    def is_reference(self) -> bool:
        return is_reference(self.active_name)

    def statuses(self) -> list[EngineStatus]:
        out: list[EngineStatus] = []
        for name in (*DEFAULT_ORDER, *REFERENCE_ENGINES):
            if name == self.active_name:
                out.append(self.driver.status())
                continue
            cls = ENGINE_CLASSES[name]
            available = cls.available()
            if available:
                detail = "待命 (未激活)"
            elif name in REFERENCE_ENGINES:
                detail = "未构建 (运行 tools/build_engines.sh)"
            else:
                detail = "不可用 (缺少 vendor 数据)"
            out.append(EngineStatus(
                name=name, display=cls.display, upstream=cls.upstream,
                available=available, running=False, detail=detail,
                extra={"reference": name in REFERENCE_ENGINES},
            ))
        return out

    def snapshot(self) -> dict[str, Any]:
        status = self.driver.status().as_dict()
        status["requested"] = self.requested
        status["fallback_reason"] = self.fallback_reason
        return {
            "active": self.active_name,
            "running": self.running,
            "real_engine": self.is_real,
            "reference": self.is_reference,
            "requested": self.requested,
            "available": available_engines(),
            "native": list(NATIVE_ENGINES),
            "reference_engines": list(REFERENCE_ENGINES),
            "status": status,
            "engines": [s.as_dict() for s in self.statuses()],
        }
