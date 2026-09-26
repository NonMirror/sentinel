"""多引擎漏洞扫描驱动层 (综设 I 漏洞扫描子系统).

三个引擎都是 Sentinel 自己的实现, 没有任何外部二进制:

* ``nuclei``  —— :mod:`sentinel.scanner.templating` 解释官方 YAML 模板;
* ``w13scan`` —— :mod:`sentinel.scanner.plugins` 的插件式主动扫描;
* ``builtin`` —— :mod:`sentinel.scanner.detectors` 的内置检测器.

    >>> from sentinel.scanner.engines import ScannerEngineManager
    >>> manager = ScannerEngineManager()
    >>> manager.available()
    {'nuclei': True, 'w13scan': True, 'builtin': True}
"""
from .base import (EngineInfo, EngineRun, ScanOutcome, ScannerEngine, dedupe,
                   engine_run_dir, severity_by_type, severity_of)
from .builtin import BuiltinEngine
from .manager import DEFAULT_ORDER, ScannerEngineManager, build_engines
from .nuclei import NucleiEngine
from .w13scan import W13ScanEngine

__all__ = [
    "BuiltinEngine",
    "DEFAULT_ORDER",
    "EngineInfo",
    "EngineRun",
    "NucleiEngine",
    "ScanOutcome",
    "ScannerEngine",
    "ScannerEngineManager",
    "W13ScanEngine",
    "build_engines",
    "dedupe",
    "engine_run_dir",
    "severity_by_type",
    "severity_of",
]
