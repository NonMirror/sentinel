"""WAF 引擎驱动层 (综设 II 轻量级防火墙).

Sentinel 有三种**原生**引擎 (进程内, 不需要任何外部二进制) 与两种
**参考**引擎 (真实 nginx C 数据面, 可选):

======================  =============  ====================================
驱动                     类型            说明
======================  =============  ====================================
``modsecurity``         原生 (默认)     Sentinel 自研 SecRule 解释器 +
                                        OWASP CRS 规则库
``naxsi``               原生            Sentinel 自研 Naxsi 评分器 +
                                        naxsi_core.rules
``python``              原生            Sentinel 内置规则集 (轻量)
``nginx-modsecurity``   参考 (可选)     真实 nginx + libmodsecurity
``nginx-naxsi``         参考 (可选)     真实 nginx + Naxsi C 模块
======================  =============  ====================================

    >>> from sentinel.waf.engines import EngineManager
    >>> manager = EngineManager(config).start()
    >>> manager.current.name       # 'modsecurity'
"""
from .base import (
    EngineStatus,
    EngineUnavailable,
    RuleView,
    WafEngineDriver,
    build_root,
    run_dir,
    sentinel_root,
)
from .manager import (
    DEFAULT_ORDER,
    ENGINE_CLASSES,
    NATIVE_ENGINES,
    REFERENCE_ENGINES,
    EngineManager,
    available_engines,
    default_engine,
    is_reference,
)
from .modsecurity import ModSecurityEngine
from .naxsi import NaxsiEngine
from .native import InProcessEngine
from .nginx_engine import NginxWafEngine
from .nginx_stack import LogTailer, NginxHost, NginxInstall, free_port, render_nginx_conf
from .python_engine import PythonEngine

__all__ = [
    "DEFAULT_ORDER",
    "ENGINE_CLASSES",
    "NATIVE_ENGINES",
    "REFERENCE_ENGINES",
    "EngineManager",
    "EngineStatus",
    "EngineUnavailable",
    "InProcessEngine",
    "LogTailer",
    "ModSecurityEngine",
    "NaxsiEngine",
    "NginxHost",
    "NginxInstall",
    "NginxWafEngine",
    "PythonEngine",
    "RuleView",
    "WafEngineDriver",
    "available_engines",
    "build_root",
    "default_engine",
    "free_port",
    "is_reference",
    "render_nginx_conf",
    "run_dir",
    "sentinel_root",
]
