"""Sentinel 原生主动扫描插件包.

这是 ``w13scan`` 引擎的实现体 —— 引擎本身只负责"爬站 -> 分派 -> 汇总", 全部检测逻辑
都由这里的插件承担。设计上刻意与 :mod:`sentinel.scanner.detectors` (内置检测器引擎)
保持独立: 两个引擎的插件是同名不同实现, 融合扫描时才能形成交叉验证, 而不是把同一份
代码跑两遍。

用法::

    >>> from sentinel.scanner.plugins import registry, default_plugins
    >>> len(default_plugins()) > 0
    True
    >>> registry.summary()["plugins"] >= 30
    True

新增插件只需在任意子模块里给 :class:`~sentinel.scanner.plugins.base.Plugin` 子类加上
``@register``; 模块必须在下面显式导入 (不做目录扫描, 保持导入行为可预测)。
"""
from __future__ import annotations

# 各插件家族模块 —— 导入即完成 ``@register`` 自注册, 因此这里的导入顺序不影响结果,
# 但必须**逐个列出** (不做目录扫描): 插件出现在扫描能力里应当是显式的、可审阅的。
from . import (backup, cors, crlf, csrf, deserialization, disclosure, iis, jsonp, lfi,
               panels, rce, redirect, sensitive, smuggling, sqli, ssrf, upload,
               weak_password, xss, xxe)
from .base import (PLUGIN_CATEGORIES, SCOPE_ENDPOINT, SCOPE_PARAM, SCOPE_SERVER, SCOPES,
                   Plugin, PluginContext, PluginRegistry, register, registry)


def all_plugins() -> list[Plugin]:
    """全部已注册插件 (含仅深度扫描启用的)."""
    return registry.all()


def default_plugins() -> list[Plugin]:
    """默认启用的插件 (排除 ``deep_only``)."""
    return registry.select(deep=False)


def plugin_names() -> list[str]:
    return registry.names()


__all__ = [
    "PLUGIN_CATEGORIES",
    "Plugin",
    "PluginContext",
    "PluginRegistry",
    "SCOPE_ENDPOINT",
    "SCOPE_PARAM",
    "SCOPE_SERVER",
    "SCOPES",
    "all_plugins",
    "default_plugins",
    "plugin_names",
    "register",
    "registry",
]
