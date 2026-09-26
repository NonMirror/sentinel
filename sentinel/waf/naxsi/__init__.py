"""Sentinel 原生 Naxsi 规则引擎.

Naxsi 的模型与 ModSecurity 完全不同, 所以单独实现而不是塞进 SecRule 解释器:

* **负向白名单 + 打分**: 没有「规则命中即拦截」, 只有 ``MainRule`` 逐条加分;
* **分区计分**: ``s:$SQL:4`` 把 4 分加进 SQL 计数器, ``CheckRule "$SQL >= 8" BLOCK``
  才是判定; 各计数器互相独立;
* **匹配面由 mz: 决定**: 同一条规则可以只看 ``ARGS|BODY``, 也可以把
  ``$HEADERS_VAR:Cookie`` 一起纳入。

规则数据取自 ``sentinel/vendor/naxsi/naxsi_config/naxsi_core.rules``
(nbs-system/naxsi, GPL-3.0)。实现在 ``syntax`` (解析) 与 ``engine`` (评分判定)。
"""
from __future__ import annotations

from .engine import NaxsiVerdict, NativeNaxsiEngine
from .syntax import CheckRule, MainRule, NaxsiRuleSet, load_naxsi_rules

__all__ = [
    "CheckRule", "MainRule", "NativeNaxsiEngine", "NaxsiRuleSet", "NaxsiVerdict",
    "load_naxsi_rules",
]
