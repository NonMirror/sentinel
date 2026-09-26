"""Sentinel 原生 SecRule 引擎 (ModSecurity 规则语言解释器).

Sentinel 不再把 OWASP CRS 交给外部 C 引擎执行, 而是用**自己的代码**解释
ModSecurity 的 SecRule 语言, 直接执行 ``sentinel/vendor/crs`` 里的真实规则:

    from sentinel.waf.secrule import SecRuleEngine

    engine = SecRuleEngine.from_paths([crs_rules_dir()])
    verdict = engine.inspect(request)

模块划分:

===============  ==========================================================
:mod:`syntax`     规则语言: 续行拼接 / 目标 / 算子 / 动作 / 链 / 标记
:mod:`variables`  事务状态与变量解析 (ARGS / REQUEST_HEADERS / TX / ...)
:mod:`transforms` ``t:`` 归一化函数 (urlDecodeUni / jsDecode / cmdLine / ...)
:mod:`operators`  ``@rx`` / ``@pm`` / ``@detectSQLi`` / ``@ge`` / ...
:mod:`engine`     事务执行: 按 phase 顺序求值, 异常评分, 处置决策
===============  ==========================================================
"""
from __future__ import annotations

from .engine import EngineVerdict, SecRuleEngine
from .syntax import Marker, Rule, RuleSet, Variable, load_ruleset

__all__ = [
    "EngineVerdict",
    "Marker",
    "Rule",
    "RuleSet",
    "SecRuleEngine",
    "Variable",
    "load_ruleset",
]
