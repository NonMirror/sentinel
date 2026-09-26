"""Sentinel 原生 nuclei 模板引擎.

Sentinel 不再把 YAML 模板交给 nuclei 的 Go 二进制, 而是用**自己的解释器**
执行 ``sentinel/vendor/nuclei-templates`` 里的真实模板::

    from sentinel.scanner.templating import TemplateEngine

    engine = TemplateEngine([nuclei_templates_dir(), sentinel_lab_templates()])
    findings = engine.scan(["http://127.0.0.1:8080/"], deep=False)

模块划分:

===============  ==========================================================
:mod:`model`      模板结构 + 索引/按需解析 + 磁盘缓存
:mod:`expression` ``{{...}}`` 插值与 DSL 表达式求值 (ast 白名单, 不用 eval)
:mod:`matchers`   status / size / word / regex / binary / dsl matcher 与 extractor
:mod:`runner`     载荷展开 -> 请求 -> 匹配 -> 提取 -> Finding
:mod:`engine`     模板选择、并发调度与统计
===============  ==========================================================
"""
from __future__ import annotations

from .engine import TemplateEngine, TemplateScanStats
from .expression import ResponseContext, evaluate_dsl, render
from .model import HttpBlock, Matcher, Template, TemplateLoader
from .runner import TemplateRunner, TargetVars

__all__ = [
    "HttpBlock", "Matcher", "ResponseContext", "TargetVars", "Template",
    "TemplateEngine", "TemplateLoader", "TemplateRunner", "TemplateScanStats",
    "evaluate_dsl", "render",
]
