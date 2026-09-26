"""匹配器与提取器.

匹配器回答「这个响应算命中吗」, 提取器回答「从响应里拿什么出来」。
两者共享同一套 ``part`` 取值 (body / header / all / raw / status_code /
content_length / request / response), 因此放在一起实现。

匹配器的 ``condition`` 是**每个 matcher 内部**的 (word 列表之间的 and/or),
而块级的 ``matchers-condition`` 由执行器负责组合 —— nuclei 里这两层很容易混淆。
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Any

from .expression import DslError, ResponseContext, evaluate_dsl
from .model import Extractor, Matcher

#: 单条正则的缓存上限; CRS/模板里的正则重复率很高
_REGEX_CACHE_MAX = 4096


@lru_cache(maxsize=_REGEX_CACHE_MAX)
def _compile(pattern: str, ignore_case: bool) -> re.Pattern[str] | None:
    try:
        return re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error:
        return None


def _part_text(ctx: ResponseContext, part: str) -> str:
    if part == "body":
        return ctx.body
    if part == "header":
        return ctx.all_headers
    if part == "all":
        return f"{ctx.all_headers}\n{ctx.body}"
    if part == "raw":
        return ctx.body
    if part == "request":
        return ctx.request
    if part == "response":
        return f"{ctx.all_headers}\n{ctx.body}"
    if part == "status_code":
        return str(ctx.status_code)
    if part == "content_length":
        return str(ctx.content_length)
    return ctx.body


def _part_bytes(ctx: ResponseContext, part: str) -> bytes:
    if part in ("body", "raw", "response"):
        return ctx.body_bytes
    return _part_text(ctx, part).encode("utf-8", "replace")


# --------------------------------------------------------------------------
# 匹配
# --------------------------------------------------------------------------
def match_one(matcher: Matcher, ctx: ResponseContext) -> bool:
    """单个 matcher 是否命中 (已含 ``negative`` 取反)."""
    try:
        result = _match_positive(matcher, ctx)
    except DslError:
        result = False
    return (not result) if matcher.negative else result


def _match_positive(matcher: Matcher, ctx: ResponseContext) -> bool:  # noqa: C901
    kind = matcher.type

    if kind == "status":
        return ctx.status_code in matcher.status if matcher.status else False

    if kind == "size":
        return ctx.content_length in matcher.size if matcher.size else False

    if kind == "word":
        text = _part_text(ctx, matcher.part)
        if matcher.case_insensitive:
            text = text.lower()
            words = [w.lower() for w in matcher.words]
        else:
            words = list(matcher.words)
        if not words:
            return False
        hits = [w in text for w in words]
        return all(hits) if matcher.condition == "and" else any(hits)

    if kind == "regex":
        text = _part_text(ctx, matcher.part)
        hits = []
        for pattern in matcher.regex:
            compiled = _compile(pattern, matcher.case_insensitive)
            hits.append(compiled is not None and compiled.search(text) is not None)
        if not hits:
            return False
        return all(hits) if matcher.condition == "and" else any(hits)

    if kind == "binary":
        raw = _part_bytes(ctx, matcher.part)
        if not matcher.binary:
            return False
        hits = [needle in raw for needle in matcher.binary]
        return all(hits) if matcher.condition == "and" else any(hits)

    if kind == "dsl":
        hits = []
        for expression in matcher.dsl:
            try:
                hits.append(bool(evaluate_dsl(expression, ctx)))
            except DslError:
                hits.append(False)
        if not hits:
            return False
        return all(hits) if matcher.condition == "and" else any(hits)

    # 未支持的类型 (xpath / favicon / ...) 一律视为不命中, 而不是抛错中断
    return False


def match_block(matchers: tuple[Matcher, ...], condition: str,
                ctx: ResponseContext) -> tuple[bool, list[Matcher]]:
    """按块级 ``matchers-condition`` 组合, 返回 (是否命中, 命中的匹配器).

    取反后的 matcher 若命中, 在 nuclei 里同样算「本条 matcher 通过」,
    因此这里只关心 :func:`match_one` 的布尔结果。
    """
    if not matchers:
        return False, []
    results: list[tuple[Matcher, bool]] = []
    for matcher in matchers:
        if matcher.internal:
            continue
        results.append((matcher, match_one(matcher, ctx)))
    if not results:
        return False, []
    if condition == "and":
        ok = all(hit for _m, hit in results)
    else:
        ok = any(hit for _m, hit in results)
    touched = [m for m, hit in results if hit] if ok else []
    return ok, touched


# --------------------------------------------------------------------------
# 提取
# --------------------------------------------------------------------------
def extract(extractor: Extractor, ctx: ResponseContext) -> list[str]:
    """执行一个提取器, 返回字符串结果列表."""
    try:
        return _extract_positive(extractor, ctx)
    except DslError:
        return []


def _extract_positive(extractor: Extractor, ctx: ResponseContext) -> list[str]:  # noqa: C901
    kind = extractor.type

    if kind == "regex":
        text = _part_text(ctx, extractor.part)
        out: list[str] = []
        for pattern in extractor.regex:
            compiled = _compile(pattern, extractor.case_insensitive)
            if compiled is None:
                continue
            for match in compiled.finditer(text):
                try:
                    value = match.group(extractor.group)
                except (IndexError, re.error):
                    value = match.group(0)
                if value:
                    out.append(_post(value, extractor))
        return out

    if kind == "kval":
        text = _part_text(ctx, extractor.part)
        out = []
        for key in extractor.kval:
            for line in text.splitlines():
                name, sep, value = line.partition(":")
                if sep and name.strip().lower() == key.lower():
                    out.append(_post(value.strip(), extractor))
                    if not extractor.as_list:
                        break
        return out

    if kind == "json":
        try:
            data = json.loads(_part_text(ctx, extractor.part) or "null")
        except (ValueError, TypeError):
            return []
        out = []
        for pointer in extractor.json:
            value = _json_pointer(data, pointer)
            if value is not None:
                out.append(_post(str(value), extractor))
        return out

    if kind == "dsl":
        out = []
        for expression in extractor.dsl:
            value = evaluate_dsl(expression, ctx)
            if value not in (None, "", False):
                out.append(_post(str(value), extractor))
        return out

    return []


def _json_pointer(data: Any, pointer: str) -> Any:
    """极简 JSON 取值: 支持 ``a.b`` 与 ``items.0.name`` 两种写法."""
    current = data
    for token in str(pointer).strip().lstrip(".").split("."):
        if not token:
            continue
        if isinstance(current, dict):
            if token not in current:
                return None
            current = current[token]
        elif isinstance(current, list):
            try:
                current = current[int(token)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def _post(value: str, extractor: Extractor) -> str:
    if extractor.replace:
        try:
            value = re.sub(extractor.replace, "", value)
        except re.error:
            pass
    return value
