"""规则变换函数测试."""
from __future__ import annotations

import pytest

from sentinel.waf.transforms import TRANSFORMS, apply_transforms


@pytest.mark.parametrize("name,value,expected", [
    ("lowercase", "AbC", "abc"),
    ("uppercase", "AbC", "ABC"),
    ("trim", "  x  ", "x"),
    ("removeNulls", "a\x00b", "ab"),
    ("compressWhitespace", " a \t\n b ", "a b"),
    ("removeComments", "a/*x*/b", "ab"),
    ("normalizePath", "a//b/./c", "a/b/c"),
    ("urlDecode", "%3Cscript%3E", "<script>"),
    ("urlDecodeUni", "%u003cscript%u003e", "<script>"),
    ("htmlEntityDecode", "&lt;script&gt;", "<script>"),
    ("htmlEntityDecode", "&#x3c;b&#x3e;", "<b>"),
    ("jsDecode", "\\x3cscript\\x3e", "<script>"),
    ("jsDecode", "\\u003cscript\\u003e", "<script>"),
    ("cssDecode", "\\3c script\\3e", "<script>"),
    ("base64Decode", "PHNjcmlwdD4=", "<script>"),
    ("hexDecode", "3c7363726970743e", "<script>"),
    ("sqlHexDecode", "SELECT 0x61646d696e", "SELECT admin"),
    ("cmdLine", 'CMD.EXE /c "dir"', "cmd.exe /c dir"),
    ("length", "abcdef", "6"),
    ("sha1", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
])
def test_transform_values(name, value, expected):
    assert TRANSFORMS[name](value) == expected


def test_unknown_transform_is_ignored():
    assert apply_transforms("abc", ["nope", "uppercase"]) == "ABC"


def test_transform_chain_order_matters():
    assert apply_transforms("%3CSCRIPT%3E", ["urlDecode", "lowercase"]) == "<script>"
    assert apply_transforms("%3CSCRIPT%3E", ["lowercase", "urlDecode"]) == "<script>"


def test_base64_invalid_input_returned_unchanged():
    assert TRANSFORMS["base64Decode"]("!!!not-base64!!!") == "!!!not-base64!!!"


def test_all_declared_transforms_callable():
    for name, func in TRANSFORMS.items():
        assert callable(func), name
        assert isinstance(func("probe"), str), name
