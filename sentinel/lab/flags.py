"""漏洞靶场 Flag 定义 —— 想改 flag, 只改这一个文件.

靶场 (``sentinel.lab.server``) 里每个漏洞都对应下面 :data:`FLAGS` 中的一个键.
把对应字符串改成你想要的内容后, 靶场所有相关端点会立刻使用新值, 无需改动
``server.py``, 也无需改动扫描模板 (模板按漏洞"特征字符串"匹配, 不依赖 flag 内容).

键                漏洞                     触发/泄漏点
----------------  -----------------------  -----------------------------------------–
``sqli``          SQL 注入                 ``/search?q=1 or 1=1``, ``/product?id=1 or 1=1``
``xss_reflected`` 反射型 XSS               ``/page?name=<script>...``
``xss_stored``    存储型 XSS               ``POST /comment`` 后访问 ``/comments``
``lfi``           任意文件读取/目录穿越    ``/download?file=../vault/flag.txt``
``ssrf``          SSRF                      ``/fetch?url=file:///etc/passwd`` 或内网地址
``open_redirect`` 开放重定向               ``/go?next=http://evil.example/``
``cors``          CORS 配置错误             ``/api/user`` (带 ``Origin`` 头)
``jsonp``         JSONP 信息泄露           ``/api/jsonp?callback=cb``
``admin``         未授权访问                ``/admin``
``debug``         敏感信息泄露             ``/debug``
``api_leak``      接口报错信息泄露          ``/api/orders``

可选: 不修改源码也能覆盖某个 flag —— 设置环境变量 ``SENTINEL_FLAG_<键名大写>``,
例如 ``SENTINEL_FLAG_SQLI='FLAG{my_own}'``; 或用 ``SENTINEL_LAB_FLAGS`` 指向一个
JSON 文件 (形如 ``{"sqli": "FLAG{...}"}``) 批量覆盖。
"""
from __future__ import annotations

import json
import os

#: 每个漏洞对应的 flag。改这里就行。
FLAGS: dict[str, str] = {
    "sqli": "FLAG{lab_sql_injection_union_select}",
    "xss_reflected": "FLAG{lab_xss_reflected_script}",
    "xss_stored": "FLAG{lab_xss_stored_persisted}",
    "lfi": "FLAG{lab_path_traversal_read_any_file}",
    "ssrf": "FLAG{lab_ssrf_reach_internal_service}",
    "open_redirect": "FLAG{lab_open_redirect_anywhere}",
    "cors": "FLAG{lab_cors_reflects_any_origin}",
    "jsonp": "FLAG{lab_jsonp_token_disclosure}",
    "admin": "FLAG{lab_broken_access_control}",
    "debug": "FLAG{lab_debug_info_disclosure}",
    "api_leak": "FLAG{lab_api_error_disclosure}",
}

#: 漏洞人类可读名称 (报告/文档用途)。
VULN_NAMES: dict[str, str] = {
    "sqli": "SQL 注入",
    "xss_reflected": "反射型 XSS",
    "xss_stored": "存储型 XSS",
    "lfi": "任意文件读取 / 目录穿越",
    "ssrf": "SSRF",
    "open_redirect": "开放重定向",
    "cors": "CORS 配置错误",
    "jsonp": "JSONP 信息泄露",
    "admin": "未授权访问",
    "debug": "敏感信息泄露",
    "api_leak": "接口报错信息泄露",
}

_JSON_OVERRIDE_ENV = "SENTINEL_LAB_FLAGS"


def _load_overrides() -> dict[str, str]:
    """从 JSON 文件与环境变量读取 flag 覆盖 (可选, 用于不改源码的场景)。"""
    overrides: dict[str, str] = {}
    path = os.environ.get(_JSON_OVERRIDE_ENV)
    if path:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                overrides.update({str(k): str(v) for k, v in data.items()})
        except (OSError, ValueError):
            # 覆盖文件损坏时静默回退到源码默认值, 保证靶场仍可启动
            pass
    for key in FLAGS:
        env = os.environ.get(f"SENTINEL_FLAG_{key.upper()}")
        if env:
            overrides[key] = env
    return overrides


def flag(key: str) -> str:
    """返回某个漏洞当前的 flag (源码默认值, 可被环境变量覆盖)。"""
    return _load_overrides().get(key) or FLAGS[key]


def all_flags() -> dict[str, str]:
    """返回全部漏洞的当前 flag (含覆盖)。"""
    return {key: flag(key) for key in FLAGS}


__all__ = ["FLAGS", "VULN_NAMES", "flag", "all_flags"]
