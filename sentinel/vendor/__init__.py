"""第三方资产在 Sentinel 内部的位置 (:mod:`sentinel` 的唯一入口).

**这是 Sentinel 自包含的关键一环。** 过去引擎直接读 ``../waf_pro`` 与
``../digger_pro`` 两个同级工程: 目录一改名、一移动、或换台机器, WAF 与扫描器
就整体失效, 而报错往往只是一句「未找到已构建的 nginx」。

现在规则 / 模板 / 映射表都由 :file:`tools/vendor.py` 收敛进 ``sentinel/vendor/``,
逐文件 SHA-256 记在 ``MANIFEST.json``; 运行时不触碰任何同级目录::

    from sentinel.vendor import crs_rules_dir, nuclei_templates_dir

    crs_rules_dir()          # -> sentinel/vendor/crs/rules
    nuclei_templates_dir()   # -> sentinel/vendor/nuclei-templates

仍可用环境变量 ``SENTINEL_VENDOR_ROOT`` 指向别处的副本 (打包 / 只读部署)。
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

VENDOR_ROOT = Path(__file__).resolve().parent
MANIFEST_PATH = VENDOR_ROOT / "MANIFEST.json"


def vendor_root() -> Path:
    """vendor 根目录 (``SENTINEL_VENDOR_ROOT`` 可覆盖)."""
    env = os.environ.get("SENTINEL_VENDOR_ROOT")
    return Path(env).expanduser() if env else VENDOR_ROOT


def collection(name: str) -> Path:
    """某个资产集合的目录."""
    return vendor_root() / name


def crs_dir() -> Path:
    """OWASP CRS (``crs-setup.conf`` + ``rules/``)."""
    return collection("crs")


def crs_setup_conf() -> Path:
    return crs_dir() / "crs-setup.conf"


def crs_rules_dir() -> Path:
    return crs_dir() / "rules"


def naxsi_core_rules() -> Path:
    """Naxsi 核心规则 (``MainRule`` / ``CheckRule``)."""
    return collection("naxsi") / "naxsi_config" / "naxsi_core.rules"


def unicode_mapping() -> Path:
    """``t:urlDecodeUni`` / ``t:utf8toUnicode`` 的全宽字符映射表."""
    return collection("modsecurity") / "unicode.mapping"


def nuclei_templates_dir() -> Path:
    """nuclei 官方模板树 (``http/`` + ``helpers/``)."""
    return collection("nuclei-templates")


@lru_cache(maxsize=1)
def manifest() -> dict:
    """读取 ``MANIFEST.json`` (缺失时返回空清单, 不抛异常)."""
    try:
        return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"collections": [], "totals": {"collections": 0, "files": 0, "bytes": 0}}


def summary() -> dict[str, object]:
    """资产概览 (供 TUI 的引擎管理面板与报告展示)."""
    data = manifest()
    return {
        "root": str(vendor_root()),
        "collections": [
            {
                "key": item.get("key", item.get("target", "?")),
                "title": item.get("title", ""),
                "upstream": item.get("upstream", ""),
                "license": item.get("license", ""),
                "files": item.get("file_count", 0),
                "bytes": item.get("total_bytes", 0),
                "present": (vendor_root() / item.get("target", "")).exists(),
            }
            for item in data.get("collections", [])
        ],
        "totals": data.get("totals", {}),
    }


def missing() -> list[str]:
    """清单里声明但磁盘上不存在的集合 (健康检查用)."""
    return [item["key"] for item in summary()["collections"]      # type: ignore[union-attr]
            if not item["present"]]


__all__ = [
    "VENDOR_ROOT", "collection", "crs_dir", "crs_rules_dir", "crs_setup_conf",
    "manifest", "missing", "naxsi_core_rules", "nuclei_templates_dir",
    "summary", "unicode_mapping", "vendor_root",
]
