"""nuclei 模板的数据模型与加载器.

Sentinel 不调用 nuclei 的 Go 二进制, 而是**自己解释 nuclei 的 YAML 模板**。
本模块定义模板的静态结构 (模板 / 请求块 / 匹配器 / 提取器) 与按需加载:

* **按需解析**: 官方模板树有 1.1 万余条, 全量 ``yaml.safe_load`` 既慢又吃内存。
  加载时先做廉价索引 (扫 ``id:`` / ``info:`` 头部), 真正要用时才解析整份文件。
* **磁盘缓存**: 索引写到 ``reports/engine-run/nuclei/index.json``, 以目录
  mtime 判断失效, 第二次启动几乎零成本。
* **宽松失败**: 单条模板的语法错误不得拖垮整次扫描, 记入 ``warnings`` 即可。
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

import yaml

from ...core.models import Severity

#: 支持的协议: 只有 http 会被执行, 其余在索引里标记但跳过
SUPPORTED_PROTOCOLS = ("http",)

_SEVERITY = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
    "low": Severity.LOW, "info": Severity.INFO, "unknown": Severity.MEDIUM,
}


def severity_of(token: object) -> Severity:
    return _SEVERITY.get(str(token).strip().lower(), Severity.MEDIUM)


# --------------------------------------------------------------------------
# 匹配器 / 提取器
# --------------------------------------------------------------------------
@dataclass(slots=True)
class Matcher:
    """一个 matcher (status / size / word / regex / binary / dsl)."""

    type: str = "word"
    part: str = "body"
    condition: str = "or"
    negative: bool = False
    name: str = ""
    internal: bool = False
    case_insensitive: bool = False
    status: tuple[int, ...] = ()
    size: tuple[int, ...] = ()
    words: tuple[str, ...] = ()
    regex: tuple[str, ...] = ()
    binary: tuple[bytes, ...] = ()
    dsl: tuple[str, ...] = ()
    encoding: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"type": self.type, "part": self.part, "condition": self.condition,
                "negative": self.negative, "name": self.name,
                "words": list(self.words)[:6], "regex": list(self.regex)[:4],
                "status": list(self.status), "size": list(self.size),
                "dsl": list(self.dsl)[:4]}


@dataclass(slots=True)
class Extractor:
    """一个 extractor (regex / kval / json / dsl)."""

    type: str = "regex"
    part: str = "body"
    name: str = ""
    group: int = 0
    internal: bool = False
    case_insensitive: bool = False
    regex: tuple[str, ...] = ()
    kval: tuple[str, ...] = ()
    json: tuple[str, ...] = ()
    dsl: tuple[str, ...] = ()
    #: 匹配后的预处理 (nuclei 的 extractor 变换)
    replace: str = ""
    #: kval 在 body 中按换行切分
    as_list: bool = False


# --------------------------------------------------------------------------
# 请求块
# --------------------------------------------------------------------------
@dataclass(slots=True)
class RawRequest:
    """``raw:`` 形式的原始请求 (含 HTTP 首行)."""

    lines: tuple[str, ...] = ()
    #: 首行之后、空行之前的头部; 空行之后是 body
    @property
    def first_line(self) -> str:
        return self.lines[0] if self.lines else ""

    def render(self) -> str:
        return "\n".join(self.lines)


@dataclass(slots=True)
class HttpBlock:
    """``http:`` 下的一个请求块."""

    method: str = "GET"
    path: tuple[str, ...] = ()
    raw: tuple[RawRequest, ...] = ()
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    payloads: dict[str, tuple[str, ...]] = field(default_factory=dict)
    attack: str = ""                      # batteringram/pitchfork/clusterbomb/sniper
    matchers: tuple[Matcher, ...] = ()
    matchers_condition: str = "or"
    extractors: tuple[Extractor, ...] = ()
    redirects: bool = False
    max_redirects: int = 10
    cookie_reuse: bool = False
    host_redirects: bool = False
    stop_at_first_match: bool = False
    req_condition: bool = False
    iterate_all: bool = False
    unsafe: bool = False
    disable_cookie: bool = False
    #: 该块声明的 ``{{var}}`` 初值 (nuclei 的 ``variables``)
    variables: dict[str, str] = field(default_factory=dict)

    @property
    def effective_attack(self) -> str:
        """nuclei 默认攻击模式: 有 payloads 且只声明一个变量时为 sniper."""
        if self.attack:
            return self.attack.lower()
        return "sniper" if len(self.payloads) <= 1 else "clusterbomb"


@dataclass(slots=True)
class Template:
    """一条 nuclei 模板."""

    id: str = ""
    name: str = ""
    severity: Severity = Severity.MEDIUM
    description: str = ""
    tags: tuple[str, ...] = ()
    author: tuple[str, ...] = ()
    reference: tuple[str, ...] = ()
    protocol: str = "http"
    blocks: tuple[HttpBlock, ...] = ()
    variables: dict[str, str] = field(default_factory=dict)
    #: ``flow:`` 声明的编排; Sentinel 只做串行执行, 仅记录以供展示
    flow: str = ""
    path: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def short_id(self) -> str:
        """去掉 Sentinel 靶场前缀后的展示名."""
        return self.id.replace("sentinel-lab-", "")

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "severity": self.severity.value,
            "tags": list(self.tags), "path": self.path,
            "requests": len(self.blocks),
            "matchers": sum(len(b.matchers) for b in self.blocks),
        }


@dataclass(slots=True)
class TemplateEntry:
    """索引条目 (未解析的模板)."""

    id: str
    name: str
    severity: Severity
    path: str
    tags: tuple[str, ...] = ()
    protocol: str = "http"


# --------------------------------------------------------------------------
# 加载
# --------------------------------------------------------------------------
class TemplateLoader:
    """模板树的索引与按需解析."""

    def __init__(self, roots: list[Path] | None = None,
                 cache_dir: Path | None = None) -> None:
        self.roots = [Path(r) for r in (roots or [])]
        self.cache_dir = cache_dir
        self.warnings: list[str] = []
        self._entries: dict[str, TemplateEntry] = {}
        self._parsed: dict[str, Template] = {}

    # ---------------- 索引 ----------------
    @property
    def entries(self) -> dict[str, TemplateEntry]:
        if not self._entries:
            self._entries = self._build_index()
        return self._entries

    def paths(self) -> list[str]:
        return sorted(self.entries)

    def summary(self) -> dict[str, object]:
        counts: dict[str, int] = {}
        for entry in self.entries.values():
            counts[entry.severity.value] = counts.get(entry.severity.value, 0) + 1
        return {
            "roots": [str(r) for r in self.roots],
            "templates": len(self.entries),
            "by_severity": counts,
            "warnings": len(self.warnings),
        }

    def _build_index(self) -> dict[str, TemplateEntry]:
        cached = self._read_cache()
        if cached is not None:
            return cached
        entries: dict[str, TemplateEntry] = {}
        for root in self.roots:
            if not root.exists():
                continue
            for path in sorted(root.rglob("*.yaml")):
                head = _read_header(path)
                if head is None:
                    continue
                template_id = head.get("id")
                if not template_id:
                    continue
                info = head.get("info") or {}
                protocol = next((p for p in SUPPORTED_PROTOCOLS if p in head), "")
                if not protocol:
                    continue
                entries[str(template_id)] = TemplateEntry(
                    id=str(template_id),
                    name=str(info.get("name", template_id)),
                    severity=severity_of(info.get("severity", "medium")),
                    path=str(path),
                    tags=_as_tags(info.get("tags")),
                    protocol=protocol,
                )
        self._write_cache(entries)
        return entries

    # ---------------- 解析 ----------------
    def load(self, template_id: str) -> Template | None:
        """解析单条模板 (失败返回 None 并记入 warnings)."""
        if template_id in self._parsed:
            return self._parsed[template_id]
        entry = self.entries.get(template_id)
        if entry is None:
            return None
        template = self._parse_file(Path(entry.path))
        if template is not None:
            self._parsed[template_id] = template
        return template

    def load_many(self, template_ids: list[str] | None = None,
                  ) -> Iterator[Template]:
        for template_id in (template_ids or self.paths()):
            template = self.load(template_id)
            if template is not None and template.blocks:
                yield template

    def _parse_file(self, path: Path) -> Template | None:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, yaml.YAMLError) as exc:
            self.warnings.append(f"{path.name}: {exc}")
            return None
        if not isinstance(data, dict) or not data.get("id"):
            return None
        info = data.get("info") or {}
        blocks: list[HttpBlock] = []
        for raw_block in data.get("http") or []:
            if not isinstance(raw_block, dict):
                continue
            try:
                blocks.append(_parse_block(raw_block))
            except Exception as exc:                     # noqa: BLE001 - 单块失败不弃整条
                self.warnings.append(f"{path.name}: 请求块解析失败 {exc}")
        return Template(
            id=str(data["id"]),
            name=str(info.get("name", data["id"])),
            severity=severity_of(info.get("severity", "medium")),
            description=str(info.get("description", "")),
            tags=_as_tags(info.get("tags")),
            author=_as_tuple(info.get("author")),
            reference=_as_tuple(info.get("reference")),
            protocol="http",
            blocks=tuple(blocks),
            variables={str(k): str(v) for k, v in (data.get("variables") or {}).items()},
            flow=str(data.get("flow", "")),
            path=str(path),
            metadata=info.get("metadata") or {},
        )

    # ---------------- 缓存 ----------------
    def _cache_path(self) -> Path | None:
        if self.cache_dir is None:
            return None
        return self.cache_dir / "index.json"

    def _cache_signature(self) -> str:
        parts = []
        for root in self.roots:
            try:
                parts.append(f"{root}:{int(root.stat().st_mtime)}")
            except OSError:
                parts.append(f"{root}:missing")
        env = os.environ.get("SENTINEL_TEMPLATE_CACHE", "")
        return "|".join(parts) + f"|v1|{env}"

    def _read_cache(self) -> dict[str, TemplateEntry] | None:
        path = self._cache_path()
        if path is None or not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if data.get("signature") != self._cache_signature():
            return None
        entries: dict[str, TemplateEntry] = {}
        for row in data.get("entries", []):
            try:
                entries[row["id"]] = TemplateEntry(
                    id=row["id"], name=row["name"],
                    severity=Severity(row["severity"]), path=row["path"],
                    tags=tuple(row.get("tags", [])), protocol=row.get("protocol", "http"))
            except (KeyError, ValueError):
                continue
        return entries or None

    def _write_cache(self, entries: dict[str, TemplateEntry]) -> None:
        path = self._cache_path()
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({
                "signature": self._cache_signature(),
                "generated_at": time.time(),
                "entries": [
                    {"id": e.id, "name": e.name, "severity": e.severity.value,
                     "path": e.path, "tags": list(e.tags), "protocol": e.protocol}
                    for e in entries.values()
                ],
            }, ensure_ascii=False), encoding="utf-8")
        except OSError:                                   # pragma: no cover
            pass


# --------------------------------------------------------------------------
# YAML -> 结构
# --------------------------------------------------------------------------
def _read_header(path: Path) -> dict | None:
    """只读文件头部的 ``id`` / ``info`` / 协议键, 避免整份解析."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            head = handle.read(4096)
    except OSError:
        return None
    if "id:" not in head or "info:" not in head:
        return None
    try:
        # 头部片段往往被截断, 补一个空映射让它可解析
        return yaml.safe_load(head) or {}
    except yaml.YAMLError:
        return None


def _as_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    return (str(value),)


def _as_tags(value: object) -> tuple[str, ...]:
    return _as_tuple(value)


def _as_str_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    return (str(value),)


def _parse_block(raw: dict) -> HttpBlock:
    headers = {str(k): str(v) for k, v in (raw.get("headers") or {}).items()}
    payloads: dict[str, tuple[str, ...]] = {}
    for name, values in (raw.get("payloads") or {}).items():
        payloads[str(name)] = _as_str_tuple(values)
    raw_requests: list[RawRequest] = []
    for item in raw.get("raw") or []:
        text = item if isinstance(item, str) else str(item)
        raw_requests.append(RawRequest(lines=tuple(text.splitlines())))
    matchers = tuple(_parse_matcher(m) for m in (raw.get("matchers") or [])
                     if isinstance(m, dict))
    extractors = tuple(_parse_extractor(e) for e in (raw.get("extractors") or [])
                       if isinstance(e, dict))
    return HttpBlock(
        method=str(raw.get("method", "GET")).upper(),
        path=_as_str_tuple(raw.get("path")),
        raw=tuple(raw_requests),
        headers=headers,
        body=str(raw.get("body", "")),
        payloads=payloads,
        attack=str(raw.get("attack", "")),
        matchers=matchers,
        matchers_condition=str(raw.get("matchers-condition", "or")).lower(),
        extractors=extractors,
        redirects=bool(raw.get("redirects", False)),
        max_redirects=int(raw.get("max-redirects", 10) or 10),
        cookie_reuse=bool(raw.get("cookie-reuse", False)),
        host_redirects=bool(raw.get("host-redirects", False)),
        stop_at_first_match=bool(raw.get("stop-at-first-match", False)),
        req_condition=bool(raw.get("req-condition", False)),
        iterate_all=bool(raw.get("iterate-all", False)),
        unsafe=bool(raw.get("unsafe", False)),
        disable_cookie=bool(raw.get("disable-cookie", False)),
        variables={str(k): str(v) for k, v in (raw.get("variables") or {}).items()},
    )


def _parse_matcher(raw: dict) -> Matcher:
    encoding = str(raw.get("encoding", "") or "")
    # nuclei 的 binary 匹配值**一律是十六进制字符串** (不论 encoding 是否显式写出),
    # 直接拿去和 bytes 比较会抛 TypeError —— 官方模板里几乎都不写 encoding: hex。
    binary = tuple(_hex_to_bytes(item) for item in _as_str_tuple(raw.get("binary")))
    return Matcher(
        type=str(raw.get("type", "word")).lower(),
        part=str(raw.get("part", "body")).lower(),
        condition=str(raw.get("condition", "or")).lower(),
        negative=bool(raw.get("negative", False)),
        name=str(raw.get("name", "")),
        internal=bool(raw.get("internal", False)),
        case_insensitive=bool(raw.get("case-insensitive", False)),
        status=tuple(int(v) for v in raw.get("status", []) if str(v).isdigit()),
        size=tuple(int(v) for v in raw.get("size", []) if str(v).lstrip("-").isdigit()),
        words=_as_str_tuple(raw.get("words")),
        regex=_as_str_tuple(raw.get("regex")),
        binary=binary,
        dsl=_as_str_tuple(raw.get("dsl")),
        encoding=encoding,
    )


def _hex_to_bytes(text: str) -> bytes:
    cleaned = text.replace(" ", "").replace("\n", "")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""


def _parse_extractor(raw: dict) -> Extractor:
    return Extractor(
        type=str(raw.get("type", "regex")).lower(),
        part=str(raw.get("part", "body")).lower(),
        name=str(raw.get("name", "")),
        group=int(raw.get("group", 0) or 0),
        internal=bool(raw.get("internal", False)),
        case_insensitive=bool(raw.get("case-insensitive", False)),
        regex=_as_str_tuple(raw.get("regex")),
        kval=_as_str_tuple(raw.get("kval")),
        json=_as_str_tuple(raw.get("json")),
        dsl=_as_str_tuple(raw.get("dsl")),
        replace=str(raw.get("replace", "") or ""),
        as_list=bool(raw.get("as-list", False)),
    )


@lru_cache(maxsize=8)
def default_loader(roots: tuple[str, ...] = ()) -> TemplateLoader:
    """按根目录缓存的加载器 (同一批根目录只建一次索引)."""
    return TemplateLoader([Path(r) for r in roots])
