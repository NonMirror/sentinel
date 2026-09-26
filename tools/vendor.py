#!/usr/bin/env python3
"""把上游第三方资产收敛进 ``sentinel/vendor/`` (自包含).

Sentinel 曾经在运行时直接读取 ``../waf_pro`` 与 ``../digger_pro`` 两个同级工程,
一旦目录改名 / 移动 / 缺失, 引擎就整体失效。本工具把这些**数据资产**一次性
复制进 Sentinel 自己的代码树, 并生成 :file:`sentinel/vendor/MANIFEST.json`
记录来源、许可证与逐文件 SHA-256 —— 之后 Sentinel 不再依赖任何同级目录。

用法::

    python tools/vendor.py                 # 从 ../waf_pro ../digger_pro 同步
    python tools/vendor.py --check         # 只校验清单与磁盘是否一致 (CI)
    python tools/vendor.py --waf-root DIR --scanner-root DIR
    python tools/vendor.py --only crs

清单是**可复现**的: 相同输入必然产生相同 MANIFEST.json (文件按路径排序,
时间戳不参与), 因此 ``--check`` 可以在提交前发现漏同步。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

SENTINEL_ROOT = Path(__file__).resolve().parents[1]
VENDOR_ROOT = SENTINEL_ROOT / "sentinel" / "vendor"
MANIFEST_NAME = "MANIFEST.json"
MANIFEST_VERSION = 1


@dataclass(frozen=True)
class Source:
    """一个可同步的资产集合."""

    key: str
    title: str
    upstream: str
    license_name: str
    #: 相对 VENDOR_ROOT 的目标子目录
    target: str
    #: 源根目录下要复制的条目 (文件或目录), 相对 source_root
    entries: tuple[str, ...]
    #: 该集合的源根: "waf" 或 "scanner"
    origin: str
    #: 集合在源根下的子目录 (相对 source_root)
    subdir: str = ""
    notes: str = ""
    #: 需要保留的相对路径 (目录条目下的白名单 glob); 空 = 全量
    include: tuple[str, ...] = field(default_factory=tuple)


SOURCES: tuple[Source, ...] = (
    Source(
        key="crs",
        title="OWASP Core Rule Set",
        upstream="https://github.com/coreruleset/coreruleset",
        license_name="Apache-2.0",
        target="crs",
        entries=("rules", "crs-setup.conf", "LICENSE"),
        origin="waf",
        subdir="coreruleset",
        notes="Sentinel 原生 SecRule 解释器直接执行 rules/*.conf; "
              "*.data 供 @pmFromFile 使用。",
    ),
    Source(
        key="naxsi",
        title="Naxsi core rules",
        upstream="https://github.com/nbs-system/naxsi",
        license_name="GPL-3.0",
        target="naxsi",
        entries=("naxsi_config/naxsi_core.rules", "LICENSE"),
        origin="waf",
        subdir="naxsi",
        notes="Sentinel 原生评分器把 MainRule/CheckRule 编译为内部规则。",
    ),
    Source(
        key="modsecurity",
        title="ModSecurity unicode mapping",
        upstream="https://github.com/owasp-modsecurity/ModSecurity",
        license_name="Apache-2.0",
        target="modsecurity",
        entries=("unicode.mapping",),
        origin="waf",
        subdir="modsecurity",
        notes="t:urlDecodeUni / t:utf8toUnicode 的全宽映射表。",
    ),
    Source(
        key="nuclei-templates",
        title="ProjectDiscovery nuclei templates",
        upstream="https://github.com/projectdiscovery/nuclei-templates",
        license_name="MIT",
        target="nuclei-templates",
        entries=("http", "helpers", "LICENSE.md"),
        origin="scanner",
        subdir="nuclei-templates",
        include=("http/**", "helpers/**", "LICENSE.md"),
        notes="Sentinel 原生模板引擎 (sentinel.scanner.templating) 解释这些 YAML。",
    ),
)

#: 不进入清单的文件 (体积大且与运行时无关)
SKIP_NAMES = {".git", ".github", "__pycache__", ".DS_Store", "templates-checksum.txt"}
SKIP_SUFFIXES = (".pyc", ".pyo")


def _iter_files(root: Path) -> list[Path]:
    """列出 root 下全部应复制的文件 (含递归), 按 POSIX 路径排序."""
    if root.is_file():
        return [root]
    return sorted((p for p in root.rglob("*") if p.is_file() and not _skip(p)),
                  key=lambda p: p.as_posix())


def _skip(path: Path) -> bool:
    if any(part in SKIP_NAMES for part in path.parts):
        return True
    if path.name.startswith(".") or path.name.endswith(SKIP_SUFFIXES):
        return True
    return path.name in SKIP_NAMES


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_root(origin: str, waf_root: Path, scanner_root: Path) -> Path:
    """集合源根 = 工程根 + 集合子目录."""
    return waf_root if origin == "waf" else scanner_root


def collection_root(source: Source, waf_root: Path,
                    scanner_root: Path) -> Path:
    return source_root(source.origin, waf_root, scanner_root) / source.subdir


def sync_one(source: Source, waf_root: Path, scanner_root: Path,
             *, dry_run: bool = False) -> dict:
    """同步单个资产集合, 返回其清单条目."""
    root = collection_root(source, waf_root, scanner_root)
    target_dir = VENDOR_ROOT / source.target
    files: list[dict] = []
    missing: list[str] = []

    for entry in source.entries:
        src = root / entry
        if not src.exists():
            missing.append(entry)
            continue
        for path in _iter_files(src):
            rel = path.relative_to(root).as_posix()
            # 只保留白名单内的文件 (白名单以「集合根相对路径」书写)
            if source.include and not _matches(rel, source.include):
                continue
            destination = target_dir / rel
            files.append([rel, path.stat().st_size, _sha256(path)[:16]])
            if dry_run:
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)

    return {
        "key": source.key,
        "title": source.title,
        "upstream": source.upstream,
        "license": source.license_name,
        "target": source.target,
        "notes": source.notes,
        "missing_sources": sorted(missing),
        #: [相对路径, 字节数, sha256 前缀] —— 三元组比对象省一半体积
        "files": files,
        "file_count": len(files),
        "total_bytes": sum(f[1] for f in files),
    }


def _matches(rel: str, include: tuple[str, ...]) -> bool:
    from fnmatch import fnmatch

    return any(fnmatch(rel, pattern) for pattern in include)


def build_manifest(entries: list[dict], *, dry_run: bool = False) -> dict:
    return {
        "manifest_version": MANIFEST_VERSION,
        "generator": "tools/vendor.py",
        "dry_run": dry_run,
        "collections": entries,
        "totals": {
            "collections": len(entries),
            "files": sum(e["file_count"] for e in entries),
            "bytes": sum(e["total_bytes"] for e in entries),
        },
    }


def check_manifest(manifest: dict) -> list[str]:
    """校验磁盘与清单一致, 返回问题列表 (空 = 一致)."""
    problems: list[str] = []
    for collection in manifest.get("collections", []):
        target = VENDOR_ROOT / collection["target"]
        listed = {item[0] for item in collection["files"]}
        for rel, size, digest in collection["files"]:
            path = target / rel
            if not path.exists():
                problems.append(f"缺失: {collection['target']}/{rel}")
                continue
            if path.stat().st_size != size:
                problems.append(f"大小不符: {collection['target']}/{rel}")
            elif not _sha256(path).startswith(digest):
                problems.append(f"校验和不符: {collection['target']}/{rel}")
        if target.exists():
            for path in target.rglob("*"):
                if path.is_file() and path.relative_to(target).as_posix() not in listed:
                    problems.append(
                        f"清单外文件: {collection['target']}/"
                        f"{path.relative_to(target).as_posix()}")
    return problems


def write_readme(manifest: dict) -> None:
    lines = [
        "# sentinel/vendor — 第三方资产 (自包含)",
        "",
        "> 本目录由 `python tools/vendor.py` 生成, **请勿手工修改**。",
        "> 逐文件 SHA-256 见 `MANIFEST.json`; `python tools/vendor.py --check` 校验。",
        "",
        "Sentinel 的运行时不读取任何同级工程目录: 规则、模板、映射表全部在此。",
        "",
        "| 集合 | 上游 | 许可证 | 文件 | 体积 |",
        "| --- | --- | --- | ---: | ---: |",
    ]
    for collection in manifest["collections"]:
        size = collection["total_bytes"] / 1024 / 1024
        lines.append(
            f"| `{collection['target']}` | {collection['upstream']} | "
            f"{collection['license']} | {collection['file_count']} | {size:.1f} MiB |")
    totals = manifest["totals"]
    lines += [
        "",
        f"合计 **{totals['files']}** 个文件 / "
        f"**{totals['bytes'] / 1024 / 1024:.1f} MiB**。",
        "",
        "## 各集合说明",
        "",
    ]
    for collection in manifest["collections"]:
        lines += [
            f"### `{collection['target']}` — {collection['title']}",
            "",
            f"- 上游: {collection['upstream']}",
            f"- 许可证: {collection['license']}",
        ]
        if collection["notes"]:
            lines.append(f"- 用途: {collection['notes']}")
        if collection["missing_sources"]:
            lines.append(
                "- ⚠ 同步时缺失的源条目: "
                + ", ".join(f"`{m}`" for m in collection["missing_sources"]))
        lines.append("")
    (VENDOR_ROOT / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--waf-root", default=os.environ.get("SENTINEL_WAF_ROOT")
                        or str(SENTINEL_ROOT.parent / "waf_pro"))
    parser.add_argument("--scanner-root", default=os.environ.get("SENTINEL_SCANNER_ROOT")
                        or str(SENTINEL_ROOT.parent / "digger_pro"))
    parser.add_argument("--only", action="append", default=None,
                        help="只同步指定集合 (可重复)")
    parser.add_argument("--check", action="store_true",
                        help="只校验现有清单与磁盘, 不写入")
    parser.add_argument("--dry-run", action="store_true", help="只统计, 不复制")
    args = parser.parse_args(argv)

    manifest_path = VENDOR_ROOT / MANIFEST_NAME

    if args.check:
        if not manifest_path.exists():
            print(f"✗ 未找到 {manifest_path}", file=sys.stderr)
            return 2
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        problems = check_manifest(manifest)
        if problems:
            for problem in problems[:40]:
                print(f"✗ {problem}", file=sys.stderr)
            print(f"✗ 共 {len(problems)} 处不一致", file=sys.stderr)
            return 1
        totals = manifest["totals"]
        print(f"✓ vendor 一致: {totals['collections']} 个集合 / {totals['files']} 个文件")
        return 0

    waf_root = Path(args.waf_root).expanduser()
    scanner_root = Path(args.scanner_root).expanduser()
    selected = [s for s in SOURCES if not args.only or s.key in args.only]
    if not selected:
        print("✗ --only 未匹配任何集合", file=sys.stderr)
        return 2

    entries: list[dict] = []
    for source in selected:
        root = collection_root(source, waf_root, scanner_root)
        if not root.exists():
            print(f"✗ 源根不存在: {root} (集合 {source.key})", file=sys.stderr)
            return 2
        entry = sync_one(source, waf_root, scanner_root, dry_run=args.dry_run)
        marker = "!" if entry["missing_sources"] else "✓"
        print(f"{marker} {source.key:<18} {entry['file_count']:>6} 文件 "
              f"{entry['total_bytes'] / 1024 / 1024:>7.1f} MiB -> vendor/{source.target}")
        for missing in entry["missing_sources"]:
            print(f"    ⚠ 源条目缺失: {missing}")
        entries.append(entry)

    if args.dry_run:
        total = sum(e["total_bytes"] for e in entries)
        print(f"→ dry-run 合计 {sum(e['file_count'] for e in entries)} 文件 / "
              f"{total / 1024 / 1024:.1f} MiB (未写入)")
        return 0

    if args.only and manifest_path.exists():
        # 部分同步: 合并进既有清单, 保持其余集合不变
        previous = json.loads(manifest_path.read_text(encoding="utf-8"))
        kept = [c for c in previous["collections"] if c["key"] not in args.only]
        entries = sorted(kept + entries, key=lambda c: c["key"])

    manifest = build_manifest(entries)
    VENDOR_ROOT.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=False, ensure_ascii=False) + "\n",
        encoding="utf-8")
    write_readme(manifest)
    totals = manifest["totals"]
    print(f"✓ vendor 已同步: {totals['collections']} 个集合 / {totals['files']} 个文件 / "
          f"{totals['bytes'] / 1024 / 1024:.1f} MiB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
