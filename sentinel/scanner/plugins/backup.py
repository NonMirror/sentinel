"""备份文件泄漏插件族 (移植 w13scan ``backup_file.py`` / ``backup_folder.py`` /
``backup_domain.py`` / ``db_backup``).

三个上游插件做的事高度相似 —— 按"文件 / 目录 / 域名"三种命名习惯拼出备份文件名然后
比对**文件头魔数**。这里合并成一个 :class:`BackupFile` (按文件与目录命名) 加一个
:class:`DbBackup` (数据库导出文件), 判定沿用 w13scan 的魔数表:

===========  ==========================================
``PK\\x03\\x04``  zip
``Rar!``         rar
``\\x1f\\x8b``   gzip / tar.gz / sql.gz
``-- M``         MySQL dump
``-- ph``        phpMyAdmin dump
``/*\\n N``      Navicat 导出
===========  ==========================================

只靠魔数判定 (不靠 Content-Type), 因为很多服务器给 ``.zip`` 返回的是
``application/octet-stream`` 甚至 ``text/html``。
"""
from __future__ import annotations

from urllib.parse import urlsplit

from ...core.models import Finding, Severity
from .base import A01, SCOPE_SERVER, Plugin, PluginContext, is_ip_host, register

#: 备份文件魔数 (w13scan ``_check`` 的 features 表, 用可读形式表达)
MAGIC_SIGNS: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "zip 压缩包"),
    (b"Rar!\x1a\x07", "rar 压缩包"),
    (b"\x1f\x8b\x08", "gzip 压缩流"),
    (b"-- M", "MySQL dump 导出文件"),
    (b"-- ph", "phpMyAdmin 导出文件"),
    (b"/*\n N", "Navicat 导出文件"),
    (b"-- A", "Adminer 导出文件"),
    (b"BZh9", "bzip2 压缩流"),
    (b"7z\xbc\xaf", "7z 压缩包"),
)

#: 文件级备份后缀
FILE_SUFFIXES: tuple[str, ...] = (
    ".bak", ".bak1", ".old", ".orig", ".save", ".swp", ".swo", "~", ".copy", ".tmp",
    ".rar", ".zip", ".tar.gz", ".tgz", ".7z", ".txt",
)

#: 目录 / 站点级备份文件名 (w13scan ``backup_folder.file_dic`` + ``backup_domain``)
SITE_NAMES: tuple[str, ...] = (
    "www", "web", "wwwroot", "backup", "bak", "site", "htdocs", "html",
    "log", "logs", "db", "data", "sql", "public_html", "archiv", "archive",
    "database", "dump", "release", "prod", "test", "app",
)

#: 数据库导出文件名
DB_NAMES: tuple[str, ...] = (
    "backup", "db", "database", "dump", "data", "sql", "www", "mysql", "prod",
    "app", "site", "web", "sentinel",
)

#: 数据库导出后缀
DB_SUFFIXES: tuple[str, ...] = (".sql", ".sql.gz", ".sql.zip", ".sql.bak", ".sql.rar")

#: 单个目标最多探测的目录数 (防止对大站打爆请求量)
MAX_DIRS = 12
#: 单个目标最多探测的接口数
MAX_ENDPOINTS = 24


@register
class BackupFile(Plugin):
    """备份文件泄漏 (w13scan ``backup_file`` + ``backup_folder`` + ``backup_domain``)."""

    name = "backup_file"
    title = "备份文件泄漏"
    category = "backup"
    severity = Severity.MEDIUM
    cwe = "CWE-530"
    owasp = A01
    description = "按文件/目录/域名命名习惯探测备份包, 依据压缩包魔数判定"
    scope = SCOPE_SERVER
    references = ("https://owasp.org/www-community/vulnerabilities/Backup_file",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        for url in self._candidates(ctx):
            result = ctx.raw(url)
            if result.status != 200 or not result.body:
                continue
            sign = _magic(result.body)
            if not sign:
                continue
            return [ctx.add(
                vuln_type="backup_file", url=url, method="GET", param="",
                payload=url,
                evidence=f"{sign}, {len(result.body)} 字节 "
                         f"(Content-Type: {result.content_type or '未知'})",
                severity=self.severity, confidence=0.85,
                proof=f"可直接下载备份文件 ({sign}), 泄漏源码/配置/数据")]
        return []

    def _candidates(self, ctx: PluginContext) -> list[str]:
        base = ctx.base_url.rstrip("/")
        host = urlsplit(ctx.base_url).hostname or ""
        paths: list[str] = []
        dirs = _directories(ctx)

        # 1) 目录级: /<dirname>.zip, /<dirname>.rar
        for directory in dirs:
            name = directory.rstrip("/").rsplit("/", 1)[-1]
            if name:
                paths += [f"{base}{directory}{name}.zip", f"{base}{directory}{name}.rar"]

        # 2) 站点级: 根目录下的常见备份名 + 域名同名备份 (w13scan ``backup_domain``)
        for name in SITE_NAMES:
            paths.append(f"{base}/{name}.zip")
            paths.append(f"{base}/{name}.rar")
        if host and not is_ip_host(host):
            bare = host.split(".")[0]
            for name in {bare, host}:
                paths.append(f"{base}/{name}.zip")
                paths.append(f"{base}/{name}.rar")

        # 3) 文件级: 每个接口路径加备份后缀 (w13scan ``backup_file``)
        for endpoint in list(ctx.target.endpoints)[:MAX_ENDPOINTS]:
            path = urlsplit(endpoint).path
            if path in ("", "/"):
                continue
            for suffix in FILE_SUFFIXES:
                paths.append(f"{base}{path}{suffix}")
        deduped: list[str] = []
        seen: set[str] = set()
        for url in paths:
            if url not in seen:
                seen.add(url)
                deduped.append(url)
        return deduped


@register
class DbBackup(Plugin):
    """数据库备份文件泄漏 (w13scan 的 ``db_backup`` 对应项)."""

    name = "db_backup"
    title = "数据库备份文件泄漏"
    category = "backup"
    severity = Severity.HIGH
    cwe = "CWE-530"
    owasp = A01
    description = "探测 .sql/.sql.gz 等数据库导出文件, 依据 dump 文件头与压缩魔数判定"
    scope = SCOPE_SERVER

    def run(self, ctx: PluginContext) -> list[Finding]:
        base = ctx.base_url.rstrip("/")
        paths: list[str] = []
        for directory in _directories(ctx):
            for name in DB_NAMES:
                for suffix in DB_SUFFIXES:
                    paths.append(f"{base}{directory}{name}{suffix}")
        for name in DB_NAMES:
            for suffix in DB_SUFFIXES:
                paths.append(f"{base}/{name}{suffix}")
        seen: set[str] = set()
        for url in paths:
            if url in seen:
                continue
            seen.add(url)
            result = ctx.raw(url)
            if result.status != 200 or not result.body:
                continue
            sign = _magic(result.body) or _sql_dump(result.text)
            if not sign:
                continue
            return [ctx.add(
                vuln_type="db_backup", url=url, method="GET", param="", payload=url,
                evidence=f"{sign}, {len(result.body)} 字节",
                severity=self.severity, confidence=0.9,
                proof=f"数据库导出文件可公开下载 ({sign}), 直接泄漏全量业务数据")]
        return []


def _directories(ctx: PluginContext) -> list[str]:
    """目标中发现的一级目录集合 (含根目录), 按出现顺序去重."""
    dirs = ["/"]
    for url in ctx.target.endpoints:
        path = urlsplit(url).path
        if "/" not in path.strip("/"):
            continue
        parent = path.rsplit("/", 1)[0]
        if parent and parent not in dirs:
            dirs.append(parent + "/")
    return dirs[:MAX_DIRS]


def _magic(body: bytes) -> str:
    for sign, label in MAGIC_SIGNS:
        if body.startswith(sign):
            return label
    return ""


def _sql_dump(text: str) -> str:
    """无魔数时的兜底: 正文里出现成套 SQL 导出语句."""
    head = text[:4000].upper()
    if "CREATE TABLE" in head and ("INSERT INTO" in head or "DROP TABLE" in head):
        return "SQL 导出脚本"
    return ""


__all__ = ["DB_NAMES", "DB_SUFFIXES", "FILE_SUFFIXES", "MAGIC_SIGNS", "SITE_NAMES",
           "BackupFile", "DbBackup"]
