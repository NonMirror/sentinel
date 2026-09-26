"""目录遍历 / 源码仓库泄漏 / 工程文件泄漏插件族.

移植 w13scan 的 ``directory_browse.py`` (目录遍历)、``repository_leak.py``
(``.git`` / ``.svn`` / ``.bzr`` / ``.hg`` / ``CVS``) 与 ``idea.py`` (``.idea`` 工程
配置), 并补充 w13scan 未覆盖但在实战中同样常见的 ``.DS_Store`` 与 ``webpack`` 的
``.map`` 源文件泄漏。

这些插件的共同点是"只 GET 固定路径 + 匹配一个稳定的指纹字符串", 因此判定非常确定,
不存在相似度/时延这类需要调参的启发式。
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from ...core.models import Finding, Severity
from .base import (A01, A05, SCOPE_ENDPOINT, SCOPE_SERVER, Plugin, PluginContext,
                   register, snippet)

#: 目录遍历特征 (w13scan ``directory_browse.flag_list`` + 各服务器默认列表页特征)
LISTING_SIGNS: tuple[str, ...] = (
    "directory listing for",
    "<title>directory",
    "<title>index of",
    "<head><title>index of",
    "index of /",
    '<table summary="directory listing"',
    "last modified</a>",
    "[to parent directory]",
    "<h1>index of",
    'alt="[dir]"',
)

#: 单个目标最多探测的目录数
MAX_DIRS = 10


@register
class DirectoryBrowse(Plugin):
    """目录遍历 (w13scan ``directory_browse``)."""

    name = "directory_browse"
    title = "目录遍历 (目录列表暴露)"
    category = "dirlist"
    severity = Severity.MEDIUM
    cwe = "CWE-548"
    owasp = A01
    description = "探测目录是否直接列出文件清单, 依据服务器默认列表页特征判定"
    scope = SCOPE_ENDPOINT
    references = ("https://owasp.org/www-community/attacks/Directory_traversal",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        for url in [ctx.endpoint.url] + _directories(ctx)[1:]:
            result = ctx.raw(url)
            if result.status != 200 or not result.body:
                continue
            lower = result.text.lower()
            sign = next((s for s in LISTING_SIGNS if s in lower), "")
            if not sign:
                continue
            return [ctx.add(
                vuln_type="directory_browse", url=result.url, method="GET",
                param="", payload=url, evidence=snippet(result.text, sign, 60),
                severity=self.severity, confidence=0.85,
                proof=f"目录 {result.url} 直接列出文件清单 (命中 {sign!r}), "
                      f"泄漏源码与备份文件名")]
        return []


#: 仓库泄漏指纹: (类型, 探测路径, 命中正则, 证据标签).
#: ``\x00\x00\x00\x01Bud1`` 是二进制魔数, 由 :func:`_binary_hit` 单独处理。
REPO_TARGETS: tuple[tuple[str, str, str, str], ...] = (
    (".git", "/.git/config", r"repositoryformatversion", "Git 配置 repositoryformatversion"),
    (".git", "/.git/HEAD", r"ref:\s*refs/heads/", "Git HEAD 引用"),
    (".svn", "/.svn/all-wcprops", r"svn:wc:ra_dav:version-url", "SVN wcprops 版本元数据"),
    (".svn", "/.svn/entries", r"^\d{1,2}\s*\ndir\s*\n", "SVN entries 目录清单"),
    (".hg", "/.hg/requires", r"^revlogv1", "Mercurial requires 版本元数据"),
    (".bzr", "/.bzr/README", r"This\s+is\s+a\s+Bazaar", "Bazaar 仓库 README"),
    ("CVS", "/CVS/Root", r":pserver:[\s\S]*?:", "CVS Root 连接串"),
    # CVS/Eentries 形如 /filename/revision/..., 用 "文件名后紧跟版本号" 收紧误报
    ("CVS", "/CVS/Entries", r"^/[\w.-]+/\d", "CVS Entries 文件清单"),
    # w13scan 无 .DS_Store 检测, 这里补上: macOS 会泄漏目录下的真实文件名
    ("ds_store", "/.DS_Store", r"\x00\x00\x00\x01Bud1", ".DS_Store 魔数 Bud1"),
)


def _repo_scan(ctx: PluginContext, kinds: tuple[str, ...], vuln_type: str,
               title: str, severity: Severity, cwe: str) -> list[Finding]:
    """在根目录与各级目录上探测指定类型的泄漏指纹 (命中即返回)."""
    for directory in _directories(ctx):
        for kind, path, pattern, label in REPO_TARGETS:
            if kind not in kinds:
                continue
            url = ctx.base_url.rstrip("/") + directory.rstrip("/") + path
            result = ctx.raw(url)
            if result.status != 200 or not result.body:
                continue
            if not _fingerprint_hit(pattern, result.text, result.body):
                continue
            return [ctx.add(
                vuln_type=vuln_type, url=url, method="GET", param="", payload=path,
                evidence=f"{label} ({len(result.body)} 字节)",
                severity=severity, confidence=0.9,
                proof=f"{title}: {url} 可公开访问且包含版本控制元数据, "
                      f"可还原完整源码与历史提交")]
    return []


def _fingerprint_hit(pattern: str, text: str, body: bytes) -> bool:
    if pattern.startswith("\\x"):
        return _binary_hit(body, pattern)
    return re.search(pattern, text, re.I | re.S | re.M) is not None


def _binary_hit(body: bytes, pattern: str) -> bool:
    """``.DS_Store`` 这类二进制指纹: 用转义序列还原成字节再比对."""
    if pattern == r"\x00\x00\x00\x01Bud1":
        return body.startswith(b"\x00\x00\x00\x01Bud1") or b"Bud1" in body[:64]
    return False


@register
class GitLeak(Plugin):
    """``.git`` 源码泄漏 (w13scan ``repository_leak``)."""

    name = "git_leak"
    title = "Git 源码仓库泄漏"
    category = "dirlist"
    severity = Severity.HIGH
    cwe = "CWE-527"
    owasp = A05
    description = "探测 /.git/config 与 /.git/HEAD, 依据版本库元数据判定源码泄漏"
    scope = SCOPE_SERVER
    references = (
        "https://owasp.org/www-community/vulnerabilities/Unprotected_Git_Repository",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        return _repo_scan(ctx, (".git",), "git_leak", "Git 仓库泄漏",
                          self.severity, self.cwe)


@register
class SvnLeak(Plugin):
    """``.svn`` / ``.hg`` / ``.bzr`` / ``CVS`` 源码泄漏 (w13scan ``repository_leak``)."""

    name = "svn_leak"
    title = "SVN/HG/Bzr/CVS 源码泄漏"
    category = "dirlist"
    severity = Severity.HIGH
    cwe = "CWE-527"
    owasp = A05
    description = "探测 .svn/.hg/.bzr/CVS 元数据文件, 依据版本控制指纹判定源码泄漏"
    scope = SCOPE_SERVER

    def run(self, ctx: PluginContext) -> list[Finding]:
        return _repo_scan(ctx, (".svn", ".hg", ".bzr", "CVS"), "svn_leak",
                          "版本控制元数据泄漏", self.severity, self.cwe)


@register
class DsStoreLeak(Plugin):
    """``.DS_Store`` 文件泄漏 (w13scan 无对应插件, 实战常见)."""

    name = "ds_store_leak"
    title = ".DS_Store 文件泄漏"
    category = "dirlist"
    severity = Severity.LOW
    cwe = "CWE-538"
    owasp = A05
    description = "探测 macOS 的 .DS_Store, 依据文件魔数判定目录文件名泄漏"
    scope = SCOPE_SERVER

    def run(self, ctx: PluginContext) -> list[Finding]:
        return _repo_scan(ctx, ("ds_store",), "ds_store_leak", ".DS_Store 泄漏",
                          self.severity, self.cwe)


#: .idea 工程配置文件 (w13scan ``idea.py``)
IDEA_PATHS: tuple[str, ...] = (
    "/.idea/workspace.xml", "/.idea/modules.xml", "/.idea/dataSources.xml",
    "/.idea/vcs.xml",
)
#: 命中的两个条件: 是 JetBrains 配置文件, 且泄漏了工程绝对路径
IDEA_MARKERS: tuple[str, ...] = ('<component name="', '<project version=')


@register
class Idea(Plugin):
    """JetBrains ``.idea`` 工程文件泄漏 (w13scan ``idea``)."""

    name = "idea"
    title = ".idea 工程配置泄漏"
    category = "dirlist"
    severity = Severity.MEDIUM
    cwe = "CWE-538"
    owasp = A05
    description = "探测 .idea 配置文件, 依据工程结构与 $PROJECT_DIR$ 路径判定"
    scope = SCOPE_SERVER

    def run(self, ctx: PluginContext) -> list[Finding]:
        for directory in _directories(ctx):
            for path in IDEA_PATHS:
                url = ctx.base_url.rstrip("/") + directory.rstrip("/") + path
                result = ctx.raw(url)
                if result.status != 200 or not result.body:
                    continue
                marker = next((m for m in IDEA_MARKERS if m in result.text), "")
                if not marker:
                    continue
                paths = _project_paths(result.text)
                return [ctx.add(
                    vuln_type="idea", url=url, method="GET", param="", payload=path,
                    evidence=f"命中 {marker!r}; 工程路径 {paths[:5]}"
                             if paths else f"命中 {marker!r}",
                    severity=self.severity, confidence=0.85,
                    proof="IDE 工程配置可公开下载, 泄漏工程结构与服务器绝对路径")]
        return []


def _project_paths(text: str) -> list[str]:
    """从 .idea 配置里提取 ``$PROJECT_DIR$`` 之后的相对路径 (w13scan ``idea`` 逻辑)."""
    out: list[str] = []
    for chunk in text.split("$PROJECT_DIR$")[1:]:
        value = chunk.split('"')[0].split("<")[0].strip()
        if value and value not in out:
            out.append(value)
    return out


#: webpack 源文件泄漏标记 (w13scan ``webpack``)
WEBPACK_MARKER = "webpack:///"


@register
class Webpack(Plugin):
    """webpack ``.map`` 源文件泄漏 (w13scan ``webpack``)."""

    name = "webpack"
    title = "webpack 源文件泄漏"
    category = "dirlist"
    severity = Severity.LOW
    cwe = "CWE-540"
    owasp = A05
    description = "对 .js 接口追加 .map 请求, 依据 webpack:/// 标记判定源码泄漏"
    scope = SCOPE_ENDPOINT
    references = ("https://github.com/w-digital-scanner/w13scan",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        for url in _js_endpoints(ctx):
            result = ctx.raw(url + ".map")
            if result.status != 200 or WEBPACK_MARKER not in result.text:
                continue
            return [ctx.add(
                vuln_type="webpack", url=url + ".map", method="GET", param="",
                payload=url + ".map",
                evidence=snippet(result.text, WEBPACK_MARKER, 60),
                severity=self.severity, confidence=0.9,
                proof="sourcemap 可公开下载且包含 webpack:/// 原始路径, "
                      "可完整还原前端源码")]
        return []


def _js_endpoints(ctx: PluginContext) -> list[str]:
    """目标中以 ``.js`` 结尾的接口 (含当前接口)."""
    urls = []
    for url in [ctx.endpoint.url] + list(ctx.target.endpoints):
        if url.split("?")[0].lower().endswith(".js") and url not in urls:
            urls.append(url)
    return urls[:10]


def _directories(ctx: PluginContext) -> list[str]:
    """目标中出现的目录集合 (根目录在前)."""
    dirs = ["/"]
    for url in ctx.target.endpoints:
        path = urlsplit(url).path
        if "/" not in path.strip("/"):
            continue
        parent = path.rsplit("/", 1)[0]
        if parent and parent not in dirs:
            dirs.append(parent + "/")
    return dirs[:MAX_DIRS]


__all__ = ["IDEA_MARKERS", "IDEA_PATHS", "LISTING_SIGNS", "REPO_TARGETS",
           "WEBPACK_MARKER", "DirectoryBrowse", "DsStoreLeak", "GitLeak", "Idea",
           "SvnLeak", "Webpack"]
