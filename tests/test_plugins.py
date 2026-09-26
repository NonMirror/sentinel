"""原生主动扫描插件引擎测试.

覆盖三层:

1. **注册表自检** —— 元数据完整性、重名、分类/档位分布、``deep_only`` 语义;
2. **植入式靶场端到端** —— 本文件内置一个 :class:`PluginLabServer`, 逐个植入本仓库
   各插件要检测的漏洞形态 (含靶场没有的 RCE/XXE/SSTI/备份文件/仓库泄漏/上传/弱口令
   等), 断言插件真的**命中**而不是"返回空列表也算过";
3. **真实靶场端到端** —— 用 :class:`sentinel.lab.server.LabServer` 跑一遍, 断言实验室
   植入的漏洞被原生引擎发现。

两层合起来覆盖全部插件, ``test_every_plugin_fires_somewhere`` 会强制这一点 —— 它把
每个插件**单独**拉出来扫两层靶场, 因此任何插件被写坏 (不再命中) 或退化成桩都会让断言
失败, 而不是静默地"零发现通过"。

运行: ``.venv/bin/python -m pytest -q tests/test_plugins.py`` (约 20 秒)。
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from sentinel.core.config import ScannerConfig
from sentinel.core.models import Severity
from sentinel.lab.server import LabServer
from sentinel.scanner.client import HttpClient
from sentinel.scanner.crawler import Endpoint, Target
from sentinel.scanner.engines import ScannerEngineManager, W13ScanEngine
from sentinel.scanner.engines.w13scan import _dedupe as engine_dedupe
from sentinel.scanner.plugins import (PLUGIN_CATEGORIES, SCOPE_ENDPOINT, SCOPE_PARAM,
                                      SCOPE_SERVER, Plugin, PluginContext,
                                      all_plugins, default_plugins, plugin_names,
                                      register, registry)
from sentinel.scanner.plugins.base import (reflected_raw, similarity, with_param)


# --------------------------------------------------------------------------
# 注册表
# --------------------------------------------------------------------------
def test_registry_is_populated_and_named_uniquely():
    names = plugin_names()
    assert len(names) == len(set(names)), "插件名必须唯一"
    assert len(names) >= 30, f"插件数量明显偏少: {len(names)}"
    # w13scan 的插件命名 (引擎 --disable/--able 用的就是这些名字)
    for expected in ("sqli_error", "sqli_bool", "sqli_time", "xss", "jsonp", "ssti",
                     "unauth", "webpack", "backup_file", "directory_browse",
                     "iis_shortname", "swf_files", "http_smuggling", "errorpage",
                     "net_xss", "phpinfo", "idea", "git_leak", "svn_leak",
                     "ds_store_leak", "phpmyadmin", "spring_actuator", "swagger_ui",
                     "db_backup", "weak_password", "upload", "csrf", "crlf", "xxe",
                     "cors", "ssrf", "open_redirect", "lfi", "cmd_inject", "php_code"):
        assert expected in names, f"缺少插件 {expected}"


def test_every_plugin_has_complete_metadata():
    problems = registry.validate()
    assert problems == [], f"插件元数据缺陷: {problems}"
    for plugin in all_plugins():
        assert plugin.title and plugin.description
        assert plugin.cwe.startswith("CWE-")
        assert plugin.owasp.startswith("A") and ":" in plugin.owasp
        assert plugin.category in PLUGIN_CATEGORIES
        assert plugin.scope in (SCOPE_PARAM, SCOPE_ENDPOINT, SCOPE_SERVER)
        assert isinstance(plugin.severity, Severity)
        assert callable(plugin.run)
        # TUI / 报告展示用的元信息视图必须与声明一致
        info = plugin.info()
        assert info["name"] == plugin.name
        assert info["title"] == plugin.title
        assert info["severity"] == plugin.severity.value
        assert info["cwe"] == plugin.cwe and info["owasp"] == plugin.owasp
        assert repr(plugin).startswith("<")


def test_registry_summary_and_categories():
    summary = registry.summary()
    assert summary["plugins"] == len(all_plugins())
    assert summary["deep_only"] == len(all_plugins()) - len(default_plugins())
    cats = registry.categories()
    # 任务书要求的核心分类都要有插件
    for category in ("sqli", "xss", "rce", "lfi", "ssrf", "redirect", "crlf", "jsonp",
                     "cors", "xxe", "ssti", "info", "backup", "dirlist", "auth",
                     "upload", "csrf", "smuggling", "deserialization"):
        assert category in cats, f"缺少分类 {category}"
        assert PLUGIN_CATEGORIES[category]


def test_registry_rejects_duplicate_names():
    class Dup(Plugin):
        name = "sqli_error"
        title = "重复"
        category = "sqli"
        cwe = "CWE-89"
        owasp = "A03:2021"
        description = "重复插件"

        def run(self, ctx):  # pragma: no cover - 不应被调用
            return []

    with pytest.raises(ValueError, match="重名"):
        register(Dup)


def test_deep_only_plugins_are_the_invasive_ones():
    deep_only = {p.name for p in all_plugins() if p.deep_only}
    assert deep_only == {"sqli_time", "http_smuggling", "upload", "weak_password"}
    # 深度模式启用全部插件, 普通模式只启用非侵入式
    assert registry.select(deep=True) and len(registry.select(deep=True)) > \
        len(registry.select(deep=False))
    assert not [p for p in registry.select(deep=False) if p.deep_only]


def test_deep_flag_gates_invasive_plugins_end_to_end(plugin_lab):
    """``deep`` 必须真正控制侵入式插件 —— 普通扫描不得写入文件/爆破口令."""
    config = ScannerConfig(max_urls=20, max_depth=1, concurrency=8, timeout_s=3.0)
    engine = W13ScanEngine(config=config)
    assert not [p for p in engine.plugins(deep=False) if p.deep_only]
    assert [p for p in engine.plugins(deep=True) if p.deep_only]
    findings = engine.scan([plugin_lab.base_url + "/"], deep=False, timeout_s=90)
    assert not {f.vuln_type for f in findings} & {"upload", "brute_force", "smuggling"}


def test_registry_select_filters_by_scope_and_category():
    assert all(p.scope == SCOPE_SERVER for p in registry.select(scope=SCOPE_SERVER))
    assert all(p.category == "sqli" for p in registry.select(categories=["sqli"]))
    picked = registry.select(names=["xss"])
    assert [p.name for p in picked] == ["xss"]


def test_param_hint_matching():
    xss = registry.get("xss")
    assert xss is not None and xss.matches("name") and not xss.matches("account_no")
    generic = registry.get("deserialization")
    assert generic is not None and generic.matches("anything")

    class QueryOnly(Plugin):
        name = "query_only_test"
        title = "仅 GET 参数"
        category = "info"
        cwe = "CWE-000"
        owasp = "A01:2021"
        description = "验证 positions 声明生效"
        positions = ("query",)

        def run(self, ctx):  # pragma: no cover - 只验证选择逻辑
            return []

    plugin = QueryOnly()
    assert plugin.matches("q", "query")
    assert not plugin.matches("q", "form")


# --------------------------------------------------------------------------
# 上下文与判定辅助
# --------------------------------------------------------------------------


def _ctx(**kwargs) -> PluginContext:
    target = Target(base_url="http://lab.local/", host="lab.local")
    endpoint = Endpoint(url="http://lab.local/search", params=["q"])
    base = dict(client=HttpClient(timeout=1.0), target=target, endpoint=endpoint,
                param="q", position="query")
    base.update(kwargs)
    return PluginContext(**base)


def test_with_param_preserves_other_parameters():
    url = with_param("http://h/a?x=1&y=2", "x", "p q")
    assert "y=2" in url and "x=p%20q" in url


def test_with_param_safe_keeps_path_separators():
    url = with_param("http://h/download?file=a", "file", "../../etc/passwd", safe="/\\")
    assert "../../etc/passwd" in url


def test_reflected_raw_distinguishes_escaping():
    assert reflected_raw("<div><script>alert(1)</script></div>",
                         "<script>alert(1)</script>")
    assert not reflected_raw("<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>",
                             "<script>alert(1)</script>")
    assert not reflected_raw("<div>nothing</div>", "<script>alert(1)</script>")


def test_similarity_bounds():
    assert similarity("abc", "abc") == 1.0
    assert similarity("", "abc") == 0.0
    assert similarity("a" * 100, "b" * 100) < 0.2


def test_context_add_tags_engine_provenance():
    ctx = _ctx()
    finding = ctx.add(vuln_type="x", url="http://lab.local/search?q=1",
                      severity=Severity.LOW)
    assert finding.conn_id == "w13scan"
    assert ctx.findings == [finding]


# --------------------------------------------------------------------------
# 引擎元信息 / 健壮性
# --------------------------------------------------------------------------


def test_engine_is_native_and_truthful():
    engine = W13ScanEngine()
    assert W13ScanEngine.available() is True
    info = engine.info()
    assert info.name == "w13scan"
    assert info.available is True
    assert "w13scan" in info.display.lower() or "W13Scan" in info.display
    assert info.upstream.startswith("w-digital-scanner/w13scan")
    assert "原生" in info.display
    assert info.tools["plugins"] == len(all_plugins())
    assert "sqli" in info.tools["categories"]
    assert str(info.tools["plugins"]) in info.detail


def test_engine_module_has_no_subprocess_or_digger_paths():
    """原生引擎不该再依赖子进程 / 外部 checkout (按 AST 检查真实 import)."""
    import ast

    from sentinel.scanner.engines import w13scan as module

    source = module.__file__
    assert source is not None
    with open(source, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "subprocess" not in imported, "引擎仍 import subprocess"
    assert not hasattr(module, "subprocess")
    # 不得再引用 digger_pro checkout 的定位函数
    assert "scanner_root" not in module.__dict__
    assert "sentinel_root" not in module.__dict__
    # 上游驱动的旧属性面 (python/script 路径) 已不存在
    assert not hasattr(module.W13ScanEngine, "python")
    assert not hasattr(module.W13ScanEngine, "script")
    engine = module.W13ScanEngine()
    assert "digger_pro" not in str(engine.work)


def test_plugin_crash_does_not_abort_scan_and_sets_last_error(lab_base):
    class Boom(Plugin):
        name = "boom_test"
        title = "崩溃插件"
        category = "info"
        cwe = "CWE-000"
        owasp = "A01:2021"
        description = "故意抛异常的插件"

        def run(self, ctx):
            raise RuntimeError("插件内部崩溃")

    engine = W13ScanEngine(config=ScannerConfig(max_urls=8, max_depth=1),
                           plugins=[Boom(), registry.get("xss")])
    findings = engine.scan([lab_base + "/page?name=x"], timeout_s=60)
    assert "boom_test" in engine.last_error and "插件内部崩溃" in engine.last_error
    # 崩溃插件之外的插件照常执行 -> XSS 仍然被发现
    assert any(f.vuln_type == "xss" for f in findings)
    assert engine.stats["targets"] == 1


def test_engine_writes_w13scan_compatible_report(tmp_path, lab_base):
    engine = W13ScanEngine(tmp_path, config=ScannerConfig(max_urls=8, max_depth=1))
    engine.scan([lab_base + "/search?q=hello"], timeout_s=60)
    reports = list(tmp_path.glob("w13scan-native-*.jsonl"))
    assert reports, "引擎未落盘 JSONL 报告"
    # 报告可被自身的 parse_report 读回 (与上游 w13scan 输出同一解析入口)
    findings = W13ScanEngine.parse_report(reports[0])
    assert findings and all(f.conn_id == "w13scan" for f in findings)


def test_engine_dedupes_but_keeps_distinct_sqli_techniques():
    from sentinel.core.models import Finding

    rows = [
        Finding(vuln_type="sqli", url="http://h/s?q=1", severity=Severity.HIGH,
                param="q", payload="'"),
        Finding(vuln_type="sqli", url="http://h/s?q=1", severity=Severity.HIGH,
                param="q", payload="'"),                       # 完全重复 -> 合并
        Finding(vuln_type="sqli", url="http://h/s?q=1", severity=Severity.HIGH,
                param="q", payload="1 AND SLEEP(3)--"),        # 另一种技术 -> 保留
    ]
    assert len(engine_dedupe(rows)) == 2


def test_engine_handles_empty_and_unreachable_targets():
    engine = W13ScanEngine(config=ScannerConfig(timeout_s=0.4, max_urls=4, max_depth=1))
    assert engine.scan([]) == []
    assert engine.scan(["http://127.0.0.1:1/"]) == []
    assert engine.stats["targets"] == 1


def test_engine_publishes_progress_on_the_event_bus(lab_base):
    """与既有引擎一致: 通过 EventBus 汇报阶段进度 (供 TUI / 审计消费)."""
    from sentinel.core.events import EventBus

    bus = EventBus()
    engine = W13ScanEngine(config=ScannerConfig(max_urls=8, max_depth=1), bus=bus)
    engine.scan([lab_base + "/page?name=x"], timeout_s=60)
    phases = [event.payload["phase"] for event in bus.history("scan.progress")]
    assert "recognized" in phases
    assert "plugin_done" in phases
    assert phases[-1] == "engine_finished"
    assert all(event.payload.get("engine") == "w13scan"
               for event in bus.history("scan.progress"))


def test_manager_treats_native_engine_as_available():
    manager = ScannerEngineManager()
    assert manager.available()["w13scan"] is True
    infos = {info.name: info for info in manager.infos()}
    assert infos["w13scan"].available is True
    assert "deep_only" in infos["w13scan"].tools


# --------------------------------------------------------------------------
# 植入式靶场: 覆盖真实靶场没有的漏洞形态
# --------------------------------------------------------------------------
FLAG_FILE = "root:x:0:0:root:/root:/bin/bash\n"
FIXTURE_BOUNDARY = "----SentinelFixture9137"
#: 只允许这些命令真的执行 (其余一律返回模拟输出) —— 测试用的注入点不该变成后门
ALLOWED_COMMANDS = ("id", "whoami", "echo ")


class _FixtureApp:
    """一个"该有的漏洞都有"的最小应用, 用于验证插件的检测能力."""

    def __init__(self, name: str = "plugin-lab") -> None:
        self.name = name
        self.uploads: dict[str, bytes] = {}

    # ---------------- 路由 ----------------
    def handle(self, method: str, target: str, headers: dict[str, str],
               body: bytes) -> tuple[int, dict[str, str], bytes]:
        parts = urlsplit(target)
        path = unquote(parts.path)
        query = {k: v[0] for k, v in parse_qs(parts.query,
                                             keep_blank_values=True).items()}
        form = {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace"),
                                            keep_blank_values=True).items()}
        low_headers = {k.lower(): v for k, v in headers.items()}

        # 1) 短文件名: IIS 对 ~1 形式返回 400, 普通不存在路径返回 404
        if "~1" in path:
            return 400, {"Content-Type": "text/html"}, b"<h1>Bad Request</h1>"

        # 2) 错误页: 任意 .jsp 返回带堆栈的 500
        if path.endswith(".jsp"):
            return 500, {"Content-Type": "text/html"}, (
                "<html><body><h1>HTTP Status 500 - Internal Server Error</h1>"
                "<pre>java.lang.NullPointerException\n"
                "\tat com.sentinel.demo.UserServlet.doGet(UserServlet.java:42)\n"
                "</pre></body></html>").encode()

        handler = {
            "/": self._home,
            "/health": lambda: (200, {"Content-Type": "text/plain"}, b"ok"),
            "/robots.txt": lambda: (200, {"Content-Type": "text/plain"},
                                    b"User-agent: *\nDisallow: /admin\n"
                                    b"Disallow: /backup\n"),
            "/files/": lambda: (200, {"Content-Type": "text/html"}, _LISTING),
            "/static/app.js": lambda: (200, {"Content-Type": "application/javascript"},
                                       b"console.log('sentinel fixture');\n"),
            "/static/app.js.map": lambda: (200, {"Content-Type": "application/json"},
                                           _SOURCEMAP),
            "/index.php": lambda: (200, {"Content-Type": "text/html"},
                                   b"<h1>index.php</h1>"),
            "/index.php.bak": lambda: (200, {"Content-Type": "application/octet-stream"},
                                       b"PK\x03\x04" + b"\x00" * 64),
            "/www.zip": lambda: (200, {"Content-Type": "application/octet-stream"},
                                 b"PK\x03\x04" + b"\x00" * 128),
            "/backup.sql": lambda: (200, {"Content-Type": "text/plain"}, _SQL_DUMP),
            "/.git/config": lambda: (200, {"Content-Type": "text/plain"},
                                     b"[core]\n\trepositoryformatversion = 0\n"
                                     b"\tfilemode = true\n"),
            "/.svn/all-wcprops": lambda: (200, {"Content-Type": "text/plain"},
                                          b"K 1\nsvn:wc:ra_dav:version-url\nV 1\n"
                                          b"/repos/!svn/ver/1/trunk\nEND\n"),
            "/.DS_Store": lambda: (200, {"Content-Type": "application/octet-stream"},
                                   b"\x00\x00\x00\x01Bud1" + b"\x00" * 48),
            "/.idea/workspace.xml": lambda: (200, {"Content-Type": "text/xml"},
                                             _IDEA_XML),
            "/phpinfo.php": lambda: (200, {"Content-Type": "text/html"},
                                     b"<html><head><title>phpinfo()</title></head>"
                                     b"<body>PHP Version => 8.1.7</body></html>"),
            "/phpmyadmin/": lambda: (200, {"Content-Type": "text/html"},
                                     b"<html><head><title>phpMyAdmin</title></head>"
                                     b"<body><form id='login_form'></form></body></html>"),
            "/actuator/env": lambda: (200, {"Content-Type": "application/json"},
                                      b'{"activeProfiles":[],'
                                      b'"propertySources":[{"name":"systemProperties"}]}'),
            "/swagger-ui.html": lambda: (200, {"Content-Type": "text/html"},
                                         b"<html><head><title>Swagger UI</title>"
                                         b"</head><body></body></html>"),
            "/common/swfupload/swfupload.swf": lambda: (
                200, {"Content-Type": "application/x-shockwave-flash"},
                b"FWS\x0a" + b"\x00" * 96),
            "/cmd": lambda: self._command(query.get("cmd", "")),
            "/phpcode": lambda: self._php_code(query.get("code", "")),
            "/ssti": lambda: self._ssti(query.get("template", "")),
            "/php": lambda: self._php_array(query),
            "/setheader": lambda: self._set_header(query.get("redirect", "")),
            "/deser": lambda: (200, {"Content-Type": "text/html"},
                               b"<h1>deserialization sink</h1>"),
            "/xml": lambda: (200, {"Content-Type": "text/html"},
                             b"<h1>xml endpoint</h1>") if method == "GET"
            else self._xxe(body.decode("utf-8", "replace")),
            "/smuggle": lambda: self._smuggle(headers, body),
            "/login": lambda: self._login(method, form),
            "/upload": lambda: self._upload(method, headers, body),
            "/comment": lambda: self._comment(method, form),
            "/admin": lambda: (200, {"Content-Type": "text/html"},
                               b"<h1 id='admin-panel'>admin-panel</h1>"),
            "/config": lambda: (200, {"Content-Type": "text/html"},
                                b"<h1>config</h1><pre>DB_PASSWORD=sentinel-fixture"
                                b"-pass</pre>"),
        }.get(path)
        if handler is not None:
            return handler()

        # 3) PathInfo 型反射 (net_xss): 只有 (A(...)) 形式的路径会被回显
        if "(" in path and ")" in path:
            return 404, {"Content-Type": "text/html"}, (
                f"<html><body><h1>404</h1><p>path: {path}</p></body></html>").encode()
        return 404, {"Content-Type": "text/html"}, b"<h1>404 Not Found</h1>"

    # ---------------- 漏洞处理器 ----------------
    def _home(self):
        body = ("<!doctype html><html><head><title>Plugin Lab</title></head><body>"
                "<a href='/health'>health</a>"
                "<a href='/index.php'>index</a>"
                "<a href='/files/'>files</a>"
                "<a href='/static/app.js'>js</a>"
                "<a href='/cmd?cmd=help'>cmd</a>"
                "<a href='/phpcode?code=help'>php</a>"
                "<a href='/ssti?template=hello'>ssti</a>"
                "<a href='/php?file=hello'>phpinfo-path</a>"
                "<a href='/deser?data=hello'>deser</a>"
                "<a href='/setheader?redirect=hello'>header</a>"
                "<a href='/smuggle'>smuggle</a>"
                "<a href='/xml'>xml</a>"
                "<a href='/phpinfo.php'>phpinfo</a>"
                "<a href='/phpmyadmin/'>pma</a>"
                "<a href='/actuator/env'>actuator</a>"
                "<a href='/swagger-ui.html'>swagger</a>"
                "<a href='/config'>config</a>"
                "<form action='/login' method='post'>"
                "<input name='username'><input type='password' name='password'>"
                "<input type='submit'></form>"
                "<form action='/upload' method='post' enctype='multipart/form-data'>"
                "<input type='file' name='upfile'><input type='submit'></form>"
                "<form action='/comment' method='post'>"
                "<input name='name'><textarea name='message'></textarea>"
                "<input type='submit'></form>"
                "</body></html>")
        return 200, {"Content-Type": "text/html"}, body.encode()

    def _command(self, value: str):
        """命令注入点: 参数整体交给 shell (用白名单限制真实执行范围)."""
        command = _extract_command(value)
        if not command:
            return 200, {"Content-Type": "text/plain"}, b"usage: ?p=<command>"
        if command in ("ver",):
            return 200, {"Content-Type": "text/plain"}, \
                b"Microsoft Windows [Version 10.0.19045.1]"
        if command in ("cat /etc/passwd", "cat /etc/shadow"):
            return 200, {"Content-Type": "text/plain"}, FLAG_FILE.encode()
        if not command.startswith(ALLOWED_COMMANDS):
            return 200, {"Content-Type": "text/plain"}, \
                b"command not allowed in fixture"
        try:
            proc = subprocess.run(["/bin/sh", "-c", command], capture_output=True,
                                  timeout=5, check=False)
        except (OSError, subprocess.SubprocessError):
            return 200, {"Content-Type": "text/plain"}, b"exec error"
        return 200, {"Content-Type": "text/plain"}, proc.stdout

    def _php_code(self, value: str):
        """PHP 代码注入点: 求值 md5(N)."""
        match = re.search(r"md5\(\s*(\d+)\s*\)", value)
        if not match:
            return 200, {"Content-Type": "text/html"}, b"<p>no output</p>"
        digest = hashlib.md5(match.group(1).encode()).hexdigest()
        return 200, {"Content-Type": "text/html"}, f"<p>{digest}</p>".encode()

    def _ssti(self, value: str):
        """模板注入点: 花括号/标签内的乘法会被求值."""
        match = re.search(r"(\d{1,6})\s*\*\s*(\d{1,6})", value)
        if not match:
            return (200, {"Content-Type": "text/html"},
                    f"<p>{value}</p>".encode())
        product = int(match.group(1)) * int(match.group(2))
        return 200, {"Content-Type": "text/html"}, f"<p>{product}</p>".encode()

    def _php_array(self, query: dict[str, str]):
        """PHP 数组参数导致的真实路径泄漏."""
        if any(key.endswith("[]") for key in query):
            return 200, {"Content-Type": "text/html"}, (
                "<br /><b>Warning</b>:  array given in "
                "/var/www/fixture/html/index.php on line 12").encode()
        return 200, {"Content-Type": "text/html"}, b"<p>php page</p>"

    def _set_header(self, value: str):
        """响应头注入点: 参数原样写入响应头 (换行未被过滤)."""
        return 200, {"Content-Type": "text/plain", "X-Echo": value}, b"header set"

    def _xxe(self, payload: str):
        """XXE: 解析 DOCTYPE 里的外部实体."""
        return 200, {"Content-Type": "application/xml"}, _expand_entities(payload)

    def _smuggle(self, headers: dict[str, str], body: bytes):
        """前后端对报文边界理解不一致的端点 (CL 与 TE 冲突时按 TE 解析)."""
        low = {k.lower() for k in headers}
        if "transfer-encoding" in low and "content-length" in low:
            return 200, {"Content-Type": "text/plain"}, \
                b"parsed by Transfer-Encoding: 0 bytes"
        return 200, {"Content-Type": "text/plain"}, \
            f"parsed by Content-Length: {len(body)} bytes".encode()

    def _login(self, method: str, form: dict[str, str]):
        if method == "GET":
            return 200, {"Content-Type": "text/html"}, _LOGIN_FORM
        if form.get("username") == "admin" and form.get("password") == "admin":
            return (302, {"Location": "/dashboard",
                          "Set-Cookie": "SESSION=sentinel-fixture-session"},
                    b"<p>login ok</p>")
        return (200, {"Content-Type": "text/html"},
                "<p>用户名或密码错误</p>".encode())

    def _upload(self, method: str, headers: dict[str, str], body: bytes):
        if method == "GET":
            return 200, {"Content-Type": "text/html"}, _UPLOAD_FORM
        ctype = ""
        for key, value in headers.items():
            if key.lower() == "content-type":
                ctype = value
        filename, content = _parse_multipart(ctype, body)
        if not filename:
            return 200, {"Content-Type": "text/html"}, b"<p>no file</p>"
        self.uploads[filename] = content
        return 200, {"Content-Type": "text/html"}, (
            f"<p>upload ok: {filename}</p>"
            f"<a href='/uploads/{filename}'>download</a>").encode()

    def _comment(self, method: str, form: dict[str, str]):
        if method == "GET":
            return 200, {"Content-Type": "text/html"}, _COMMENT_FORM
        return 200, {"Content-Type": "text/html"}, (
            f"<p>saved: {form.get('message', '')}</p>").encode()


def _extract_command(value: str) -> str:
    """从注入载荷里取出待执行命令 (注入点的"正常"语义)."""
    command = value.strip().strip(";|&\n \t")
    wrapped = re.fullmatch(r"\$\((.*)\)", command) or re.fullmatch(r"`(.*)`", command)
    if wrapped:
        command = wrapped.group(1).strip()
    return command


def _expand_entities(payload: str) -> bytes:
    """把 DOCTYPE 里声明的外部实体替换成目标内容."""
    entities = re.findall(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>', payload)
    text = payload
    for name, uri in entities:
        if uri.startswith("file://"):
            replacement = FLAG_FILE
        elif uri.startswith("php://filter"):
            replacement = ""
        else:
            replacement = "sentinel-entity-fetched"
        text = text.replace(f"&{name};", replacement)
    return text.encode()


def _parse_multipart(content_type: str, body: bytes) -> tuple[str, bytes]:
    match = re.search(r"boundary=([^;]+)", content_type)
    if not match:
        return "", b""
    boundary = match.group(1).strip().strip('"').encode()
    for part in body.split(b"--" + boundary):
        if b"filename=" not in part:
            continue
        name = re.search(rb'filename="([^"]*)"', part)
        if not name:
            continue
        content = part.split(b"\r\n\r\n", 1)
        return name.group(1).decode("utf-8", "replace"), \
            (content[1].rstrip(b"\r\n-") if len(content) > 1 else b"")
    return "", b""


_LISTING = (b"<html><head><title>Index of /files</title></head><body>"
            b"<h1>Index of /files</h1><table><tr><td><a href='readme.txt'>"
            b"readme.txt</a></td><td>last modified</td></tr></table></body></html>")
_SOURCEMAP = (b'{"version":3,"file":"app.js","sources":'
              b'["webpack:///./src/app.js","webpack:///./src/util.js"],'
              b'"mappings":"AAAA"}')
_SQL_DUMP = (b"-- MySQL dump 10.13  Distrib 8.0.32, for Linux (x86_64)\n--\n"
             b"CREATE TABLE `users` (`id` int(11) NOT NULL);\n"
             b"INSERT INTO `users` VALUES (1,'admin');\n")
_IDEA_XML = (b'<?xml version="1.0" encoding="UTF-8"?>\n'
             b'<project version="4">\n'
             b'  <component name="ProjectRootManager" version="2">\n'
             b'    <output url="file://$PROJECT_DIR$/out" />\n'
             b'    <content url="file://$PROJECT_DIR$/src" />\n'
             b'  </component>\n</project>\n')
_LOGIN_FORM = (b"<html><body><form action='/login' method='post'>"
               b"<input name='username'><input type='password' name='password'>"
               b"</form></body></html>")
_UPLOAD_FORM = (b"<html><body><form action='/upload' method='post' "
                b"enctype='multipart/form-data'>"
                b"<input type='file' name='upfile'></form></body></html>")
_COMMENT_FORM = (b"<html><body><form action='/comment' method='post'>"
                 b"<input name='name'><textarea name='message'></textarea>"
                 b"</form></body></html>")


class PluginLabServer:
    """植入式插件靶场 (仅绑定回环地址, 供测试使用)."""

    def __init__(self, host: str = "127.0.0.1", name: str = "plugin-lab") -> None:
        self.host = host
        self.name = name
        self.app = _FixtureApp(name)
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.bound_port: int | None = None

    def start(self) -> int:
        app = self.app

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "PluginLab/1.0"
            sys_version = ""

            def log_message(self, *args):
                return

            def _serve(self, method: str) -> None:
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    body = self.rfile.read(length) if length else b""
                    status, headers, payload = app.handle(
                        method, self.path, dict(self.headers.items()), body)
                    self.send_response(status)
                    for key, value in (headers or {}).items():
                        try:
                            self.send_header(str(key), str(value))
                        except (UnicodeEncodeError, ValueError):
                            continue
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True

            def do_GET(self):  # noqa: N802
                self._serve("GET")

            def do_POST(self):  # noqa: N802
                self._serve("POST")

        self._httpd = ThreadingHTTPServer((self.host, 0), Handler)
        self._httpd.daemon_threads = True
        self._httpd.request_queue_size = 256
        self.bound_port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        name="plugin-lab", daemon=True)
        self._thread.start()
        return self.bound_port

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.bound_port}"


# --------------------------------------------------------------------------
# 夹具
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def plugin_lab():
    server = PluginLabServer()
    server.start()
    yield server
    server.stop()


@pytest.fixture(scope="module")
def fixture_scan(plugin_lab) -> dict:
    """对植入式靶场跑一次深度扫描 (覆盖 deep_only 插件)."""
    config = ScannerConfig(max_urls=40, max_depth=2, concurrency=8,
                           timeout_s=3.0, time_based_threshold_s=2.0)
    engine = W13ScanEngine(config=config)
    seeds = [
        plugin_lab.base_url + "/",
        # 反序列化插件需要一个带序列化参数值的种子 URL
        plugin_lab.base_url + "/deser?data=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
    ]
    findings = engine.scan(seeds, deep=True, timeout_s=180)
    return {"findings": findings, "engine": engine,
            "types": {f.vuln_type for f in findings},
            "by_type": _group(findings)}


@pytest.fixture(scope="module")
def lab_scan(lab_server) -> dict:
    """用真实漏洞靶场 (LabServer) 跑一次原生引擎扫描."""
    config = ScannerConfig(max_urls=40, max_depth=2, concurrency=8,
                           timeout_s=3.0, time_based_threshold_s=2.0)
    engine = W13ScanEngine(config=config)
    base = f"http://127.0.0.1:{lab_server.bound_port}"
    findings = engine.scan([base + "/"], deep=True, timeout_s=180)
    return {"findings": findings, "engine": engine,
            "types": {f.vuln_type for f in findings},
            "by_type": _group(findings)}


@pytest.fixture(scope="module")
def lab_server():
    server = LabServer("127.0.0.1", 0, "plugin-lab-real")
    server.start()
    yield server
    server.stop()


def _group(findings) -> dict[str, list]:
    out: dict[str, list] = {}
    for finding in findings:
        out.setdefault(finding.vuln_type, []).append(finding)
    return out


# --------------------------------------------------------------------------
# 端到端: 植入式靶场
# --------------------------------------------------------------------------
def test_fixture_scan_reports_no_plugin_errors(fixture_scan):
    assert fixture_scan["engine"].last_error == "", fixture_scan["engine"].last_error
    assert fixture_scan["engine"].stats["plugins_run"] > 100
    assert fixture_scan["findings"], "植入式靶场扫描零发现"


#: 植入式靶场 -> 期望命中的插件 (``vuln_type`` 与插件名一致, 少数有映射)
FIXTURE_EXPECTED: dict[str, str] = {
    "cmd_injection": "cmd_inject 执行 echo|base64 / id 并读到命令输出",
    "code_injection": "php_code 回显 md5(N) 证明 PHP 代码被执行",
    "ssti": "ssti 回显 9137*9139 的乘积",
    "xxe": "xxe 展开 file:// 外部实体读到伪 /etc/passwd",
    "crlf": "crlf 通过 %0d%0a 伪造出 Sentinel-Inject 响应头",
    "smuggling": "http_smuggling 观察到 CL/TE 冲突报文的解析差异",
    "csrf": "csrf 发现无令牌的 POST 表单",
    "upload": "upload 上传探针文件并被回显",
    "brute_force": "weak_password 用 admin/admin 登录成功",
    "backup_file": "backup_file 命中 zip 魔数的 /www.zip",
    "db_backup": "db_backup 命中 MySQL dump 头的 /backup.sql",
    "directory_browse": "directory_browse 命中 /files/ 的目录列表",
    "git_leak": "git_leak 命中 /.git/config",
    "svn_leak": "svn_leak 命中 /.svn/all-wcprops",
    "ds_store_leak": "ds_store_leak 命中 /.DS_Store 的 Bud1 魔数",
    "idea": "idea 命中 /.idea/workspace.xml 与 $PROJECT_DIR$",
    "webpack": "webpack 命中 /static/app.js.map 的 webpack:///",
    "phpinfo": "phpinfo 命中 /phpinfo.php",
    "phpmyadmin": "phpmyadmin 命中 /phpmyadmin/",
    "spring_actuator": "spring_actuator 命中 /actuator/env",
    "swagger_ui": "swagger_ui 命中 /swagger-ui.html",
    "iis_shortname": "iis_shortname 观察到 ~1 路径与普通 404 的状态码差异",
    "errorpage": "errorpage 从 .jsp 500 页面提取到 Java 堆栈",
    "net_xss": "net_xss 观察到 (A(...)) 路径被原样反射",
    "swf_files": "swf_files 命中 FWS 魔数的 swfupload.swf",
    "sensitive": "sensitive_info 命中 /config 里的 DB_PASSWORD",
    "unauth": "unauth 无凭据访问 /admin 命中 admin-panel",
    "xss": "xss 命中 /comment 表单的反射回显",
    "baseline": "deserialization 识别出种子 URL 里的 Java 序列化参数",
}


@pytest.mark.parametrize("vuln_type,reason", sorted(FIXTURE_EXPECTED.items()))
def test_fixture_plugin_fires(fixture_scan, vuln_type, reason):
    """逐个插件断言"真的命中", 而不是"返回空列表也算过"."""
    assert vuln_type in fixture_scan["types"], \
        f"{vuln_type} 未命中植入漏洞 ({reason}); 实际命中: " \
        f"{sorted(fixture_scan['types'])}"
    findings = fixture_scan["by_type"][vuln_type]
    assert any(f.evidence or f.proof for f in findings), "发现缺少证据/证明"
    assert all(f.conn_id == "w13scan" for f in findings)


def test_fixture_findings_carry_actionable_detail(fixture_scan):
    for finding in fixture_scan["findings"]:
        assert finding.url.startswith("http://")
        assert finding.severity in tuple(Severity)
        assert 0.0 < finding.confidence <= 1.0
        assert finding.proof, f"{finding.vuln_type} 缺少 proof"


def test_sqli_techniques_are_all_reported_on_real_lab(lab_scan):
    """真实靶场的三种 SQLi (报错/布尔/时间) 都必须被报出来."""
    sqli = lab_scan["by_type"].get("sqli", [])
    assert len(sqli) >= 3, f"SQLi 发现过少: {[f.payload for f in sqli]}"
    payloads = " ".join(f.payload for f in sqli)
    assert "SLEEP" in payloads.upper(), "缺少时间盲注发现"
    assert "1=1" in payloads or "1'='1" in payloads, "缺少布尔盲注发现"


def test_lfi_uses_raw_path_separators(lab_scan):
    lfi = lab_scan["by_type"].get("path_traversal", [])
    assert lfi, "路径穿越未命中真实靶场"
    assert any("etc/passwd" in f.payload for f in lfi)


# --------------------------------------------------------------------------
# 端到端: 真实漏洞靶场
# --------------------------------------------------------------------------
LAB_EXPECTED: dict[str, str] = {
    "sqli": "SQL 注入 (报错/布尔/时间三型)",
    "xss": "反射型 XSS (/page?name=)",
    "path_traversal": "任意文件读取 (/download?file=)",
    "ssrf": "SSRF (/fetch?url=)",
    "redirect": "开放重定向 (/go?next=)",
    "jsonp": "JSONP 劫持 (/api/jsonp?callback=)",
    "cors": "CORS 配置错误 (/api/user)",
    "unauth": "未授权访问 (/admin, /api/orders, /debug)",
    "sensitive": "信息泄漏 (/debug 的 DB_PASSWORD/FLAG/堆栈)",
    "robots": "robots.txt 路径泄漏",
    # 靶场 /go 把解码后的参数原样写进 Location, 解码出的 CRLF 会伪造出新响应头
    "crlf": "CRLF 响应头注入 (/go?next= 把 %0d%0a 解码进 Location)",
}


@pytest.mark.parametrize("vuln_type,reason", sorted(LAB_EXPECTED.items()))
def test_real_lab_plugin_fires(lab_scan, vuln_type, reason):
    assert vuln_type in lab_scan["types"], \
        f"{vuln_type} 未命中真实靶场漏洞 ({reason}); 实际命中: " \
        f"{sorted(lab_scan['types'])}"


def test_real_lab_scan_is_fast_and_error_free(lab_scan):
    engine = lab_scan["engine"]
    assert engine.last_error == "", engine.last_error
    assert engine.stats["endpoints"] >= 8
    assert engine.stats["seconds"] < 120


def test_no_false_positive_on_benign_paths(plugin_lab):
    """对一个只有健康检查接口的目标, 不应报出注入 / 上传 / 弱口令一类"路径级"漏洞."""
    engine = W13ScanEngine(config=ScannerConfig(max_urls=12, max_depth=1))
    findings = engine.scan([plugin_lab.base_url + "/health"], deep=False,
                           timeout_s=60)
    # /health 是纯文本 "ok"; 备份文件与仓库泄漏是**主机级**发现 (本夹具确实存在),
    # 因此不在此列 —— 这里断言的是"按参数/表单检测"的插件没有误报。
    assert not {f.vuln_type for f in findings} & {
        "sqli", "xss", "cmd_injection", "code_injection", "upload",
        "brute_force", "xxe", "ssti", "path_traversal", "redirect", "cors",
        "jsonp", "ssrf", "crlf", "smuggling"}


# --------------------------------------------------------------------------
# 覆盖率: 每个插件都必须在某一层靶场上**单独**命中过
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def per_plugin_hits(plugin_lab, lab_server) -> dict[str, list[str]]:
    """逐个插件单独扫描两层靶场, 记录它命中的目标.

    这是本文件里最"较真"的一道闸门: 单独跑一个插件, 它必须自己产出发现。任何插件被
    写成桩 (永远返回 ``[]``) 或检测逻辑失效, 都会在这里暴露, 而不是被其它插件的发现
    掩盖过去。
    """
    config = ScannerConfig(max_urls=40, max_depth=2, concurrency=8,
                           timeout_s=3.0, time_based_threshold_s=2.0)
    seeds = {
        "fixture": [plugin_lab.base_url + "/",
                    plugin_lab.base_url + "/deser?data=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="],
        "real": [f"http://127.0.0.1:{lab_server.bound_port}/"],
    }
    hits: dict[str, list[str]] = {}
    for plugin in all_plugins():
        fired: list[str] = []
        for name, targets in seeds.items():
            engine = W13ScanEngine(config=config, plugins=[plugin])
            if engine.scan(targets, deep=True, timeout_s=120):
                fired.append(name)
        hits[plugin.name] = fired
    return hits


def test_every_plugin_fires_somewhere(per_plugin_hits):
    silent = [name for name, hits in per_plugin_hits.items() if not hits]
    assert silent == [], (
        f"这些插件在两层靶场上都没有命中, 说明检测逻辑失效或退化成桩: {silent}")


def test_plugin_counts_cover_the_catalogue(per_plugin_hits):
    assert len(per_plugin_hits) == len(all_plugins())
    verified = sum(1 for hits in per_plugin_hits.values() if hits)
    assert verified == len(all_plugins()), f"仅 {verified} 个插件被验证命中"


def test_every_plugin_metadata_survives_a_full_scan(fixture_scan):
    """扫描过程中插件实例不得残留状态 (上下文全部走 PluginContext)."""
    engine = fixture_scan["engine"]
    assert not hasattr(engine, "_state"), "引擎不应持有可变全局状态"
    assert isinstance(engine.stats, dict)


# --------------------------------------------------------------------------
# 兼容性: 上游 JSONL 报告解析仍可用 (w13scan 历史报告入口)
# --------------------------------------------------------------------------
def test_parse_report_keeps_upstream_compatibility(tmp_path):
    report = tmp_path / "w13.jsonl"
    rows = [
        {"type": "sqli", "name": "SQL Injection", "url": "http://lab/s?q=1",
         "detail": {"payload": ["1' OR '1'='1"]}},
        {"result": "信息泄露", "name": "info", "url": "http://lab/debug",
         "detail": {}},
    ]
    report.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    findings = W13ScanEngine.parse_report(report)
    assert [f.vuln_type for f in findings] == ["sqli", "信息泄露"]
    assert findings[0].severity is Severity.HIGH
    assert findings[0].payload == "1' OR '1'='1"


def test_registry_is_importable_without_network():
    """注册表自注册不依赖网络/外部文件 (纯 Python 包)."""
    assert len(registry) == len(all_plugins()) == len(plugin_names())
    assert registry.get("nope") is None
    assert "xss" in registry


def test_engine_scoped_plugins_get_a_synthetic_endpoint():
    """目标没有任何接口时, server 档插件仍应拿到一个可用的 Endpoint."""
    seen: list[str] = []

    class Probe(Plugin):
        name = "probe_test"
        title = "探针"
        category = "info"
        scope = SCOPE_SERVER
        cwe = "CWE-000"
        owasp = "A01:2021"
        description = "记录 server 档插件的上下文"

        def run(self, ctx):
            seen.append(ctx.endpoint.url)
            return []

    engine = W13ScanEngine(config=ScannerConfig(timeout_s=0.4, max_urls=2,
                                                max_depth=1), plugins=[Probe()])
    engine.scan(["http://127.0.0.1:1/"], timeout_s=30)
    assert seen == ["http://127.0.0.1:1/"]
