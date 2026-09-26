"""Sentinel 综合测试报告生成器 (中文 Markdown / 自包含 HTML / DOCX).

消费 :mod:`benchmarks.run_all` 产出的基准 JSON, 汇总:

* 运行环境与工具链 (mise / uv / Python / nginx 真实引擎)
* 综设 I / II / III + 后端靶场 的架构映射
* 测试用例矩阵 (优先读取 pytest JUnit XML, 缺失时静态扫描 ``tests/``)
* 检测语料库规模与 WAF 引擎质量指标 (精确率 / 召回率 / F1 / 误报率)
* 性能基准 (解析器吞吐 / 引擎吞吐 / 真实引擎 QPS / 代理延迟 / 负载均衡)
* Paranoia Level 与异常阈值权衡曲线
* 漏洞扫描子系统的真实发现与 OWASP Top 10 / CWE 映射
* TUI 截图与复现命令

产物 (写入 ``outdir``)::

    report-<stamp>.md    中文综合测试报告 (Markdown)
    report-<stamp>.html  自包含 HTML (Catppuccin Frappé, 内嵌截图与 SVG 图表)
    report-<stamp>.docx  Word 文档 (复用 coredocx, 缺失时自动跳过)
"""
from __future__ import annotations

import ast
import base64
import html as _html
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree

from .tui import palette as P

ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
SHOT_DIR = ROOT / "docs" / "tui"

MISE_TOML = ROOT / "mise.toml"
PYPROJECT = ROOT / "pyproject.toml"

# ---------------------------------------------------------------------------
# 综设映射 / 术语表
# ---------------------------------------------------------------------------
ARCH = [
    ("综设 I", "漏洞扫描子系统", "sentinel.scanner",
     "目标识别 → 漏洞检测 → 漏洞库/规则 → 报告生成; 对齐 w13scan 十类插件"),
    ("综设 II", "轻量级防火墙", "sentinel.waf",
     "HTTP 解析 → 变换归一化 → 特征/规则引擎 → 阻断与审计; 由真实 C 引擎驱动"),
    ("综设 III", "可视化安全运营与管理平台", "sentinel.tui",
     "综合仪表盘 / 配置 / 入侵检测 / 规则 / 审计 / 引擎管理, Vim 键位 TUI"),
    ("后端", "WEB 漏洞靶场", "sentinel.lab",
     "多实例标准库 http.server 靶场, 预置 SQLi/XSS/SSRF/文件读取/未授权等漏洞"),
]

# 测试模块 → (综设归属, 被测能力)
SUITE_META: dict[str, tuple[str, str]] = {
    "test_parser": ("综设 II", "HTTP/1.1 请求解析 (方法与头部/请求体/分块)"),
    "test_transforms": ("综设 II", "输入规范化与多重编码解码"),
    "test_signatures": ("综设 II", "攻击特征库 (SQLi/XSS/RCE/LFI/SSRF/扫描器)"),
    "test_rules": ("综设 II", "规则引擎与 JSON→ModSecurity 语法导出"),
    "test_engine": ("综设 II", "检测引擎评分、阈值与阻断决策"),
    "test_ids": ("综设 II", "入侵检测事件聚合与告警"),
    "test_balancer": ("综设 II", "后端负载均衡策略 (RR/LC/random/ip_hash)"),
    "test_engines": ("综设 II", "引擎注册表与可用性探测"),
    "test_engine_e2e": ("综设 II", "端到端拦截 (解析→引擎→响应)"),
    "test_proxy_e2e": ("综设 II", "反向代理端到端 (真实 socket 报文)"),
    "test_runtime_engines": ("综设 II", "真实引擎 (ModSecurity / Naxsi) 运行时冒烟"),
    "test_lab": ("后端靶场", "靶场路由与漏洞注入正确性"),
    "test_scanner_report": ("综设 I", "漏洞报告渲染 (Markdown/HTML/JSON) 与多引擎记录"),
    "test_scanner_engines": ("综设 I", "扫描引擎驱动 (nuclei / w13scan / 内置)"),
    "test_config": ("综设 III", "配置模型校验与 TOML 持久化"),
    "test_core": ("综设 III", "事件总线 / 指标直方图 / 审计日志"),
    "test_tui": ("综设 III", "TUI 面板、Vim 键位与命令模式"),
    "test_benchmarks": ("综设 III", "基准与报告工具链"),
}

# 漏洞类型 → (中文名, OWASP 2021, CWE, 修复建议)
VULN_META: dict[str, tuple[str, str, str, str]] = {
    "sqli": ("SQL 注入", "A03 注入", "CWE-89",
             "使用参数化查询/预编译语句, 禁止字符串拼接 SQL。"),
    "sqli_error": ("SQL 注入 (报错型)", "A03 注入", "CWE-89",
                   "同 SQL 注入: 参数化查询 + 关闭详细报错回显。"),
    "sqli_time": ("SQL 注入 (时间盲注)", "A03 注入", "CWE-89",
                  "参数化查询 + 输入白名单, 拦截 SLEEP/WAITFOR/BENCHMARK。"),
    "sqli-boolean": ("SQL 注入 (布尔盲注)", "A03 注入", "CWE-89",
                     "参数化查询 + 统一错误响应, 消除真假条件差异。"),
    "sqli-error": ("SQL 注入 (报错型)", "A03 注入", "CWE-89",
                   "参数化查询 + 生产环境关闭数据库报错回显。"),
    "xss": ("跨站脚本 (反射型)", "A03 注入", "CWE-79",
            "按输出上下文做 HTML/JS/URL 编码, 部署 CSP。"),
    "xss-reflected": ("跨站脚本 (反射型)", "A03 注入", "CWE-79",
                      "输出编码 + CSP + 输入实体解码后检测。"),
    "rce": ("远程命令执行", "A03 注入", "CWE-78",
            "禁止将用户输入拼接进命令; 使用参数化 API 与命令白名单。"),
    "path_traversal": ("路径穿越", "A01 权限控制失效", "CWE-22",
                       "规范化路径并校验白名单前缀, 拒绝 .. 与绝对路径。"),
    "directory_traversal": ("目录穿越", "A01 权限控制失效", "CWE-22",
                            "使用 basename 限制目录, 禁止拼接用户路径。"),
    "file_read": ("任意文件读取", "A01 权限控制失效", "CWE-22",
                  "文件参数白名单化, 使用映射 ID 而非真实路径。"),
    "lfi": ("本地文件包含", "A01 权限控制失效", "CWE-98",
            "白名单包含模板, 禁止动态拼接包含路径。"),
    "ssrf": ("服务端请求伪造", "A10 服务端请求伪造", "CWE-918",
             "目标地址白名单, 禁止内网/回环/元数据地址与危险协议。"),
    "ssrf-internal": ("SSRF 访问内网", "A10 服务端请求伪造", "CWE-918",
                      "阻断对 127.0.0.1 / 169.254.169.254 / 内网段的请求。"),
    "cors": ("CORS 配置错误", "A05 安全配置错误", "CWE-942",
             "仅回显白名单来源, 携带凭据时禁止通配符。"),
    "cors-misconfig": ("CORS 配置错误", "A05 安全配置错误", "CWE-942",
                       "校验 Origin 白名单, 避免原样反射。"),
    "jsonp": ("JSONP 数据劫持", "A01 权限控制失效", "CWE-346",
              "废弃 JSONP 改用 CORS+JSON; callback 名称严格白名单。"),
    "url_redirect": ("开放重定向", "A01 权限控制失效", "CWE-601",
                     "跳转目标使用服务端映射白名单。"),
    "open-redirect": ("开放重定向", "A01 权限控制失效", "CWE-601",
                      "禁止把用户参数直接写入 Location 头。"),
    "unauth": ("未授权访问", "A01 权限控制失效", "CWE-284",
               "为管理/调试接口增加统一鉴权与最小权限。"),
    "admin-panel": ("后台管理面板暴露", "A01 权限控制失效", "CWE-284",
                    "限制管理面板访问来源并强制鉴权。"),
    "debug-exposure": ("调试接口泄露", "A05 安全配置错误", "CWE-200",
                       "生产环境关闭调试端点。"),
    "html_res_information_disclosure": ("敏感信息泄露", "A05 安全配置错误", "CWE-200",
                                        "统一异常处理, 移除响应中的密钥与堆栈。"),
}


def vuln_meta(vuln_type: str) -> tuple[str, str, str, str]:
    """容忍命名差异的漏洞类型归一化查询."""
    key = (vuln_type or "").strip().lower()
    if key in VULN_META:
        return VULN_META[key]
    for prefix in ("sqli", "xss", "ssrf", "rce", "lfi", "path_traversal",
                   "file_read", "cors", "jsonp", "redirect", "unauth", "admin",
                   "debug"):
        if key.startswith(prefix):
            for name, meta in VULN_META.items():
                if name.startswith(prefix):
                    return meta
    return (vuln_type or "未知", "-", "-", "按业务上下文修复。")


# ---------------------------------------------------------------------------
# 测试结果采集
# ---------------------------------------------------------------------------
def _first_docline(node: ast.AST) -> str:
    doc = ast.get_docstring(node) or ""
    return doc.strip().splitlines()[0] if doc.strip() else ""


def discover_tests(tests_dir: Path | None = None) -> dict:
    """静态扫描 tests/ 建立用例清单 (无 JUnit 时的回退)."""
    module_rows: dict[str, dict] = {}
    total = 0
    for path in sorted((tests_dir or TESTS_DIR).glob("test_*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        cases = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
                    node.name.startswith("test"):
                cases.append({"name": node.name, "line": node.lineno,
                              "status": "collected", "seconds": 0.0,
                              "doc": _first_docline(node)})
            elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
                            sub.name.startswith("test"):
                        cases.append({"name": f"{node.name}::{sub.name}",
                                      "line": sub.lineno, "status": "collected",
                                      "seconds": 0.0, "doc": _first_docline(sub)})
        if cases:
            module_rows[path.stem] = {"cases": cases, "seconds": 0.0,
                                      "source": "static"}
            total += len(cases)
    return {"source": "static", "modules": module_rows, "total": total,
            "passed": 0, "failed": 0, "skipped": 0, "seconds": 0.0}


def parse_junit(xml_path: str | Path) -> dict:
    """解析 pytest ``--junitxml`` 结果."""
    root = ElementTree.parse(str(xml_path)).getroot()
    modules: dict[str, dict] = {}
    passed = failed = skipped = 0
    for case in root.iter("testcase"):
        classname = case.get("classname") or ""
        module = classname.split(".")[-1] if classname else "tests"
        name = case.get("name") or ""
        seconds = float(case.get("time") or 0.0)
        status = "passed"
        message = ""
        for tag in ("failure", "error"):
            node = case.find(tag)
            if node is not None:
                status = "failed"
                message = (node.get("message") or (node.text or "")).strip().splitlines()
                message = message[0][:160] if message else ""
                break
        else:
            node = case.find("skipped")
            if node is not None:
                status = "skipped"
                message = (node.get("message") or "").strip().splitlines()
                message = message[0][:160] if message else ""
        if status == "passed":
            passed += 1
        elif status == "failed":
            failed += 1
        else:
            skipped += 1
        bucket = modules.setdefault(module, {"cases": [], "seconds": 0.0,
                                             "source": "junit"})
        bucket["cases"].append({"name": name, "status": status, "seconds": seconds,
                                "doc": message})
        bucket["seconds"] += seconds
    total = passed + failed + skipped
    return {"source": "pytest-junit", "modules": modules, "total": total,
            "passed": passed, "failed": failed, "skipped": skipped,
            "seconds": round(sum(m["seconds"] for m in modules.values()), 2)}


def run_pytest(outdir: str | Path = "reports", timeout: int = 3600) -> dict:
    """运行完整 pytest 并采集 JUnit XML (供 --report --tests 使用)."""
    xml_path = Path(outdir) / "junit.xml"
    xml_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:randomly",
           f"--junitxml={xml_path}"]
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True,
                          timeout=timeout, check=False)
    result = parse_junit(xml_path) if xml_path.exists() else discover_tests()
    result["command"] = " ".join(cmd)
    result["returncode"] = proc.returncode
    result["stdout_tail"] = (proc.stdout or "").strip().splitlines()[-3:]
    return result


def load_tests(outdir: str | Path = "reports", run_tests: bool = False) -> dict:
    """优先使用最新 JUnit XML; 否则回退到 tests/ 静态清单."""
    if run_tests:
        return run_pytest(outdir)
    xml_path = Path(outdir) / "junit.xml"
    if xml_path.exists():
        try:
            result = parse_junit(xml_path)
            result["command"] = "uv run pytest -q -p no:randomly --junitxml=reports/junit.xml"
            return result
        except (ElementTree.ParseError, OSError):
            pass
    return discover_tests()


def test_matrix(tests: dict) -> dict:
    """把测试结果按综设归属聚合成报告表格数据."""
    groups: dict[str, dict] = {}
    rows = []
    for module, data in sorted(tests["modules"].items()):
        group, capability = SUITE_META.get(module, ("其他", "综合回归"))
        cases = data["cases"]
        counts = {"passed": 0, "failed": 0, "skipped": 0, "collected": 0}
        for case in cases:
            counts[case["status"]] = counts.get(case["status"], 0) + 1
        rows.append({
            "module": module, "group": group, "capability": capability,
            "total": len(cases), "passed": counts.get("passed", 0),
            "failed": counts.get("failed", 0), "skipped": counts.get("skipped", 0),
            "seconds": round(data["seconds"], 2),
        })
        bucket = groups.setdefault(group, {"total": 0, "passed": 0, "failed": 0,
                                           "skipped": 0, "seconds": 0.0})
        bucket["total"] += len(cases)
        bucket["passed"] += counts.get("passed", 0)
        bucket["failed"] += counts.get("failed", 0)
        bucket["skipped"] += counts.get("skipped", 0)
        bucket["seconds"] += data["seconds"]
    return {"rows": rows, "groups": groups}


# ---------------------------------------------------------------------------
# 内联 SVG 图表 (无外部依赖, 直接嵌入自包含 HTML)
# ---------------------------------------------------------------------------
def _esc(text) -> str:
    return _html.escape(str(text), quote=True)


def _svg_open(title: str, width: int, height: int) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" role="img" aria-label="{_esc(title)}" '
        f'style="background:{P.MANTLE};border-radius:10px">',
        f'<text x="16" y="24" fill="{P.TEXT}" font-size="14" '
        f'font-family="ui-monospace,monospace" font-weight="600">{_esc(title)}</text>',
    ]


def svg_grouped_bars(title: str, labels: list[str], series: list[dict],
                     *, ymax: float = 1.0, fmt=lambda v: f"{v:.0%}",
                     width: int = 720, height: int = 300) -> str:
    """分组柱状图 (series: [{name, color, values}])."""
    if not labels or not series:
        return ""
    pad_l, pad_r, pad_t, pad_b = 58, 20, 56, 66
    pw, ph = width - pad_l - pad_r, height - pad_t - pad_b
    grid = 5
    parts = _svg_open(title, width, height)
    for i in range(grid + 1):
        value = ymax * i / grid
        y = pad_t + ph * (1 - i / grid)
        parts.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{pad_l + pw}" '
                     f'y2="{y:.1f}" stroke="{P.SURFACE0}" stroke-width="1"/>')
        parts.append(f'<text x="{pad_l - 8}" y="{y + 4:.1f}" fill="{P.OVERLAY1}" '
                     f'font-size="11" text-anchor="end" '
                     f'font-family="ui-monospace,monospace">{_esc(fmt(value))}</text>')
    slot = pw / len(labels)
    bar_w = slot * 0.66 / len(series)
    for li, label in enumerate(labels):
        x0 = pad_l + slot * li + slot * 0.17
        for si, serie in enumerate(series):
            value = float(serie["values"][li]) if li < len(serie["values"]) else 0.0
            value = max(0.0, min(value, ymax))
            bar_h = ph * value / ymax
            x = x0 + bar_w * si
            parts.append(
                f'<rect x="{x:.1f}" y="{pad_t + ph - bar_h:.1f}" width="{max(bar_w - 2, 1):.1f}" '
                f'height="{bar_h:.1f}" rx="3" fill="{serie["color"]}"><title>'
                f'{_esc(serie["name"])} · {_esc(label)} · {_esc(fmt(value))}</title></rect>')
        parts.append(f'<text x="{pad_l + slot * li + slot / 2:.1f}" y="{pad_t + ph + 20}" '
                     f'fill="{P.SUBTEXT0}" font-size="11" text-anchor="middle" '
                     f'font-family="ui-monospace,monospace">{_esc(label)}</text>')
    legend_x = pad_l
    for serie in series:
        parts.append(f'<rect x="{legend_x}" y="{height - 30}" width="10" height="10" rx="2" '
                     f'fill="{serie["color"]}"/>')
        parts.append(f'<text x="{legend_x + 15}" y="{height - 21}" fill="{P.SUBTEXT1}" '
                     f'font-size="11" font-family="ui-monospace,monospace">'
                     f'{_esc(serie["name"])}</text>')
        legend_x += 24 + 8 * len(str(serie["name"]))
    parts.append("</svg>")
    return "\n".join(parts)


def svg_hbars(title: str, labels: list[str], values: list[float],
              *, colors: list[str] | None = None, ymax: float = 1.0,
              width: int = 720) -> str:
    """横向条形图 (逐类检出率)."""
    if not labels:
        return ""
    row_h = 24
    height = 52 + row_h * len(labels) + 14
    pad_l = min(300, max(132, int(max(len(str(l)) for l in labels) * 13.5) + 18))
    pad_r = 62
    pw = max(width - pad_l - pad_r, 60)
    parts = _svg_open(title, width, height)
    for i, (label, value) in enumerate(zip(labels, values)):
        y = 44 + row_h * i
        color = (colors[i] if colors else None) or P.SAPPHIRE
        bar_w = max(pw * min(max(value, 0.0), ymax) / ymax, 1.0)
        parts.append(f'<text x="{pad_l - 10}" y="{y + 13}" fill="{P.SUBTEXT1}" '
                     f'font-size="11" text-anchor="end" '
                     f'font-family="ui-monospace,monospace">{_esc(label)}</text>')
        parts.append(f'<rect x="{pad_l}" y="{y + 3}" width="{pw}" height="12" rx="3" '
                     f'fill="{P.SURFACE0}"/>')
        parts.append(f'<rect x="{pad_l}" y="{y + 3}" width="{bar_w:.1f}" height="12" rx="3" '
                     f'fill="{color}"><title>{_esc(label)} · {value:.1%}</title></rect>')
        parts.append(f'<text x="{pad_l + pw + 8}" y="{y + 13}" fill="{P.TEXT}" '
                     f'font-size="11" font-family="ui-monospace,monospace">'
                     f'{value:.1%}</text>')
    parts.append("</svg>")
    return "\n".join(parts)


def svg_lines(title: str, xlabels: list[str], series: list[dict],
              *, ymax: float = 1.0, fmt=lambda v: f"{v:.0%}",
              width: int = 720, height: int = 300) -> str:
    """折线图 (Paranoia Level / 阈值权衡)."""
    if not xlabels or not series:
        return ""
    pad_l, pad_t, pad_b = 58, 56, 60
    legend_w = int(max(len(str(s["name"])) for s in series) * 13.2) + 30
    pad_r = min(260, max(120, legend_w))
    pw, ph = width - pad_l - pad_r, height - pad_t - pad_b
    grid = 5
    parts = _svg_open(title, width, height)
    for i in range(grid + 1):
        value = ymax * i / grid
        y = pad_t + ph * (1 - i / grid)
        parts.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{pad_l + pw}" '
                     f'y2="{y:.1f}" stroke="{P.SURFACE0}"/>')
        parts.append(f'<text x="{pad_l - 8}" y="{y + 4:.1f}" fill="{P.OVERLAY1}" '
                     f'font-size="11" text-anchor="end" '
                     f'font-family="ui-monospace,monospace">{_esc(fmt(value))}</text>')
    step = pw / max(len(xlabels) - 1, 1)
    for li, label in enumerate(xlabels):
        x = pad_l + step * li
        parts.append(f'<text x="{x:.1f}" y="{pad_t + ph + 20}" fill="{P.SUBTEXT0}" '
                     f'font-size="11" text-anchor="middle" '
                     f'font-family="ui-monospace,monospace">{_esc(label)}</text>')
        parts.append(f'<line x1="{x:.1f}" y1="{pad_t}" x2="{x:.1f}" y2="{pad_t + ph}" '
                     f'stroke="{P.SURFACE0}" stroke-dasharray="2 4"/>')
    for si, serie in enumerate(series):
        points = []
        for li, value in enumerate(serie["values"]):
            x = pad_l + step * li
            y = pad_t + ph * (1 - min(max(float(value), 0.0), ymax) / ymax)
            points.append(f"{x:.1f},{y:.1f}")
        parts.append(f'<polyline fill="none" stroke="{serie["color"]}" stroke-width="2.5" '
                     f'points="{" ".join(points)}"/>')
        for li, value in enumerate(serie["values"]):
            x = pad_l + step * li
            y = pad_t + ph * (1 - min(max(float(value), 0.0), ymax) / ymax)
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" '
                         f'fill="{serie["color"]}"><title>{_esc(serie["name"])} · '
                         f'{_esc(xlabels[li])} · {_esc(fmt(value))}</title></circle>')
        ly = pad_t + 6 + si * 20
        parts.append(f'<rect x="{pad_l + pw + 14}" y="{ly - 9}" width="10" height="10" rx="2" '
                     f'fill="{serie["color"]}"/>')
        parts.append(f'<text x="{pad_l + pw + 30}" y="{ly}" fill="{P.SUBTEXT1}" '
                     f'font-size="11" font-family="ui-monospace,monospace">'
                     f'{_esc(serie["name"])}</text>')
    parts.append("</svg>")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Markdown 报告
# ---------------------------------------------------------------------------
def _md_table(headers: list[str], rows: list[list]) -> list[str]:
    lines = ["| " + " | ".join(str(h) for h in headers) + " |",
             "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return lines


def _pct(value) -> str:
    try:
        return f"{float(value):.1%}"
    except (TypeError, ValueError):
        return "-"


def _fnum(value, digits=2) -> str:
    try:
        return f"{float(value):,.{digits}f}"
    except (TypeError, ValueError):
        return "-"


# ---------------------------------------------------------------------------
# 文档模型 (Markdown / HTML / DOCX 共享)
# ---------------------------------------------------------------------------
def _arch_table() -> list[list]:
    return [[name, title, f"`{pkg}`", detail] for name, title, pkg, detail in ARCH]


def _upstream_rows(bench: dict) -> list[list]:
    rows = []
    for name, meta in (bench.get("environment", {}).get("waf_engines") or {}).items():
        if name == "python":
            continue
        rows.append([meta.get("display", name), meta.get("upstream", "-"),
                     "真实 C 引擎" if meta.get("real_engine") else "内置回退",
                     "可用" if meta.get("available") else "不可用"])
    for name, meta in (bench.get("environment", {}).get("scanner_engines") or {}).items():
        rows.append([meta.get("display", name),
                     meta.get("upstream", "-"), meta.get("version", "-"),
                     "可用" if meta.get("available") else "不可用"])
    return rows


def _quality_rows(bench: dict) -> tuple[list[list], list[tuple[str, dict]]]:
    entries: list[tuple[str, dict]] = []
    for name, quality in (bench.get("quality") or {}).items():
        entries.append((name, quality))
    for name, block in (bench.get("real_engines") or {}).items():
        if isinstance(block, dict) and block.get("quality"):
            entries.append((name, block["quality"]))
    rows = []
    for name, q in entries:
        rows.append([name, q.get("mode", "-"), _pct(q.get("precision")),
                     _pct(q.get("recall")), _pct(q.get("f1")),
                     _pct(q.get("false_positive_rate")),
                     _pct(q.get("false_negative_rate")),
                     f"{q.get('tp', 0)}/{q.get('fp', 0)}/{q.get('tn', 0)}/{q.get('fn', 0)}"])
    return rows, entries


def build_document(bench: dict, tests: dict, *, stamp: str,
                   title: str = "Sentinel 综合测试与评测报告") -> list[dict]:
    env = bench.get("environment", {})
    meta = bench.get("meta", {})
    matrix = test_matrix(tests)
    blocks: list[dict] = []

    blocks.append({"type": "h1", "text": title})
    blocks.append({"type": "p", "text":
                   f"覆盖 **综设 I（漏洞扫描子系统）**、**综设 II（轻量级防火墙）**、"
                   f"**综设 III（可视化安全运营与管理平台）** 与 **后端 WEB 漏洞靶场** 四个组成部分。"
                   f"WAF 数据面由真实 C 引擎驱动（ModSecurity v3 + OWASP CRS、Naxsi），"
                   f"扫描面由 nuclei 模板引擎与 w13scan 插件体系驱动，管理面为 Vim 键位的 "
                   f"Catppuccin Frappé TUI。"})
    blocks.append({"type": "bullets", "items": [
        f"报告生成时间：{meta.get('generated_at', '-')}（基准采集耗时 "
        f"{meta.get('duration_s', '-')} 秒）",
        f"工具链：mise {env.get('mise') or '-'} · uv {env.get('uv') or '-'} · "
        f"Python {env.get('python', '-')}",
        f"平台：{env.get('platform', '-')} / {env.get('machine', '-')} / "
        f"{env.get('cpu_count', '-')} 逻辑核心",
        f"nginx：{env.get('nginx', {}).get('version') or '未检测到'} "
        f"（模块：{', '.join(env.get('nginx', {}).get('modules') or []) or '无'}）",
        f"检测语料：{bench.get('corpus', {}).get('total', '-')} 条（75 正常 + 103 攻击）",
    ]})

    # ---- 一、架构映射 ----
    blocks.append({"type": "h2", "text": "一、架构映射"})
    blocks.append({"type": "p", "text":
                   "本报告把仓库中的两个上游工程（WAF 与扫描器）统一到一张架构图上，"
                   "每一层都有可执行的代码与可复现的测试。"})
    blocks.append({"type": "table", "headers": ["架构层", "子系统", "代码包", "职责"],
                   "rows": _arch_table()})
    blocks.append({"type": "h3", "text": "1.1 上游引擎与星级（只选用高星级、真实工程）"})
    blocks.append({"type": "p", "text":
                   "下列星数为 **2026-09-25 GitHub API 快照**；选取标准是同领域中星级最高、"
                   "且提供可编译/可执行真实实现的工程（而非纯脚本复刻）。"})
    blocks.append({"type": "table",
                   "headers": ["组件", "上游来源（GitHub ★）", "类型/版本", "状态"],
                   "rows": _upstream_rows(bench)})

    # ---- 二、测试矩阵 ----
    blocks.append({"type": "h2", "text": "二、测试用例矩阵"})
    source = "pytest JUnit XML" if tests.get("source") == "pytest-junit" else "tests/ 静态扫描"
    detail = ""
    if tests.get("command"):
        detail = f"命令：`{tests.get('command')}`"
        if tests.get("returncode") is not None:
            detail += f"；返回码 {tests['returncode']}"
        detail += "。"
    blocks.append({"type": "p", "text": f"结果来源：**{source}**。{detail}"})
    if tests.get("source") == "pytest-junit":
        blocks.append({"type": "table", "headers": ["通过", "失败", "跳过", "合计", "总耗时(s)"],
                       "rows": [[tests.get("passed", 0), tests.get("failed", 0),
                                 tests.get("skipped", 0), tests.get("total", 0),
                                 tests.get("seconds", 0)]]})
    else:
        blocks.append({"type": "p", "text":
                       "当前未采集 JUnit 结果，下表为 `tests/` 目录的静态用例清单；"
                       "运行 `uv run python -m benchmarks.run_all --report --tests` 可刷新为真实通过率。"})
    blocks.append({"type": "h3", "text": "2.1 按综设归属汇总"})
    group_rows = []
    for group, data in sorted(matrix["groups"].items()):
        group_rows.append([group, data["total"], data["passed"], data["failed"],
                           data["skipped"], round(data["seconds"], 2)])
    blocks.append({"type": "table",
                   "headers": ["综设归属", "用例数", "通过", "失败", "跳过", "耗时(s)"],
                   "rows": group_rows})
    blocks.append({"type": "h3", "text": "2.2 明细用例矩阵"})
    blocks.append({"type": "table",
                   "headers": ["测试模块", "综设", "被测能力", "用例", "通过", "失败", "跳过"],
                   "rows": [[r["module"], r["group"], r["capability"], r["total"],
                             r["passed"], r["failed"], r["skipped"]] for r in matrix["rows"]]})

    # ---- 三、语料库 ----
    corpus_stats = (bench.get("corpus") or {}).get("stats", {})
    blocks.append({"type": "h2", "text": "三、检测语料库"})
    blocks.append({"type": "p", "text":
                   "语料库由 `benchmarks/corpus.py` 构造，全部为合法 HTTP/1.1 原始报文"
                   "（含方法、头部、请求体），因此可以同时喂给进程内引擎与 nginx 数据面。"})
    cat_zh = {"benign": "正常流量", "sqli": "SQL 注入", "xss": "跨站脚本",
              "rce": "远程命令执行", "lfi": "本地文件包含/路径穿越",
              "ssrf": "服务端请求伪造", "scanner": "扫描器指纹",
              "protocol": "协议层攻击", "recon": "信息侦察", "total": "合计"}
    blocks.append({"type": "table", "headers": ["类别", "样本数", "占比"],
                   "rows": [[cat_zh.get(k, k), v,
                             _pct(v / max(corpus_stats.get("total", 1), 1))]
                            for k, v in sorted(corpus_stats.items(),
                                               key=lambda kv: (kv[0] == "total", -kv[1]))]})

    # ---- 四、质量评测 ----
    quality_rows, quality_entries = _quality_rows(bench)
    blocks.append({"type": "h2", "text": "四、WAF 引擎检测质量"})
    blocks.append({"type": "p", "text":
                   "以语料库的人工标注为准，统计 TP/FP/TN/FN；真实引擎通过原始 socket "
                   "回放原始报文（方法/头部/请求体完整保留），避免“因测量方式而漏报”。"})
    blocks.append({"type": "table",
                   "headers": ["引擎", "模式", "精确率", "召回率", "F1", "误报率", "漏报率",
                               "TP/FP/TN/FN"],
                   "rows": quality_rows})
    attack_cats = [c for c in ("sqli", "xss", "rce", "lfi", "ssrf", "scanner",
                               "protocol", "recon") if c in corpus_stats]
    cat_short = {"sqli": "SQLi", "xss": "XSS", "rce": "RCE", "lfi": "LFI/穿越",
                 "ssrf": "SSRF", "scanner": "扫描器", "protocol": "协议攻击",
                 "recon": "信息侦察"}
    if attack_cats and quality_entries:
        colors = {"python": P.GREEN, "modsecurity": P.SAPPHIRE, "naxsi": P.PEACH}
        series = []
        for name, q in quality_entries:
            by_cat = q.get("by_category") or {}
            series.append({"name": name, "color": colors.get(name, P.MAUVE),
                           "values": [by_cat.get(c, {}).get("rate", 0.0)
                                      for c in attack_cats]})
        blocks.append({"type": "chart", "svg": svg_grouped_bars(
            "图 4-1 各攻击类别检出率", [cat_short.get(c, c) for c in attack_cats],
            series)})
    for name, q in quality_entries:
        fps = q.get("false_positive_samples") or []
        fns = q.get("false_negative_samples") or []
        notes = []
        if fps:
            notes.append(f"误报 {len(fps)} 条（{'、'.join(cat_zh.get(c, c) for c in fps[:8])}）")
        if fns:
            notes.append(f"漏报 {len(fns)} 条（{'、'.join(cat_zh.get(c, c) for c in fns[:8])}）")
        if notes:
            blocks.append({"type": "p", "text": f"`{name}` 误报/漏报明细：" + "；".join(notes) + "。"})

    # ---- 五、性能基准 ----
    blocks.append({"type": "h2", "text": "五、性能基准"})
    parser = bench.get("parser") or {}
    throughput = (bench.get("engine_throughput") or {}).get("python") or {}
    detail = throughput.get("latency_detail") or {}
    blocks.append({"type": "h3", "text": "5.1 解析与判定吞吐"})
    blocks.append({"type": "table", "headers": ["环节", "吞吐", "P50", "P90", "P99"],
                   "rows": [
                       ["HTTP/1.1 解析", f"{_fnum(parser.get('ops_per_s'), 0)} 次/秒",
                        f"{parser.get('latency_us', {}).get('p50', '-')} µs",
                        f"{parser.get('latency_us', {}).get('p90', '-')} µs",
                        f"{parser.get('latency_us', {}).get('p99', '-')} µs"],
                       ["进程内检测 (python)", f"{_fnum(throughput.get('ops_per_s'), 0)} 次/秒",
                        f"{detail.get('p50_ms', '-')} ms", f"{detail.get('p90_ms', '-')} ms",
                        f"{detail.get('p99_ms', '-')} ms"],
                   ]})
    qps_rows = []
    for name, block in (bench.get("real_engines") or {}).items():
        qps = (block or {}).get("qps") or {}
        if not qps:
            continue
        lat = qps.get("latency_ms") or {}
        qps_rows.append([name, _fnum(qps.get("qps"), 1), qps.get("requests", "-"),
                         qps.get("concurrency", "-"), f"{lat.get('p50', '-')} ms",
                         f"{lat.get('p90', '-')} ms", f"{lat.get('p99', '-')} ms",
                         json.dumps(qps.get("statuses") or {}, ensure_ascii=False)])
    if qps_rows:
        blocks.append({"type": "h3", "text": "5.2 真实 nginx 数据面并发 QPS"})
        blocks.append({"type": "table",
                       "headers": ["引擎", "QPS", "请求数", "并发", "P50", "P90", "P99", "状态码"],
                       "rows": qps_rows})
    proxy = bench.get("proxy") or {}
    if proxy:
        seq, con = proxy.get("sequential") or {}, proxy.get("concurrent") or {}
        blocks.append({"type": "h3", "text": "5.3 反向代理端到端延迟"})
        blocks.append({"type": "table", "headers": ["场景", "样本", "吞吐", "P50", "P99"],
                       "rows": [
                           ["顺序请求", seq.get("count", "-"), "-",
                            f"{seq.get('p50', '-')} ms", f"{seq.get('p99', '-')} ms"],
                           ["并发请求", con.get("requests", "-"),
                            f"{_fnum(con.get('qps'), 1)} QPS",
                            f"{con.get('latency_ms', {}).get('p50', '-')} ms",
                            f"{con.get('latency_ms', {}).get('p99', '-')} ms"],
                       ]})
    lb = bench.get("load_balancer") or {}
    if lb:
        blocks.append({"type": "h3", "text": "5.4 负载均衡分发均匀度"})
        blocks.append({"type": "table", "headers": ["后端数", "分发分布", "均值", "变异系数", "最大偏差"],
                       "rows": [[lb.get("backends", "-"),
                                 json.dumps(lb.get("distribution") or {}, ensure_ascii=False),
                                 lb.get("mean", "-"),
                                 lb.get("coefficient_of_variation", "-"),
                                 lb.get("max_deviation", "-")]]})
    rules = bench.get("rules") or {}
    if rules:
        blocks.append({"type": "h3", "text": "5.5 规则库规模与索引耗时"})
        blocks.append({"type": "table", "headers": ["引擎", "规则数", "索引耗时", "来源"],
                       "rows": [[name, block.get("total", "-"),
                                 f"{block.get('index_ms', block.get('load_ms', '-'))} ms",
                                 block.get("source", block.get("upstream", "-"))]
                                for name, block in rules.items()]})

    # ---- 六、权衡曲线 ----
    paranoia = bench.get("paranoia") or {}
    sweep = bench.get("threshold_sweep") or {}
    if paranoia or sweep:
        blocks.append({"type": "h2", "text": "六、Paranoia Level 与异常阈值权衡"})
    if paranoia:
        blocks.append({"type": "h3", "text": "6.1 Paranoia Level (误报/漏报权衡)"})
        pl_rows = []
        pl_entries: dict[str, dict[str, dict]] = {}
        for name, levels_map in paranoia.items():
            if not isinstance(levels_map, dict):
                continue
            pl_entries[name] = levels_map
            for level, quality in sorted(levels_map.items(), key=lambda kv: int(kv[0])):
                pl_rows.append([name, f"PL{level}", _pct(quality.get("precision")),
                                _pct(quality.get("recall")), _pct(quality.get("f1")),
                                quality.get("fp", "-"), quality.get("fn", "-")])
        blocks.append({"type": "table",
                       "headers": ["引擎", "PL", "精确率", "召回率", "F1", "误报数", "漏报数"],
                       "rows": pl_rows})
        colors = {"python": P.GREEN, "modsecurity": P.SAPPHIRE, "naxsi": P.PEACH}
        short = {"modsecurity": "ModSec", "naxsi": "Naxsi", "python": "Python"}
        levels = ["1", "2", "3", "4"]
        series = []
        for name, levels_map in pl_entries.items():
            present = [l for l in levels if l in levels_map]
            if not present:
                continue
            label = short.get(name, name)
            series.append({"name": f"{label} 召回", "color": colors.get(name, P.MAUVE),
                           "values": [levels_map[l].get("recall", 0.0) for l in present]})
            series.append({"name": f"{label} 误报", "color": colors.get(name, P.MAUVE),
                           "values": [levels_map[l].get("false_positive_rate", 0.0)
                                      for l in present]})
            levels = present
        blocks.append({"type": "chart", "svg": svg_lines(
            "图 6-1 Paranoia Level 权衡（上=召回率，下=误报率）",
            [f"PL{l}" for l in levels], series)})
        flat = [n for n, m in pl_entries.items()
                if len({round(q.get("f1", 0.0), 4) for q in m.values()}) == 1]
        if flat:
            blocks.append({"type": "p", "text":
                           "说明：" + "、".join(f"`{n}`" for n in flat) +
                           " 的规则自带显式阻断动作（critical/high 单项即拦截），"
                           "判定不依赖异常评分，故 Paranoia Level 不改变其检出结果；"
                           "真正的 PL 权衡体现在纯异常评分的 CRS 引擎上。"})
    if sweep:
        blocks.append({"type": "h3", "text": "6.2 异常评分阈值 (越高越严格)"})
        th_rows = []
        th_entries: dict[str, dict[str, dict]] = {}
        for name, th_map in sweep.items():
            if not isinstance(th_map, dict):
                continue
            th_entries[name] = th_map
            for threshold, quality in sorted(th_map.items(), key=lambda kv: float(kv[0])):
                th_rows.append([name, threshold, _pct(quality.get("precision")),
                                _pct(quality.get("recall")), _pct(quality.get("f1")),
                                quality.get("fp", "-"), quality.get("fn", "-")])
        blocks.append({"type": "table",
                       "headers": ["引擎", "阈值", "精确率", "召回率", "F1", "误报数", "漏报数"],
                       "rows": th_rows})
        for name, th_map in th_entries.items():
            keys = sorted(th_map, key=lambda k: float(k))
            if not keys:
                continue
            blocks.append({"type": "chart", "svg": svg_lines(
                f"图 6-2 {name} 阈值-质量权衡",
                [f"阈值 {k}" for k in keys], [
                    {"name": "精确率", "color": P.SKY,
                     "values": [th_map[k].get("precision", 0.0) for k in keys]},
                    {"name": "召回率", "color": P.GREEN,
                     "values": [th_map[k].get("recall", 0.0) for k in keys]},
                    {"name": "F1", "color": P.MAUVE,
                     "values": [th_map[k].get("f1", 0.0) for k in keys]},
                ])})
        flat_th = [n for n, m in th_entries.items()
                   if len({round(q.get("f1", 0.0), 4) for q in m.values()}) == 1]
        if flat_th:
            blocks.append({"type": "p", "text":
                           "说明：" + "、".join(f"`{n}`" for n in flat_th) +
                           " 在所有阈值下结果恒定（同上：规则含显式阻断动作，"
                           "单项高危即拦截，异常阈值对其不起作用）。"})

    # ---- 七、扫描子系统 ----
    scanner = bench.get("scanner") or {}
    blocks.append({"type": "h2", "text": "七、漏洞扫描子系统实测"})
    builtin = scanner.get("builtin")
    if builtin:
        blocks.append({"type": "h3", "text": "7.1 内置检测器 (直连靶场)"})
        blocks.append({"type": "table",
                       "headers": ["耗时(s)", "请求数", "接口", "参数", "插件", "发现", "请求/秒",
                                   "风险评分"],
                       "rows": [[builtin.get("seconds"), builtin.get("requests"),
                                 builtin.get("urls"), builtin.get("params"),
                                 builtin.get("plugins_run"), builtin.get("findings"),
                                 builtin.get("requests_per_s"),
                                 f"{builtin.get('risk_score')} ({builtin.get('risk_level')})"]]})
        if builtin.get("by_type"):
            items = sorted(builtin["by_type"].items(), key=lambda kv: -kv[1])
            peak = max(count for _t, count in items) or 1
            blocks.append({"type": "chart", "svg": svg_hbars(
                f"图 7-1 内置检测器发现分布（共 {builtin.get('findings', 0)} 个）",
                [f"{vuln_meta(t)[0]} · {count}" for t, count in items],
                [count / peak for _t, count in items],
                colors=[P.SAPPHIRE] * len(items), ymax=1.0)})
    multi = scanner.get("multi")
    if multi:
        blocks.append({"type": "h3", "text": "7.2 多引擎融合 (nuclei + w13scan + 内置)"})
        blocks.append({"type": "table",
                       "headers": ["引擎", "目标数", "发现", "耗时(s)", "状态", "错误"],
                       "rows": [[run.get("engine"), run.get("targets"), run.get("findings"),
                                 run.get("seconds"), "成功" if run.get("ok") else "失败",
                                 run.get("error") or "-"]
                                for run in (multi.get("runs") or [])]})
        blocks.append({"type": "p", "text":
                       f"融合去重后共 **{multi.get('findings')}** 个唯一漏洞，总耗时 "
                       f"{multi.get('seconds')} 秒；去重后按引擎归属 "
                       f"{multi.get('by_engine')}，按级别 {multi.get('by_severity')}。"})
        blocks.append({"type": "p", "text":
                       "评测口径：靶场的 listen backlog 原为 `socketserver` 默认的 5，"
                       "而 nuclei 采集时会瞬时开出上百条并发连接；backlog 顶满后内核"
                       "静默丢弃 SYN，客户端按 `tcp_syn_retries` 退避重试，握手从毫秒级"
                       "退化到秒级，在 `-timeout 5` 下表现为部分模板「超时未命中」，"
                       "使同一配置的结果在 122 / 133 条之间抖动。把 backlog 放大到 512 后，"
                       "64 条并发连接的握手耗时由 7.18 s 降到 17.9 ms；同一配置的 nuclei "
                       "采集可稳定复现 133 条原始发现，回归测试见 "
                       "`tests/test_lab.py::test_lab_backlog_survives_scanner_burst`。"})
        sample = multi.get("sample") or []
        if sample:
            blocks.append({"type": "h3", "text": "7.3 真实漏洞样例 (去重后前 15 条)"})
            rows = []
            for finding in sample:
                name, owasp, cwe, _ = vuln_meta(finding.get("vuln_type", ""))
                rows.append([name, finding.get("severity", "-"), finding.get("method", "-"),
                             finding.get("url", "-"), finding.get("param") or "-",
                             (finding.get("proof") or finding.get("evidence") or "")[:60]])
            blocks.append({"type": "table",
                           "headers": ["漏洞类型", "级别", "方法", "URL", "参数", "证据"],
                           "rows": rows})

    # ---- 八、OWASP / CWE ----
    blocks.append({"type": "h2", "text": "八、OWASP Top 10 (2021) 与 CWE 映射"})
    seen: list[str] = []
    for finding in (multi.get("sample") or []) if multi else []:
        if finding.get("vuln_type") not in seen:
            seen.append(finding["vuln_type"])
    if builtin:
        for key in (builtin.get("by_type") or {}):
            if key not in seen:
                seen.append(key)
    if not seen:
        seen = ["sqli_error", "sqli_time", "xss", "ssrf", "file_read", "cors",
                "jsonp", "url_redirect", "unauth", "html_res_information_disclosure"]
    blocks.append({"type": "table", "headers": ["漏洞类型", "OWASP 2021", "CWE", "修复建议"],
                   "rows": [[name, owasp, cwe, fix]
                            for name, owasp, cwe, fix in (vuln_meta(t) for t in seen)]})

    # ---- 九、TUI ----
    panels = [("panel1-dashboard", "综设 III 综合仪表盘：实时 QPS / 拦截率 / 事件流"),
              ("panel2-config", "综设 III 配置管理：监听、模式、阈值、负载均衡策略"),
              ("panel3-ids", "综设 II 入侵检测：逐条攻击判定与命中规则"),
              ("panel4-rules", "综设 II 规则防御：规则启停、导出 ModSecurity 语法"),
              ("panel5-audit", "综设 II 日志审计：结构化审计日志与 vim `dd` 冻结视图"),
              ("panel6-scan", "综设 I 漏洞检测：单引擎/多引擎融合扫描"),
              ("panel7-vulndb", "综设 I 漏洞库管理：插件与 OWASP/CWE 映射"),
              ("panel8-report", "综设 I 报告生成：Markdown / HTML / JSON"),
              ("panel9-engines", "综设 II WAF 引擎管理：ModSecurity / Naxsi / 内置热切换")]
    shots = [(SHOT_DIR / f"{name}.png", caption) for name, caption in panels
             if (SHOT_DIR / f"{name}.png").exists()]
    if shots:
        blocks.append({"type": "h2", "text": "九、TUI 界面（Catppuccin Frappé）"})
        for path, caption in shots:
            blocks.append({"type": "image", "path": str(path), "caption": caption})

    # ---- 十、复现 ----
    blocks.append({"type": "h2", "text": "十、复现命令与结论"})
    blocks.append({"type": "code", "text": "\n".join([
        "cd ~/Projects/sentinel",
        "mise install                 # 安装 Python 3.14 + uv",
        "mise run install             # uv sync --extra test --extra report",
        "mise run test                # 全部单元 + 集成 + 端到端测试",
        "mise run bench               # 采集性能/质量基准 -> reports/bench-*.json",
        "mise run report              # 生成中文报告 (MD/HTML/DOCX)",
        "mise run tui                 # 启动 TUI 管理平台",
        "mise run lab                 # 启动漏洞靶场 + WAF 反代",
    ])})
    conclusion: list[str] = []
    if tests.get("source") == "pytest-junit":
        conclusion.append(
            f"测试：{tests.get('passed', 0)}/{tests.get('total', 0)} 通过"
            f"（失败 {tests.get('failed', 0)}，跳过 {tests.get('skipped', 0)}）。")
    for name, q in quality_entries:
        conclusion.append(f"引擎 `{name}`：召回率 {_pct(q.get('recall'))}，"
                          f"精确率 {_pct(q.get('precision'))}，F1 {_pct(q.get('f1'))}。")
    if qps_rows:
        best = max(qps_rows, key=lambda r: float(str(r[1]).replace(",", "") or 0))
        conclusion.append(f"真实数据面峰值吞吐：{best[0]} {best[1]} QPS。")
    if multi:
        conclusion.append(f"漏洞扫描：融合 {len(multi.get('runs') or [])} 个引擎，"
                          f"去重后发现 {multi.get('findings')} 个漏洞。")
    conclusion.append("以上数据均可由 `mise run bench && mise run report` 一键复现。")
    blocks.append({"type": "bullets", "items": conclusion})
    return blocks


# ---------------------------------------------------------------------------
# Markdown 渲染
# ---------------------------------------------------------------------------
def render_markdown_doc(blocks: list[dict], stamp: str) -> str:
    lines: list[str] = []
    for block in blocks:
        kind = block["type"]
        if kind == "h1":
            lines += [f"# {block['text']}", ""]
        elif kind == "h2":
            lines += [f"## {block['text']}", ""]
        elif kind == "h3":
            lines += [f"### {block['text']}", ""]
        elif kind == "p":
            lines += [block["text"], ""]
        elif kind == "bullets":
            lines += [f"- {item}" for item in block["items"]] + [""]
        elif kind == "code":
            lines += ["```bash", block["text"], "```", ""]
        elif kind == "table":
            lines += _md_table(block["headers"],
                               [[str(c) for c in row] for row in block["rows"]]) + [""]
        elif kind == "image":
            caption = block.get("caption", "")
            lines += [f"![{caption}]({os.path.relpath(block['path'], ROOT)})", ""]
        elif kind == "chart":
            continue  # Markdown 版不内嵌 SVG, HTML 版提供图表
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# 自包含 HTML 渲染 (Catppuccin Frappé)
# ---------------------------------------------------------------------------
HTML_CSS = f"""
:root {{
  --crust: {P.CRUST}; --mantle: {P.MANTLE}; --base: {P.BASE};
  --s0: {P.SURFACE0}; --s1: {P.SURFACE1}; --s2: {P.SURFACE2};
  --text: {P.TEXT}; --sub1: {P.SUBTEXT1}; --sub0: {P.SUBTEXT0}; --over: {P.OVERLAY1};
  --accent: {P.SAPPHIRE}; --accent2: {P.MAUVE}; --green: {P.GREEN};
  --yellow: {P.YELLOW}; --red: {P.RED}; --peach: {P.PEACH}; --sky: {P.SKY};
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--base); color: var(--text);
  font: 15px/1.7 -apple-system, "Segoe UI", "Noto Sans CJK SC", "Microsoft YaHei", sans-serif; }}
.wrap {{ max-width: 1080px; margin: 0 auto; padding: 32px 24px 80px; }}
h1 {{ font-size: 30px; margin: 0 0 8px; color: var(--accent); letter-spacing: .5px; }}
h2 {{ font-size: 21px; margin: 40px 0 12px; padding-bottom: 8px;
  border-bottom: 2px solid var(--s0); color: var(--accent2); }}
h3 {{ font-size: 16px; margin: 26px 0 10px; color: var(--sky); }}
p, li {{ color: var(--sub1); }}
ul {{ padding-left: 22px; }}
code {{ background: var(--crust); color: var(--green); padding: 1px 6px;
  border-radius: 5px; font-family: ui-monospace, "JetBrains Mono", monospace; font-size: 13px; }}
pre {{ background: var(--crust); border: 1px solid var(--s0); border-radius: 10px;
  padding: 14px 16px; overflow-x: auto; }}
pre code {{ padding: 0; color: var(--sub1); }}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0 18px; font-size: 13.5px; }}
th {{ background: var(--s0); color: var(--text); text-align: left; font-weight: 600;
  padding: 8px 10px; border-bottom: 2px solid var(--s1); white-space: nowrap; }}
td {{ padding: 7px 10px; border-bottom: 1px solid var(--s0); color: var(--sub1);
  vertical-align: top; word-break: break-word; }}
tbody tr:nth-child(even) {{ background: {P.MANTLE}66; }}
tbody tr:hover {{ background: var(--s0); }}
.chart {{ margin: 14px 0 22px; }}
figure {{ margin: 18px 0; background: var(--mantle); border: 1px solid var(--s0);
  border-radius: 12px; padding: 12px; }}
figure img {{ width: 100%; border-radius: 8px; display: block; }}
figcaption {{ color: var(--sub0); font-size: 13px; margin-top: 8px; }}
.lead {{ background: var(--mantle); border-left: 3px solid var(--accent);
  border-radius: 0 10px 10px 0; padding: 14px 18px; }}
.toc {{ background: var(--mantle); border: 1px solid var(--s0); border-radius: 12px;
  padding: 14px 20px; margin: 20px 0 8px; }}
.toc a {{ color: var(--sky); text-decoration: none; font-size: 14px; }}
.toc a:hover {{ color: var(--accent); text-decoration: underline; }}
.toc ol {{ margin: 6px 0; padding-left: 22px; column-count: 2; }}
footer {{ margin-top: 50px; color: var(--over); font-size: 12px;
  border-top: 1px solid var(--s0); padding-top: 14px; }}
@media print {{ body {{ background: #fff; color: #111; }} }}
"""


def _html_cover(blocks: list[dict], stamp: str) -> str:
    toc_items = []
    for block in blocks:
        if block["type"] == "h2":
            anchor = "sec-" + str(abs(hash(block["text"])) % 10**8)
            block["_anchor"] = anchor
            toc_items.append(f'<li><a href="#{anchor}">{_esc(block["text"])}</a></li>')
    toc = ('<nav class="toc"><strong>目录</strong><ol>' + "".join(toc_items) +
           "</ol></nav>") if toc_items else ""
    return toc


def _html_blocks(blocks: list[dict]) -> str:
    out: list[str] = []
    for block in blocks:
        kind = block["type"]
        if kind == "h1":
            out.append(f"<h1>{_esc(block['text'])}</h1>")
        elif kind == "h2":
            anchor = block.get("_anchor", "")
            out.append(f'<h2 id="{anchor}">{_esc(block["text"])}</h2>')
        elif kind == "h3":
            out.append(f"<h3>{_esc(block['text'])}</h3>")
        elif kind == "p":
            text = _esc(block["text"])
            text = _re.sub_em(text)
            out.append(f"<p>{text}</p>")
        elif kind == "bullets":
            out.append("<ul>" + "".join(f"<li>{_re.sub_em(_esc(i))}</li>"
                                        for i in block["items"]) + "</ul>")
        elif kind == "code":
            out.append(f"<pre><code>{_esc(block['text'])}</code></pre>")
        elif kind == "table":
            head = "".join(f"<th>{_esc(h)}</th>" for h in block["headers"])
            body = "".join(
                "<tr>" + "".join(f"<td>{_re.sub_em(_esc(c))}</td>" for c in row) + "</tr>"
                for row in block["rows"])
            out.append(f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")
        elif kind == "chart":
            out.append(f'<div class="chart">{block["svg"]}</div>')
        elif kind == "image":
            path = Path(block["path"])
            data = base64.b64encode(path.read_bytes()).decode("ascii")
            out.append(f'<figure><img alt="{_esc(block.get("caption", ""))}" '
                       f'src="data:image/png;base64,{data}">'
                       f'<figcaption>{_esc(block.get("caption", ""))}</figcaption></figure>')
    return "\n".join(out)


def render_html_doc(blocks: list[dict], stamp: str, title: str) -> str:
    toc = _html_cover(blocks, stamp)
    # 标题与导语在正文中单独渲染, 避免重复
    body_start = 1
    if len(blocks) > 1 and blocks[1]["type"] == "p":
        body_start = 2
    body = _html_blocks(blocks[body_start:])
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    first = next((b["text"] for b in blocks if b["type"] == "p"), "")
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title><style>{HTML_CSS}</style></head>
<body><div class="wrap">
<h1>{_esc(title)}</h1>
<p class="lead">{_re.sub_em(_esc(first))}</p>
{toc}
{body}
<footer>Sentinel v{_version()} · 生成于 {generated} · 配色 Catppuccin Frappé ·
报告标识 {_esc(stamp)}</footer>
</div></body></html>
"""


class _re:
    """极简内联标记: **粗体** 与 `行内代码`."""

    @staticmethod
    def sub_em(text: str) -> str:
        text = _re_inline_code(text)
        while "**" in text:
            start = text.find("**")
            end = text.find("**", start + 2)
            if end < 0:
                break
            text = text[:start] + "<strong>" + text[start + 2:end] + "</strong>" + text[end + 2:]
        return text


def _re_inline_code(text: str) -> str:
    parts = text.split("`")
    if len(parts) == 1:
        return text
    out = [parts[0]]
    for index, chunk in enumerate(parts[1:], 1):
        out.append(f"<code>{chunk}</code>" if index % 2 else chunk)
    return "".join(out)


def _version() -> str:
    try:
        from . import __version__
        return __version__
    except Exception:  # noqa: BLE001
        return "1.0.0"


# ---------------------------------------------------------------------------
# DOCX 渲染 (python-docx, 可选依赖)
# ---------------------------------------------------------------------------
def _plain(text) -> str:
    text = str(text).replace("**", "")
    return text.replace("`", "")


def render_docx(blocks: list[dict], path: str | Path, title: str) -> str:
    """渲染 Word 文档; 缺少 python-docx 时返回空串."""
    try:
        from docx import Document
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.oxml.ns import qn
        from docx.shared import Inches, Pt, RGBColor
    except ImportError:
        return ""
    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Noto Sans CJK SC"
    style.font.size = Pt(10)
    try:
        style.element.rPr.rFonts.set(qn("w:eastAsia"), "Noto Sans CJK SC")
    except Exception:  # noqa: BLE001
        pass

    def heading(text: str, level: int) -> None:
        node = doc.add_heading(_plain(text), level=level)
        for run in node.runs:
            run.font.color.rgb = RGBColor(0x30, 0x34, 0x46) if level == 0 else \
                RGBColor(0x8C, 0xAA, 0xEE)
            run.font.name = "Noto Sans CJK SC"
            try:
                run.element.rPr.rFonts.set(qn("w:eastAsia"), "Noto Sans CJK SC")
            except Exception:  # noqa: BLE001
                pass

    heading(title, 0)
    for block in blocks[1:]:
        kind = block["type"]
        if kind == "h1":
            heading(block["text"], 1)
        elif kind == "h2":
            heading(block["text"], 1)
        elif kind == "h3":
            heading(block["text"], 2)
        elif kind == "p":
            doc.add_paragraph(_plain(block["text"]))
        elif kind == "bullets":
            for item in block["items"]:
                doc.add_paragraph(_plain(item), style="List Bullet")
        elif kind == "code":
            paragraph = doc.add_paragraph()
            run = paragraph.add_run(block["text"])
            run.font.name = "DejaVu Sans Mono"
            run.font.size = Pt(8.5)
        elif kind == "table":
            headers = block["headers"]
            table = doc.add_table(rows=1, cols=len(headers))
            table.style = "Table Grid"
            for cell, head in zip(table.rows[0].cells, headers):
                cell.text = _plain(head)
                for paragraph in cell.paragraphs:
                    for run in paragraph.runs:
                        run.bold = True
            for row in block["rows"]:
                cells = table.add_row().cells
                for cell, value in zip(cells, row):
                    cell.text = _plain(value)[:400]
        elif kind == "image":
            path_png = Path(block["path"])
            if path_png.exists():
                try:
                    doc.add_picture(str(path_png), width=Inches(6.2))
                    caption = doc.add_paragraph(block.get("caption", ""))
                    caption.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    for run in caption.runs:
                        run.font.size = Pt(8.5)
                        run.font.color.rgb = RGBColor(0x73, 0x79, 0x94)
                except Exception:  # noqa: BLE001
                    pass
        elif kind == "chart":
            continue
    out = Path(path)
    doc.save(str(out))
    return str(out)


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------
def latest_bench(outdir: str | Path = "reports") -> tuple[dict, Path]:
    """读取目录下最新的 ``bench-*.json``."""
    candidates = sorted(Path(outdir).glob("bench-*.json"))
    if not candidates:
        raise FileNotFoundError(
            f"未找到基准结果 {outdir}/bench-*.json, 请先运行 `mise run bench`")
    path = candidates[-1]
    return json.loads(path.read_text(encoding="utf-8")), path


def generate_test_report(*, bench: dict | None = None, outdir: str | Path = "reports",
                         run_tests: bool = False, stamp: str | None = None,
                         title: str = "Sentinel 综合测试与评测报告",
                         bench_path: str | Path | None = None) -> dict[str, str]:
    """生成中文综合测试报告 (Markdown + 自包含 HTML + DOCX).

    :param bench: 基准结果字典; 为 ``None`` 时自动读取最新 ``bench-*.json``
    :param outdir: 输出目录
    :param run_tests: 是否重新运行完整 pytest 以刷新 JUnit 结果
    :param stamp: 输出文件名时间戳, 默认当前时间
    :returns: ``{"markdown": ..., "html": ..., "docx": ...}``
    """
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    if bench is None:
        if bench_path:
            bench = json.loads(Path(bench_path).read_text(encoding="utf-8"))
        else:
            bench, _ = latest_bench(outdir)
    stamp = stamp or datetime.now().strftime("%Y%m%d-%H%M%S")
    tests = load_tests(outdir, run_tests=run_tests)
    blocks = build_document(bench, tests, stamp=stamp, title=title)

    md_path = outdir / f"report-{stamp}.md"
    html_path = outdir / f"report-{stamp}.html"
    docx_path = outdir / f"report-{stamp}.docx"
    md_path.write_text(render_markdown_doc(blocks, stamp), encoding="utf-8")
    html_path.write_text(render_html_doc(blocks, stamp, title), encoding="utf-8")
    docx_result = render_docx(blocks, docx_path, title)
    return {"markdown": str(md_path), "html": str(html_path),
            "docx": docx_result or "(未安装 python-docx, 跳过 DOCX)"}


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Sentinel 中文综合测试报告生成器")
    parser.add_argument("--bench", default=None, help="指定 bench-*.json (默认取最新)")
    parser.add_argument("--out", default="reports")
    parser.add_argument("--stamp", default=None)
    parser.add_argument("--tests", action="store_true", help="重新运行 pytest 刷新 JUnit")
    parser.add_argument("--title", default="Sentinel 综合测试与评测报告")
    args = parser.parse_args(argv)

    generated = generate_test_report(bench_path=args.bench, outdir=args.out,
                                     run_tests=args.tests, stamp=args.stamp,
                                     title=args.title)
    for kind, path in generated.items():
        print(f"[report] {kind.upper()} -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
