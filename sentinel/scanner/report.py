"""报告生成模块 — 中文漏洞扫描报告 (Markdown / HTML / JSON)."""
from __future__ import annotations

import json
import os
from datetime import datetime

from .scanner import ScanReport

SEVERITY_ZH = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
               "info": "信息"}
TYPE_ZH = {
    "sqli_error": "SQL 注入 (报错型)",
    "sqli_time": "SQL 注入 (时间盲注)",
    "xss": "跨站脚本 (反射型 XSS)",
    "ssrf": "服务端请求伪造 (SSRF)",
    "cors": "跨域资源共享配置错误",
    "jsonp": "JSONP 数据劫持",
    "file_read": "任意文件读取 (路径穿越)",
    "url_redirect": "开放重定向",
    "unauth": "未授权访问",
    "html_res_information_disclosure": "敏感信息泄露",
}
REMEDIATION = {
    "sqli_error": "使用参数化查询/预编译语句, 禁止字符串拼接 SQL; 对数据库账号最小授权。",
    "sqli_time": "同 SQL 注入: 参数化查询 + 输入白名单校验 + WAF 规则拦截 SLEEP/WAITFOR。",
    "xss": "输出按上下文进行 HTML/JS/URL 编码; 部署 CSP; 输入侧启用实体解码后的检测。",
    "ssrf": "对目标地址做白名单校验, 禁止内网/回环/元数据地址; 禁止 file:// 等协议。",
    "cors": "仅回显白名单来源, 避免 Origin 反射; 携带凭据时禁止使用通配符。",
    "jsonp": "废弃 JSONP, 改用 CORS + JSON; 若必须保留, callback 名称需严格白名单。",
    "file_read": "对文件参数做规范化与白名单校验, 使用 basename 限制目录, 禁止拼接用户路径。",
    "url_redirect": "跳转目标使用服务端映射白名单, 禁止直接把用户参数写入 Location。",
    "unauth": "为管理/调试接口增加统一鉴权与最小权限控制, 生产环境关闭调试端点。",
    "html_res_information_disclosure": "生产环境关闭调试模式, 统一异常处理, 移除响应中的密钥与堆栈。",
}
OWASP_ZH = {"A01:2021": "A01 权限控制失效", "A03:2021": "A03 注入",
            "A05:2021": "A05 安全配置错误", "A10:2021": "A10 服务端请求伪造"}


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def render_markdown(report: ScanReport, title: str = "漏洞扫描报告") -> str:
    target = report.target
    stats = report.stats
    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"- 扫描目标: `{report.seed}`")
    lines.append(f"- 扫描范围: `{report.scope}`{' (深度模式)' if report.deep_scan else ''}")
    lines.append(f"- 开始时间: {_fmt_ts(report.started_at)}")
    lines.append(f"- 结束时间: {_fmt_ts(report.finished_at or report.started_at)}")
    lines.append(f"- 耗时: {stats.duration_s:.2f} 秒 / 发送请求 {stats.requests} 次")
    if target:
        lines.append(f"- 服务指纹: `{target.server or '未知'}` / 技术栈: "
                     f"{', '.join(target.technologies) or '未识别'}")
        lines.append(f"- 资产发现: {stats.urls} 个接口, {stats.params} 个可注入参数")
    lines.append("")
    lines.append("## 一、总体结论")
    lines.append("")
    # ``plugins_run`` 统计的是**执行次数** (每个「接口 x 参数 x 插件」算一次),
    # 不是插件个数 —— 早期写成「N 个检测插件」会让报告里的数字对不上插件清单。
    lines.append(f"共执行 **{stats.plugins_run}** 次检测插件, 发现 **{stats.findings}** 个漏洞, "
                 f"风险评分 **{report.risk_score}** (等级: **{report.risk_level}**)。")
    if stats.findings == 0:
        lines.append("")
        lines.append("未发现可复现的漏洞。")
    lines.append("")
    lines.append("| 严重级别 | 数量 |")
    lines.append("| --- | --- |")
    for sev in ("critical", "high", "medium", "low", "info"):
        count = stats.by_severity.get(sev, 0)
        if count:
            lines.append(f"| {SEVERITY_ZH[sev]} | {count} |")
    lines.append(f"| **合计** | **{stats.findings}** |")
    lines.append("")

    lines.append("## 二、漏洞清单")
    lines.append("")
    if not report.findings:
        lines.append("_无_")
    else:
        lines.append("| # | 漏洞类型 | 级别 | 位置 | 参数 | 置信度 |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for idx, finding in enumerate(report.findings, 1):
            lines.append(
                f"| {idx} | {TYPE_ZH.get(finding.vuln_type, finding.vuln_type)} | "
                f"{SEVERITY_ZH[finding.severity.value]} | `{finding.url}` | "
                f"`{finding.param or '-'}` | {finding.confidence:.2f} |")
    lines.append("")

    if report.findings:
        lines.append("## 三、漏洞详情与修复建议")
        lines.append("")
        for idx, finding in enumerate(report.findings, 1):
            title_zh = TYPE_ZH.get(finding.vuln_type, finding.vuln_type)
            lines.append(f"### {idx}. {title_zh} — {SEVERITY_ZH[finding.severity.value]}")
            lines.append("")
            lines.append(f"- 位置: `{finding.method} {finding.url}`")
            lines.append(f"- 参数: `{finding.param or '-'}`")
            if finding.payload:
                lines.append(f"- 载荷: `{finding.payload}`")
            lines.append(f"- 判定依据: {finding.proof or finding.evidence}")
            if finding.evidence:
                lines.append(f"- 证据片段: `{finding.evidence[:160]}`")
            lines.append(f"- 修复建议: {REMEDIATION.get(finding.vuln_type, '参见 OWASP 建议')}")
            lines.append("")
            lines.append("**复现命令**")
            lines.append("")
            lines.append("```bash")
            lines.append(_curl(finding))
            lines.append("```")
            lines.append("")
    if report.engine_runs:
        lines.append("## 四、多引擎融合执行记录")
        lines.append("")
        lines.append("| 引擎 | 执行 | 发现 | 耗时(s) | 目标数 | 备注 |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for run in report.engine_runs:
            data = run.as_dict() if hasattr(run, "as_dict") else dict(run)
            lines.append(
                f"| `{data.get('engine', '-')}` | "
                f"{'成功' if data.get('ok') else '失败'} | {data.get('findings', 0)} | "
                f"{data.get('seconds', 0)} | {data.get('targets', 0)} | "
                f"{data.get('error') or '-'} |")
        lines.append("")
        lines.append(f"多引擎结果已按 (漏洞类型, 路径, 参数) 指纹去重融合, "
                     f"最终输出 {stats.findings} 条唯一发现。")
        lines.append("")
        lines.append("## 五、测试覆盖")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("| --- | --- |")
    lines.append(f"| 检测插件数 | {len(TYPE_ZH)} |")
    lines.append(f"| 执行插件次数 | {stats.plugins_run} |")
    lines.append(f"| HTTP 请求数 | {stats.requests} |")
    lines.append(f"| 发现接口数 | {stats.urls} |")
    lines.append(f"| 可注入参数数 | {stats.params} |")
    lines.append(f"| 执行错误数 | {stats.errors} |")
    lines.append(f"| 扫描吞吐 | {stats.requests / stats.duration_s:.1f} req/s |"
                 if stats.duration_s else "| 扫描吞吐 | n/a |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("_本报告由 Sentinel 可视化安全运营与管理平台自动生成。_")
    return "\n".join(lines)


def _curl(finding) -> str:
    import shlex
    url = finding.url
    if finding.payload and finding.param:
        from urllib.parse import quote
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{finding.param}={quote(str(finding.payload))}"
    cmd = f"curl -i -sk -X {finding.method} {shlex.quote(url)}"
    return cmd


def render_html(report: ScanReport, title: str = "漏洞扫描报告") -> str:
    stats = report.stats
    rows = []
    for idx, finding in enumerate(report.findings, 1):
        rows.append(f"""<tr class="sev-{finding.severity.value}">
<td>{idx}</td><td>{TYPE_ZH.get(finding.vuln_type, finding.vuln_type)}</td>
<td><span class="badge">{SEVERITY_ZH[finding.severity.value]}</span></td>
<td><code>{_esc(finding.url)}</code></td><td><code>{_esc(finding.param)}</code></td>
<td>{finding.confidence:.2f}</td></tr>""")
    details = []
    for idx, finding in enumerate(report.findings, 1):
        details.append(f"""<div class="finding sev-{finding.severity.value}">
<h3>{idx}. {TYPE_ZH.get(finding.vuln_type, finding.vuln_type)}
<span class="badge">{SEVERITY_ZH[finding.severity.value]}</span></h3>
<p><b>位置</b>: <code>{finding.method} {_esc(finding.url)}</code></p>
<p><b>参数</b>: <code>{_esc(finding.param or '-')}</code>
{' &nbsp; <b>载荷</b>: <code>' + _esc(str(finding.payload)) + '</code>' if finding.payload else ''}</p>
<p><b>判定依据</b>: {_esc(finding.proof or finding.evidence)}</p>
<p><b>证据</b>: <code>{_esc(finding.evidence[:200])}</code></p>
<p><b>修复建议</b>: {_esc(REMEDIATION.get(finding.vuln_type, ''))}</p>
<p><b>复现</b>: <code>{_esc(_curl(finding))}</code></p></div>""")
    by_sev = "".join(
        f"<li>{SEVERITY_ZH[s]}: <b>{stats.by_severity.get(s, 0)}</b></li>"
        for s in ("critical", "high", "medium", "low", "info"))
    runs = [run.as_dict() if hasattr(run, "as_dict") else dict(run)
            for run in (report.engine_runs or [])]
    engine_rows = "".join(
        f"<tr><td><code>{_esc(run.get('engine', '-'))}</code></td>"
        f"<td>{'成功' if run.get('ok') else '失败'}</td><td>{run.get('findings', 0)}</td>"
        f"<td>{run.get('seconds', 0)}</td><td>{run.get('targets', 0)}</td>"
        f"<td>{_esc(run.get('error') or '-')}</td></tr>"
        for run in runs)
    return f"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>{title}</title><style>
body{{font-family:system-ui,-apple-system,'Noto Sans SC',sans-serif;background:#303446;
color:#c6d0f5;margin:0;padding:40px}}
h1{{color:#85c1dc}} h2{{border-bottom:1px solid #51576d;padding-bottom:6px;color:#babbf1}}
code{{background:#292c3c;padding:2px 6px;border-radius:4px;color:#99d1db}}
table{{width:100%;border-collapse:collapse;margin:12px 0}}
th,td{{border:1px solid #51576d;padding:8px;text-align:left;font-size:14px}}
th{{background:#414559;color:#b5bfe2}}
.badge{{background:#414559;padding:2px 8px;border-radius:10px}}
.sev-critical .badge{{background:#e78284;color:#232634}}
.sev-high .badge{{background:#ef9f76;color:#232634}}
.sev-medium .badge{{background:#e5c890;color:#232634}}
.sev-low .badge{{background:#99d1db;color:#232634}}
.finding{{background:#292c3c;border-left:4px solid #85c1dc;padding:12px 18px;
margin:14px 0;border-radius:8px}}
.finding.sev-critical{{border-color:#e78284}} .finding.sev-high{{border-color:#ef9f76}}
.finding.sev-medium{{border-color:#e5c890}} .finding.sev-low{{border-color:#99d1db}}
.summary{{display:flex;gap:24px;flex-wrap:wrap}} .summary div{{background:#292c3c;
padding:14px 20px;border-radius:10px;min-width:150px}}
footer{{color:#838ba7}}
</style></head><body>
<h1>{title}</h1>
<div class="summary">
<div>目标<br><code>{_esc(report.seed)}</code></div>
<div>风险评分<br><b style="font-size:22px">{report.risk_score}</b> ({report.risk_level})</div>
<div>漏洞总数<br><b style="font-size:22px">{stats.findings}</b></div>
<div>请求数<br><b style="font-size:22px">{stats.requests}</b></div>
<div>耗时<br><b style="font-size:22px">{stats.duration_s:.2f}s</b></div>
</div>
<h2>严重级别分布</h2><ul>{by_sev}</ul>
<h2>漏洞清单</h2>
<table><tr><th>#</th><th>类型</th><th>级别</th><th>位置</th><th>参数</th><th>置信度</th></tr>
{''.join(rows) or '<tr><td colspan="6">未发现漏洞</td></tr>'}</table>
<h2>多引擎融合执行记录</h2>
<table><tr><th>引擎</th><th>执行</th><th>发现</th><th>耗时(s)</th><th>目标数</th><th>备注</th></tr>
{engine_rows or '<tr><td colspan="6">单引擎扫描 (内置检测器)</td></tr>'}</table>
<h2>漏洞详情</h2>
{''.join(details) or '<p>无</p>'}
<hr><footer>本报告由 Sentinel 可视化安全运营与管理平台自动生成</footer>
</body></html>"""


def _esc(text) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def render_json(report: ScanReport) -> str:
    return json.dumps(report.as_dict(), ensure_ascii=False, indent=2)


def write_report(report: ScanReport, outdir: str = "reports", prefix: str = "scan",
                 formats: tuple[str, ...] = ("md", "html", "json")) -> dict[str, str]:
    os.makedirs(outdir, exist_ok=True)
    stamp = datetime.fromtimestamp(report.started_at).strftime("%Y%m%d-%H%M%S")
    paths: dict[str, str] = {}
    if "md" in formats:
        path = os.path.join(outdir, f"{prefix}-{stamp}.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(report))
        paths["md"] = path
    if "html" in formats:
        path = os.path.join(outdir, f"{prefix}-{stamp}.html")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_html(report))
        paths["html"] = path
    if "json" in formats:
        path = os.path.join(outdir, f"{prefix}-{stamp}.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_json(report))
        paths["json"] = path
    return paths
