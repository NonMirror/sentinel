"""SecRule 规则语言解析 (ModSecurity 兼容).

本模块把 ``.conf`` 文本变成结构化规则, 覆盖 OWASP CRS 实际用到的全部语法。
实现要点 (都是真实规则里存在的坑):

1. **续行**: 反斜杠 + 换行在引号内被**整体删除**, 在引号外替换为一个空格。
   一律换成空格会破坏跨行的正则, 一律删除则会粘死操作符与动作串;
   必须区分引号状态。
2. **引号感知的分隔**: ``msg:'a, b'`` 里的逗号不是动作分隔符, 因此动作串
   按顶层逗号切分, 而不是先去掉引号再 split。
3. **链式规则**: 父规则带 ``chain`` 时, 紧随其后的规则是链的一环 (最多无限层)。
4. **``&`` 计数目标**: ``&TX:foo`` 求值得到匹配到的变量**个数**, 而不是值。
5. **``!`` 取反** 同时出现在目标层 (``!ARGS:x``) 与算子层 (``!@rx``)。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# 文本层
# --------------------------------------------------------------------------
_QUOTES = ("'", '"')


def logical_statements(text: str) -> list[str]:
    """把物理行按 ModSecurity 续行规则合并为逻辑语句.

    注释 (``#``) 必须在**扫描期**丢弃, 不能事后过滤: CRS 的注释里满是
    ``don't`` / ``isn't`` 之类的不成对撇号, 一旦进入引号状态机, 整个文件的
    引号配对就会错位, 后续所有语句被当成同一个字符串。
    """
    out: list[str] = []
    buffer: list[str] = []
    quote = ""
    escaped = False
    line_start = True
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\n":
            out.append("".join(buffer))
            buffer = []
            quote = ""          # 未闭合的引号不得跨行泄漏 (防御性)
            escaped = False
            line_start = True
            index += 1
            continue
        if escaped:
            buffer.append(char)
            escaped = False
            line_start = False
            index += 1
            continue
        if char == "\\":
            nxt = text[index + 1] if index + 1 < length else ""
            if nxt in ("\r", "\n"):
                index += 2
                if nxt == "\r" and index < length and text[index] == "\n":
                    index += 1
                if not quote:
                    buffer.append(" ")   # 引号外: 续行退化为空白
                line_start = False
                continue                 # 引号内: 续行整体删除
            buffer.append(char)
            escaped = True
            line_start = False
            index += 1
            continue
        if quote:
            buffer.append(char)
            index += 1
            if char == quote:
                quote = ""
            continue
        if char == "#" and (line_start or not buffer or buffer[-1].isspace()):
            while index < length and text[index] != "\n":
                index += 1
            continue
        if char in _QUOTES:
            quote = char
            buffer.append(char)
            line_start = False
            index += 1
            continue
        if char.isspace():
            buffer.append(char)
            index += 1
            continue
        buffer.append(char)
        line_start = False
        index += 1
    if buffer:
        out.append("".join(buffer))
    return out


def split_top_level(text: str, separator: str = ",") -> list[str]:
    """按顶层分隔符切分, 忽略引号内的分隔符 (引号保留在结果里)."""
    parts: list[str] = []
    buffer: list[str] = []
    quote = ""
    escaped = False
    for char in text:
        if escaped:
            buffer.append(char)
            escaped = False
            continue
        if char == "\\":
            buffer.append(char)
            escaped = True
            continue
        if quote:
            buffer.append(char)
            if char == quote:
                quote = ""
            continue
        if char in _QUOTES:
            quote = char
            buffer.append(char)
            continue
        if char == separator:
            parts.append("".join(buffer))
            buffer = []
            continue
        buffer.append(char)
    parts.append("".join(buffer))
    return [p.strip() for p in parts if p.strip()]


def split_words(text: str) -> list[str]:
    """按顶层空白切分 (引号内空白保留, 引号去除后返回内容).

    ``\\`` 转义必须参与状态机: CRS 的算子里会出现 ``\\"{2}`` 这样的
    转义引号, 若把 ``\\"`` 当成收尾引号, 后面的动作串会被整段吞掉。
    """
    parts: list[str] = []
    buffer: list[str] = []
    quote = ""
    escaped = False
    for char in text:
        if escaped:
            buffer.append(char)
            escaped = False
            continue
        if char == "\\":
            buffer.append(char)
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
                continue
            buffer.append(char)
            continue
        if char in _QUOTES:
            quote = char
            continue
        if char.isspace():
            if buffer:
                parts.append("".join(buffer))
                buffer = []
            continue
        buffer.append(char)
    if buffer:
        parts.append("".join(buffer))
    return parts


def unquote(text: str) -> str:
    """去掉包裹整个字符串的一对引号 (只去一层)."""
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in _QUOTES:
        return text[1:-1]
    return text


# --------------------------------------------------------------------------
# 结构层
# --------------------------------------------------------------------------
@dataclass(slots=True)
class Variable:
    """一个规则目标 (``REQUEST_HEADERS:User-Agent`` 等)."""

    name: str
    selectors: tuple[str, ...] = ()
    negated: bool = False
    count: bool = False
    #: 目标层写法原文, 供规则清单展示
    raw: str = ""

    @property
    def key(self) -> str:
        return self.name + "".join(f":{s}" for s in self.selectors)

    def __str__(self) -> str:
        prefix = ("!" if self.negated else "") + ("&" if self.count else "")
        return f"{prefix}{self.key}"


#: 规范名 (小写) -> ModSecurity 官方驼峰写法, 用于 TUI / 规则导出
OPERATOR_DISPLAY = {
    "rx": "@rx", "pm": "@pm", "pmfromfile": "@pmFromFile",
    "ipmatch": "@ipMatch", "ipmatchfromfile": "@ipMatchFromFile",
    "containsword": "@containsWord", "beginswith": "@beginsWith",
    "endswith": "@endsWith", "validatebyterange": "@validateByteRange",
    "validateutf8encoding": "@validateUtf8Encoding",
    "validateurlencoding": "@validateUrlEncoding",
    "detectsqli": "@detectSQLi", "detectxss": "@detectXSS",
    "unconditionalmatch": "@unconditionalMatch", "nomatch": "@noMatch",
    "streq": "@streq", "strmatch": "@strmatch", "within": "@within",
    "contains": "@contains", "rsub": "@rsub",
    "eq": "@eq", "ne": "@ne", "ge": "@ge", "gt": "@gt", "le": "@le", "lt": "@lt",
}


@dataclass(slots=True)
class Operator:
    """算子 (``@rx`` / ``@pm`` / ``@ge`` / ...)."""

    name: str = "rx"
    argument: str = ""
    negated: bool = False
    #: 参数含 ``%{...}`` 宏时需每次求值, 不能预编译
    dynamic: bool = False
    #: 预编译的正则 (仅 @rx 且非动态)
    compiled: re.Pattern[str] | None = None
    #: @pmFromFile 载入的词表
    words: tuple[str, ...] = ()
    #: 词表缺失时的告警 (供引擎健康检查展示)
    warning: str = ""


@dataclass(slots=True)
class Action:
    name: str
    argument: str = ""

    def __str__(self) -> str:
        return self.name if not self.argument else f"{self.name}:{self.argument}"


#: 处置类动作 (disruptive) —— 决定请求的最终命运
DISRUPTIVE = ("pass", "allow", "block", "deny", "drop")


@dataclass(slots=True)
class Rule:
    """一条完整的 SecRule / SecAction."""

    id: int = 0
    phase: int = 2
    variables: tuple[Variable, ...] = ()
    operator: Operator = field(default_factory=Operator)
    actions: tuple[Action, ...] = ()
    transforms: tuple[str, ...] = ()
    chained: bool = False
    chain: tuple["Rule", ...] = ()

    msg: str = ""
    logdata: str = ""
    severity: str = ""
    tags: tuple[str, ...] = ()
    disruptive: str = ""
    status: int = 0
    capture: bool = False
    multi_match: bool = False
    log: bool = True
    audit_log: bool = True
    setvars: tuple[str, ...] = ()
    ctl: tuple[str, ...] = ()
    skip: int = 0
    skip_after: str = ""
    #: ``SecRuleUpdateTargetById`` 追加的目标 (含 ``!`` 排除项)
    extra_targets: tuple[Variable, ...] = ()
    #: 解析到但引擎未实现的动作 (供健康检查, 避免静默降级)
    unknown_actions: tuple[str, ...] = ()
    source: str = ""
    line: int = 0
    raw: str = ""

    @property
    def exclusions(self) -> tuple[Variable, ...]:
        return tuple(v for v in self.extra_targets if v.negated)

    @property
    def additions(self) -> tuple[Variable, ...]:
        return tuple(v for v in self.extra_targets if not v.negated)

    @property
    def is_action_rule(self) -> bool:
        """无目标无算子的 SecAction (只执行动作)."""
        return not self.variables

    def action_names(self) -> tuple[str, ...]:
        return tuple(a.name for a in self.actions)

    def has_paranoia_tag(self) -> int | None:
        for tag in self.tags:
            if tag.startswith("paranoia-level/"):
                try:
                    return int(tag.rsplit("/", 1)[1])
                except ValueError:
                    return None
        return None


@dataclass(slots=True)
class Marker:
    """``SecMarker`` 跳转锚点."""

    name: str
    source: str = ""
    line: int = 0


Item = Rule | Marker


@dataclass(slots=True)
class RuleSet:
    """规则集合: 保持**定义顺序** (ModSecurity 语义依赖顺序)."""

    items: list[Item] = field(default_factory=list)
    settings: dict[str, str] = field(default_factory=dict)
    default_actions: dict[int, tuple[Action, ...]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    @property
    def rules(self) -> list[Rule]:
        return [item for item in self.items if isinstance(item, Rule)]

    def summary(self) -> dict[str, int]:
        rules = self.rules
        by_phase: dict[str, int] = {}
        for rule in rules:
            key = str(rule.phase)
            by_phase[key] = by_phase.get(key, 0) + 1
        return {
            "total": len(rules),
            "markers": sum(1 for i in self.items if isinstance(i, Marker)),
            "chained": sum(1 for r in rules if r.chained),
            "sources": len(self.sources),
            **{f"phase_{k}": v for k, v in by_phase.items()},
        }


# --------------------------------------------------------------------------
# 目标解析
# --------------------------------------------------------------------------
def parse_variables(text: str) -> tuple[Variable, ...]:
    """解析规则目标串 (``A|B|!C``)."""
    out: list[Variable] = []
    for chunk in text.split("|"):
        chunk = chunk.strip()
        if not chunk:
            continue
        raw = chunk
        negated = chunk.startswith("!")
        if negated:
            chunk = chunk[1:].strip()
        count = chunk.startswith("&")
        if count:
            chunk = chunk[1:].strip()
        parts = chunk.split(":")
        name = parts[0].strip().upper()
        selectors = tuple(p.strip() for p in parts[1:] if p.strip())
        out.append(Variable(name=name, selectors=selectors, negated=negated,
                            count=count, raw=raw))
    return tuple(out)


# --------------------------------------------------------------------------
# 算子解析
# --------------------------------------------------------------------------
_MACRO_RE = re.compile(r"%\{[^}]*\}")


def parse_operator(text: str, base_dir: Path | None = None) -> Operator:
    """解析算子串 (``!@rx pattern`` / ``@pmFromFile words.data``)."""
    text = text.strip()
    negated = False
    if text.startswith("!"):
        negated = True
        text = text[1:].lstrip()
    if not text.startswith("@"):
        # 裸正则 (``SecRule ARGS "foo"``) 等价于 @rx
        return Operator(name="rx", argument=text, negated=negated,
                        dynamic=bool(_MACRO_RE.search(text)),
                        compiled=_compile(text) if not _MACRO_RE.search(text) else None)
    name, _, argument = text[1:].partition(" ")
    name = name.strip().lower()
    argument = argument.strip()
    operator = Operator(name=name, argument=argument, negated=negated,
                        dynamic=bool(_MACRO_RE.search(argument)))
    _prepare(operator, base_dir)
    return operator


def _compile(pattern: str) -> re.Pattern[str] | None:
    """编译正则 (走 :mod:`operators` 的缓存与方言改写).

    必须走同一条路径: 否则健康检查里「PCRE 方言改写 / 编译失败」永远是 0,
    解释器的实际覆盖率就被掩盖了。延迟导入避免 syntax <-> operators 循环依赖。
    """
    from .operators import compile_pattern
    return compile_pattern(pattern)


def _prepare(operator: Operator, base_dir: Path | None) -> None:
    """预编译正则 / 装载词表 (只在加载期做一次).

    ``Operator.name`` 一律是**小写规范名** (``pmfromfile`` / ``detectsqli``);
    显示用的驼峰写法由 :data:`OPERATOR_DISPLAY` 还原。曾经这里按驼峰比较,
    导致 ``@pmFromFile`` / ``@detectSQLi`` 静默退化成「永不命中」——
    词表为空、且不报错, 是最难发现的一类失效。
    """
    if operator.dynamic:
        return
    if operator.name == "rx":
        operator.compiled = _compile(operator.argument)
        if operator.compiled is None:
            operator.warning = f"正则编译失败: {operator.argument[:80]}"
    elif operator.name == "pm" and operator.argument:
        operator.words = tuple(w for w in operator.argument.split() if w)
    elif operator.name in ("pmfromfile", "ipmatchfromfile"):
        path = _resolve_data(operator.argument, base_dir)
        if path is None:
            operator.warning = f"未找到数据文件: {operator.argument}"
            return
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:                      # pragma: no cover - 权限等
            operator.warning = f"读取失败 {path.name}: {exc}"
            return
        operator.words = tuple(
            line.strip() for line in lines
            if line.strip() and not line.lstrip().startswith("#"))
        if not operator.words:
            operator.warning = f"数据文件为空: {path.name}"


def _resolve_data(name: str, base_dir: Path | None) -> Path | None:
    candidate = Path(name)
    if candidate.is_absolute() and candidate.exists():
        return candidate
    roots = [base_dir] if base_dir else []
    roots.append(Path.cwd())
    for root in roots:
        if root is None:
            continue
        path = root / name
        if path.exists():
            return path
        # CRS 的 @pmFromFile 有时只给文件名, 数据文件与规则同目录
        path = root / Path(name).name
        if path.exists():
            return path
    return None


# --------------------------------------------------------------------------
# 动作解析
# --------------------------------------------------------------------------
def parse_actions(text: str) -> tuple[Action, ...]:
    """解析动作串."""
    out: list[Action] = []
    for chunk in split_top_level(text, ","):
        chunk = unquote(chunk).strip()
        if not chunk:
            continue
        name, sep, argument = chunk.partition(":")
        # 取值两侧的引号是**语法**而非内容: ``tag:'OWASP_CRS'`` 的标签就是
        # OWASP_CRS。留着引号会让 tag 匹配、类别推断、setvar 全部失准。
        out.append(Action(name=name.strip().lower(),
                          argument=unquote(argument.strip()) if sep else ""))
    return tuple(out)


_SEVERITY_WORDS = {
    "emergency": "critical", "alert": "critical", "critical": "critical",
    "error": "high", "warning": "medium", "notice": "low", "info": "info",
    "debug": "info",
}


def normalise_severity(token: str) -> str:
    token = token.strip().strip("'\"").lower()
    if token.isdigit():
        return {0: "critical", 1: "critical", 2: "critical", 3: "high",
                4: "medium", 5: "low", 6: "info", 7: "info"}.get(int(token), "medium")
    return _SEVERITY_WORDS.get(token, "medium")


# --------------------------------------------------------------------------
# 语句 -> 规则
# --------------------------------------------------------------------------
_NON_RULE_PREFIXES = (
    "SecRuleEngine", "SecRequestBodyAccess", "SecResponseBodyAccess",
    "SecRequestBodyLimit", "SecRequestBodyNoFilesLimit", "SecRequestBodyLimitAction",
    "SecResponseBodyLimit", "SecResponseBodyLimitAction", "SecPcreMatchLimit",
    "SecPcreMatchLimitRecursion", "SecTmpDir", "SecDataDir", "SecAuditEngine",
    "SecAuditLog", "SecAuditLogParts", "SecAuditLogType", "SecAuditLogFormat",
    "SecAuditLogStorageDir", "SecAuditLogRelevantStatus", "SecDebugLog",
    "SecDebugLogLevel", "SecArgumentSeparator", "SecCookieFormat",
    "SecUnicodeMapFile", "SecComponentSignature", "SecCollectionTimeout",
    "SecSensorId", "SecActionSandbox", "SecContentInjection", "SecStreamInBodyInspection",
    "SecStreamOutBodyInspection", "SecResponseBodyMimeType", "SecResponseBodyMimeTypesClear",
    "SecUploadDir", "SecUploadKeepFiles", "SecUploadFileMode", "SecUploadFileLimit",
    "SecRuleInheritance", "SecInterceptOnError", "SecXmlExternalEntity",
    "SecCollectionTimeout", "Include", "LoadModule",
)

_TAG_RE = re.compile(r"paranoia-level/(\d)")


def parse_statement(statement: str, *, source: str = "", line: int = 0,
                    base_dir: Path | None = None) -> Rule | Marker | tuple | None:
    """解析一条逻辑语句; 返回 Rule / Marker / (设置名, 值) / None."""
    text = statement.strip()
    if not text or text.startswith("#"):
        return None

    keyword, _, rest = text.partition(" ")
    keyword = keyword.strip()
    rest = rest.strip()

    if keyword == "SecMarker":
        return Marker(name=unquote(rest).strip(), source=source, line=line)

    if keyword in ("SecRule", "SecAction"):
        return _parse_rule(keyword, rest, source=source, line=line, base_dir=base_dir)

    if keyword == "SecDefaultAction":
        # 每个 phase 的默认处置动作; CRS 用 "phase:N,log,auditlog,pass" 把
        # 规则里普遍存在的 `block` 动作降级为「只记录」, 拦截另由 949 的 deny 完成。
        return ("__default_action__", unquote(rest))

    if keyword in ("SecRuleUpdateTargetById", "SecRuleUpdateTargetByTag",
                   "SecRuleUpdateTargetByMsg", "SecRuleUpdateActionById",
                   "SecRuleRemoveById", "SecRuleRemoveByTag", "SecRuleRemoveByMsg"):
        # 延迟到规则全部加载后再应用 (CRS 的排除指令写在规则文件末尾)
        return ("__update__", text)

    if keyword in _NON_RULE_PREFIXES or keyword.startswith("Sec"):
        return (keyword, rest)

    return None


def _parse_rule(keyword: str, rest: str, *, source: str, line: int,
                base_dir: Path | None) -> Rule | None:
    tokens = split_words(rest)
    if keyword == "SecAction":
        if not tokens:
            return None
        actions = parse_actions(" ".join(tokens))
        rule = Rule(actions=actions, source=source, line=line, raw=rest[:400])
        _absorb(rule)
        return rule
    if len(tokens) < 2:
        return None
    variables = parse_variables(tokens[0])
    operator = parse_operator(tokens[1], base_dir)
    actions = parse_actions(" ".join(tokens[2:])) if len(tokens) > 2 else ()
    rule = Rule(variables=variables, operator=operator, actions=actions,
                source=source, line=line, raw=rest[:400])
    _absorb(rule)
    return rule


#: 需要按名分派的动作 —— 全部小写, 与 :func:`parse_actions` 的规范化一致。
#: 曾经这里按驼峰比较 (``skipAfter`` / ``multiMatch``), 结果 Paranoia Level
#: 的分级跳转**从未生效**, PL2/PL3 的规则在 PL1 下照跑 —— 误报并且拖慢一切。
_ACTION_NAMES = frozenset({
    "t", "msg", "logdata", "severity", "tag", "phase", "id", "status", "capture",
    "multimatch", "log", "nolog", "auditlog", "noauditlog", "setvar", "ctl",
    "chain", "skip", "skipafter", "expirevar", "initcol", "setenv", "ver",
    "rev", "maturity", "accuracy", "xmlns", *DISRUPTIVE,
})


def _absorb(rule: Rule) -> None:
    """把动作列表摊平到规则的字段上."""
    transforms: list[str] = []
    tags: list[str] = []
    setvars: list[str] = []
    ctl: list[str] = []
    for action in rule.actions:
        name, argument = action.name, action.argument
        if name == "t":
            if argument.lower() == "none":
                transforms = []
            else:
                transforms.append(argument)
        elif name == "msg":
            rule.msg = argument
        elif name == "logdata":
            rule.logdata = argument
        elif name == "severity":
            rule.severity = normalise_severity(argument)
        elif name == "tag":
            tags.append(argument)
        elif name == "phase":
            rule.phase = _phase_of(argument)
        elif name == "id":
            try:
                rule.id = int(argument)
            except ValueError:
                rule.id = 0
        elif name in DISRUPTIVE:
            rule.disruptive = name
        elif name == "status":
            try:
                rule.status = int(argument)
            except ValueError:
                rule.status = 0
        elif name == "capture":
            rule.capture = True
        elif name == "multimatch":
            rule.multi_match = True
        elif name == "log":
            rule.log = True
        elif name == "nolog":
            rule.log = False
        elif name == "auditlog":
            rule.audit_log = True
        elif name == "noauditlog":
            rule.audit_log = False
        elif name == "setvar":
            setvars.append(argument)
        elif name == "ctl":
            ctl.append(argument)
        elif name == "chain":
            rule.chained = True
        elif name == "skip":
            try:
                rule.skip = int(argument)
            except ValueError:
                rule.skip = 0
        elif name == "skipafter":
            rule.skip_after = argument
        elif name not in _ACTION_NAMES:
            # 未实现的动作必须显式记录, 而不是静默吞掉
            rule.unknown_actions = rule.unknown_actions + (name,)
    rule.transforms = tuple(transforms)
    rule.tags = tuple(tags)
    rule.setvars = tuple(setvars)
    rule.ctl = tuple(ctl)
    if not rule.phase:
        rule.phase = 2


def _phase_of(argument: str) -> int:
    argument = argument.strip().lower()
    named = {"request": 1, "requestheaders": 1, "requestbody": 2,
             "response": 3, "responseheaders": 3, "responsebody": 4,
             "logging": 5}
    if argument in named:
        return named[argument]
    try:
        return int(argument)
    except ValueError:
        return 2


# --------------------------------------------------------------------------
# 规则集加载
# --------------------------------------------------------------------------
def load_ruleset(paths, *, phase_filter: tuple[int, ...] = (1, 2)) -> RuleSet:
    """加载若干个 ``.conf`` / 目录, 返回保持定义顺序的 :class:`RuleSet`.

    链式规则在这里被装配: 父规则 ``chain`` 之后的语句依次挂到 ``rule.chain``。
    """
    ruleset = RuleSet()
    updates: list[str] = []
    files = _expand(paths)
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:                     # pragma: no cover
            ruleset.warnings.append(f"{path}: {exc}")
            continue
        ruleset.sources.append(str(path))
        base_dir = path.parent
        pending_chain: Rule | None = None
        for index, statement in enumerate(logical_statements(text), start=1):
            item = parse_statement(statement, source=path.name, line=index,
                                   base_dir=base_dir)
            if item is None:
                continue
            if isinstance(item, tuple):
                key, value = item
                if key == "__update__":
                    updates.append(value)
                elif key == "__directive__":
                    ruleset.warnings.append(f"未处理的指令: {value[:60]}")
                elif key == "__default_action__":
                    actions = parse_actions(value)
                    phase = next((_phase_of(a.argument) for a in actions
                                  if a.name == "phase"), 2)
                    ruleset.default_actions[phase] = actions
                else:
                    ruleset.settings[key] = value
                continue
            if isinstance(item, Marker):
                pending_chain = None
                ruleset.items.append(item)
                continue
            if pending_chain is not None:
                pending_chain.chain = pending_chain.chain + (item,)
                if not item.chained:
                    pending_chain = None
                continue
            ruleset.items.append(item)
            if item.chained:
                pending_chain = item
    _apply_updates(ruleset, updates)
    return ruleset


def _apply_updates(ruleset: RuleSet, updates: list[str]) -> None:
    """应用 ``SecRuleUpdateTargetById`` / ``SecRuleRemoveById`` 等事后指令.

    CRS 用它们豁免 Google Analytics 之类的正常流量 (例如把 ``_ga`` cookie
    从 XSS/SQLi 规则的检查面里摘掉); 忽略它们会实打实抬高误报。
    """
    if not updates:
        return
    by_id = {rule.id: rule for rule in ruleset.items
             if isinstance(rule, Rule) and rule.id}
    removed: set[int] = set()
    for statement in updates:
        tokens = split_words(statement)
        if len(tokens) < 2:
            continue
        keyword, selector = tokens[0], tokens[1]
        payload = tokens[2] if len(tokens) > 2 else ""
        targets = _select_rules(ruleset, by_id, selector)
        if not targets:
            continue
        if keyword == "SecRuleRemoveById":
            removed.update(rule.id for rule in targets)
        elif keyword == "SecRuleUpdateTargetByTag" or keyword.startswith(
                "SecRuleUpdateTargetBy"):
            for rule in targets:
                rule.extra_targets = rule.extra_targets + parse_variables(payload)
        elif keyword == "SecRuleUpdateActionById":
            extra = parse_actions(payload)
            rule = targets[0]
            rule.actions = rule.actions + extra
            _absorb(rule)
    if removed:
        ruleset.items = [
            item for item in ruleset.items
            if not (isinstance(item, Rule) and item.id in removed)]


def _select_rules(ruleset: RuleSet, by_id: dict[int, Rule],
                  selector: str) -> list[Rule]:
    """按 id / 标签 / 消息定位目标规则."""
    selector = selector.strip()
    if selector.isdigit():
        rule = by_id.get(int(selector))
        return [rule] if rule else []
    if selector.isdigit() or "," in selector:
        out = []
        for token in selector.split(","):
            token = token.strip()
            if token.isdigit() and int(token) in by_id:
                out.append(by_id[int(token)])
        return out
    needle = selector.strip("'\"")
    return [rule for rule in ruleset.rules if needle in rule.tags]


def _expand(paths) -> list[Path]:
    out: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            out.extend(sorted(path.glob("*.conf")))
        elif path.exists():
            out.append(path)
    return out
