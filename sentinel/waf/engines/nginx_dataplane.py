"""真实 nginx + ModSecurity / Naxsi 数据面 (可选 · 参考实现).

**默认不启用。** Sentinel 日常跑的是进程内原生解释器
(:mod:`sentinel.waf.engines.modsecurity` / :mod:`sentinel.waf.engines.naxsi`),
本模块保留真实 C 引擎, 用于两件事:

1. **语义校对** —— 「同一套 CRS 规则, 两种实现」的差异只能靠真实引擎来发现。
   原生解释器开发过程中踩到的坑 (校验类算子命中于失败、``&TX:`` 计数、
   ``skipAfter`` 分级跳转) 都是用这里的真实数据面比对出来的。
2. **对照基准** —— README 里「原生解释器 vs nginx+ModSecurity」的 QPS 与
   质量对照由它产出。

启用前提: ``tools/build_engines.sh`` 已把 nginx + 模块构建到
``sentinel/build/``。规则数据同样取自 ``sentinel/vendor/`` —— 两种实现
读的是同一份 CRS, 比较才有意义。
"""
from __future__ import annotations

import re
from pathlib import Path

from ...core.models import Alert, Severity
from ...vendor import crs_dir, crs_rules_dir, unicode_mapping
from .base import EngineStatus, RuleView
from .nginx_engine import NginxWafEngine
from .nginx_stack import NginxInstall

# --------------------------------------------------------------------------
# 公共工具 (ModSecurity 规则文本解析)
# --------------------------------------------------------------------------
_CLIENT_RE = re.compile(r"\[client ([0-9a-fA-F:.]+)(?::\d+)?\]")
_ID_RE = re.compile(r"\[id \"(\d+)\"\]")
_MSG_RE = re.compile(r"\[msg \"([^\"]*)\"\]")
_SEV_RE = re.compile(r"\[severity \"([^\"]*)\"\]")
_URI_RE = re.compile(r"\[uri \"([^\"]*)\"\]")
_TAG_RE = re.compile(r"\[tag \"([^\"]*)\"\]")
_FILE_RE = re.compile(r"\[file \"([^\"]*)\"\]")
_DATA_RE = re.compile(r"\[data \"([^\"]*)\"\]")
_DENY_RE = re.compile(r"ModSecurity:\s+(Access denied|Warning|Detected)")
_SCORE_RE = re.compile(r"Total Score:\s*(\d+)")
_ID_ACTION_RE = re.compile(r"\bid:(\d+)")
_MSG_ACTION_RE = re.compile(r"msg:\'((?:[^\'\\]|\\.)*)\'|msg:\"([^\"]*)\"")
_SEV_ACTION_RE = re.compile(r"\bseverity:\'?(\w+)\'?")
_TAG_ACTION_RE = re.compile(r"\btag:\'([^\']*)\'")
_SECRULE_VARS_RE = re.compile(r"^SecRule\s+([^\s\"]+)")
_SECRULE_OP_RE = re.compile(r"\"(?:@?(\w+))\s*([^\"]*)\"")
_TRANSFORM_RE = re.compile(r"\bt:([\w-]+)")

_ENGINE_MODE = {"block": "On", "detect": "DetectionOnly", "off": "Off"}
_NUMERIC_SEVERITY = {
    "0": Severity.CRITICAL, "1": Severity.CRITICAL, "2": Severity.CRITICAL,
    "3": Severity.HIGH, "4": Severity.MEDIUM, "5": Severity.LOW,
    "6": Severity.INFO, "7": Severity.INFO,
}
_SEVERITY_WORDS = {
    "emergency": Severity.CRITICAL, "alert": Severity.CRITICAL,
    "critical": Severity.CRITICAL, "error": Severity.HIGH,
    "warning": Severity.MEDIUM, "notice": Severity.LOW,
}

_NAXSI_FMT = re.compile(r"NAXSI_FMT:\s*(\S+)")
_NAXSI_IDS = re.compile(r"(?:^|&)id(\d+)=(\d+)")
_NAXSI_ZONES = re.compile(r"(?:^|&)zone(\d+)=([A-Z_]+)")
_NAXSI_VARS = re.compile(r"(?:^|&)var_name(\d+)=([^,&]*)")
_NAXSI_TOTAL = re.compile(r"(?:^|&)total_pts=(\d+)")


def _modsec_severity(token: str) -> Severity:
    token = token.strip()
    if token.isdigit():
        return _NUMERIC_SEVERITY.get(token, Severity.MEDIUM)
    return _SEVERITY_WORDS.get(token.lower(), Severity.MEDIUM)


def secaction(rule_id: int, setvars: list[str], tag: str = "OWASP_CRS") -> str:
    """构造一条多行 ``SecAction`` (权威覆盖 CRS 运行变量).

    动作之间必须是 ``,\\`` + 换行; 只写续行符会被 libmodsecurity 判为
    "Expecting an action"。
    """
    lines = [f'    "id:{rule_id},\\', "    phase:1,\\", "    pass,\\", "    t:none,\\",
             "    nolog,\\", f"    tag:'{tag}',\\"]
    for index, var in enumerate(setvars):
        suffix = ",\\" if index < len(setvars) - 1 else '"'
        lines.append(f"    setvar:{var}{suffix}")
    return "SecAction \\\n" + "\n".join(lines)


def _secrule_statements(path: Path) -> list[str]:
    """把 (可能跨多行的) SecRule 语句合并为完整语句列表."""
    statements: list[str] = []
    pending = ""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:                                    # pragma: no cover
        return statements
    for raw in lines:
        line = raw.strip()
        if pending:
            pending += " " + line.rstrip("\\").strip()
            if not line.endswith("\\"):
                statements.append(pending)
                pending = ""
            continue
        if line.startswith("SecRule"):
            if line.endswith("\\"):
                pending = line.rstrip("\\").strip()
            else:
                statements.append(line)
    return statements


# --------------------------------------------------------------------------
# 参考引擎 1: nginx + ModSecurity + CRS
# --------------------------------------------------------------------------
class NginxModSecurityEngine(NginxWafEngine):
    """真实 nginx + libmodsecurity + OWASP CRS."""

    name = "nginx-modsecurity"
    display = "nginx + ModSecurity v3 + OWASP CRS (真实 C 数据面 · 参考)"
    upstream = ("nginx/nginx + owasp-modsecurity/ModSecurity + ModSecurity-nginx"
                " + coreruleset/coreruleset")

    @staticmethod
    def _module_present(install: NginxInstall) -> bool:
        return install.has_modsecurity

    @property
    def rules_dir(self) -> Path:
        return crs_rules_dir()

    def count_rules(self) -> int:
        return len(self.rule_index())

    # ---------------- 配置生成 ----------------
    def _render_crs_setup(self) -> Path:
        """生成 crs-setup.conf 并权威覆盖 PL 与异常阈值.

        CRS 4.x 的 ``crs-setup.conf`` 里 PL/阈值全是**注释**, 且
        ``REQUEST-901`` 只在变量未设置时才填默认值, 因此必须追加生效的
        ``SecAction`` —— 本方法在末尾追加 id:900000 / id:900110 两条动作,
        它们会在 949110 拦截评估之前执行。
        """
        source = crs_dir() / "crs-setup.conf"
        if not source.exists():
            source = crs_dir() / "crs-setup.conf.example"
        text = source.read_text(encoding="utf-8", errors="replace") if source.exists() else ""
        pl = max(1, min(4, self.config.waf.paranoia_level))
        threshold = max(1, int(self.config.waf.anomaly_threshold))
        override = "\n".join([
            "",
            "# " + "-" * 74,
            "# Sentinel 覆盖: paranoia level 与异常评分阈值",
            "# " + "-" * 74,
            secaction(900000, [f"tx.blocking_paranoia_level={pl}",
                               f"tx.detection_paranoia_level={pl}"]),
            "",
            secaction(900110, [f"tx.inbound_anomaly_score_threshold={threshold}",
                               f"tx.outbound_anomaly_score_threshold={max(1, threshold - 1)}"]),
            "",
        ])
        target = self.base / "conf" / "crs-setup.conf"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            f"# Sentinel 生成: OWASP CRS 本地配置\n# paranoia_level={pl} "
            f"anomaly_threshold={threshold}\n" + text + override, encoding="utf-8")
        return target

    def _render_modsec_conf(self) -> Path:
        waf = self.config.waf
        for sub in ("logs", "tmp", "data", "conf"):
            (self.base / sub).mkdir(parents=True, exist_ok=True)
        lines = [
            "# Sentinel 生成: ModSecurity v3 主配置 (JSON 审计日志)",
            f"SecRuleEngine {_ENGINE_MODE.get(waf.mode, 'On')}",
            "SecRequestBodyAccess On",
            f"SecRequestBodyLimit {max(1024, waf.max_body_bytes * 8)}",
            f"SecRequestBodyNoFilesLimit {max(1024, waf.max_body_bytes)}",
            "SecRequestBodyLimitAction Reject",
            "SecPcreMatchLimit 100000",
            "SecPcreMatchLimitRecursion 100000",
            "SecResponseBodyAccess Off",
            f"SecTmpDir {self.base / 'tmp'}/",
            f"SecDataDir {self.base / 'data'}/",
            "SecAuditEngine RelevantOnly",
            'SecAuditLogRelevantStatus "^(?:5|4(?!04))"',
            "SecAuditLogParts ABIJDEFHZ",
            "SecAuditLogType Serial",
            "SecAuditLogFormat JSON",
            f"SecAuditLog {self.base / 'logs' / 'modsec_audit.log'}",
            f"SecDebugLog {self.base / 'logs' / 'modsec_debug.log'}",
            "SecDebugLogLevel 0",
            "SecArgumentSeparator &",
            "SecCookieFormat 0",
        ]
        mapping = unicode_mapping()
        if mapping.exists():
            lines.append(f"SecUnicodeMapFile {mapping} 20127")
        lines += [f"Include {self._render_crs_setup()}",
                  f"Include {self.rules_dir}/*.conf", ""]
        target = self.base / "conf" / "modsecurity.conf"
        target.write_text("\n".join(lines), encoding="utf-8")
        return target

    def prepare_rules(self) -> tuple[list[str], list[str], list[str]]:
        conf = self._render_modsec_conf()
        enabled = self.config.waf.enabled and self.config.waf.mode != "off"
        return ([f"modsecurity {'on' if enabled else 'off'};",
                 f"modsecurity_rules_file {conf};"], [], ["modsecurity off;"])

    # ---------------- 事件解析 ----------------
    def parse_event(self, line: str) -> Alert | None:
        if "ModSecurity:" not in line or not _DENY_RE.search(line):
            return None
        rule = _ID_RE.search(line)
        if rule is None:
            return None
        severity_text = _SEV_RE.search(line)
        message = _MSG_RE.search(line)
        uri = _URI_RE.search(line)
        client = _CLIENT_RE.search(line)
        source = _FILE_RE.search(line)
        data = _DATA_RE.search(line)
        score = _SCORE_RE.search(line)
        evidence = (f"anomaly_score={score.group(1)}" if score
                    else (data.group(1)[:300] if data else ""))
        return Alert(
            rule_id=int(rule.group(1)),
            message=message.group(1) if message else "ModSecurity 拦截",
            severity=_modsec_severity(severity_text.group(1)) if severity_text
            else Severity.MEDIUM,
            client=client.group(1) if client else "-",
            url=uri.group(1) if uri else "/",
            category="crs" if source and "REQUEST-" in source.group(1) else "modsecurity",
            evidence=evidence,
            tags=tuple(_TAG_RE.findall(line)),
        )

    # ---------------- 规则清单 ----------------
    def rule_index(self) -> list[RuleView]:
        out: list[RuleView] = []
        for path in sorted(self.rules_dir.glob("*.conf")):
            for statement in _secrule_statements(path):
                rid = _ID_ACTION_RE.search(statement)
                if rid is None:
                    continue
                msg = _MSG_ACTION_RE.search(statement)
                msg_text = ""
                if msg is not None:
                    msg_text = msg.group(2) if msg.lastindex == 2 and not msg.group(1) \
                        else (msg.group(1) or "")
                tags = _TAG_ACTION_RE.findall(statement)
                category = "generic"
                for tag in tags:
                    if tag.startswith("attack-"):
                        category = tag[len("attack-"):]
                        break
                sev_token = _SEV_ACTION_RE.search(statement)
                variables = _SECRULE_VARS_RE.search(statement)
                operator = _SECRULE_OP_RE.search(statement)
                out.append(RuleView(
                    id=int(rid.group(1)),
                    description=msg_text or f"CRS {path.stem}",
                    severity=_modsec_severity(sev_token.group(1)) if sev_token
                    else Severity.MEDIUM,
                    category=category,
                    action="block" if re.search(r"\b(?:block|deny)\b", statement) else "log",
                    source=path.name,
                    variables=variables.group(1).split("|") if variables else [],
                    operator=operator.group(1) if operator else "",
                    operator_arg=operator.group(2) if operator else "",
                    transforms=_TRANSFORM_RE.findall(statement),
                    tags=tags,
                    secrule=statement[:400],
                ))
        return out

    def export_rules(self, path) -> int:
        out: list[str] = []
        count = 0
        for conf in sorted(self.rules_dir.glob("*.conf")):
            for line in conf.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.lstrip().startswith("SecRule"):
                    out.append(f"# {conf.name}\n{line.strip()}")
                    count += 1
        Path(path).write_text("\n".join(out) + "\n", encoding="utf-8")
        return count

    def rules_summary(self) -> dict[str, int]:
        return {"crs_rules": self.rules_loaded}


# --------------------------------------------------------------------------
# 参考引擎 2: nginx + Naxsi
# --------------------------------------------------------------------------
_BASE_CHECK = {"SQL": 8, "XSS": 8, "RFI": 8, "TRAVERSAL": 4, "EVADE": 4}


class NginxNaxsiEngine(NginxWafEngine):
    """真实 nginx + Naxsi 原生 C 模块."""

    name = "nginx-naxsi"
    display = "nginx + Naxsi (真实 C 数据面 · 参考)"
    upstream = "nbs-system/naxsi (原生 nginx 模块)"

    @staticmethod
    def _module_present(install: NginxInstall) -> bool:
        return install.has_naxsi

    @property
    def core_rules(self) -> Path | None:
        return self.install.naxsi_core_rules() if self.install else None

    def check_thresholds(self) -> dict[str, int]:
        delta = max(0, min(3, self.config.waf.paranoia_level - 1))
        return {name: max(1, value - delta) for name, value in _BASE_CHECK.items()}

    def count_rules(self) -> int:
        core = self.core_rules
        total = 0
        if core and core.exists():
            total += sum(1 for line in core.read_text(
                encoding="utf-8", errors="replace").splitlines()
                if line.startswith("MainRule"))
        return total

    def prepare_rules(self) -> tuple[list[str], list[str], list[str]]:
        core = self.core_rules
        http: list[str] = [f"include {core};"] if core else []
        mode = self.config.waf.mode if self.config.waf.enabled else "off"
        denied = "/__sentinel_denied"
        location: list[str] = []
        if mode == "off":
            location.append("SecRulesDisabled;")
        else:
            location.append("LearningMode;" if mode == "detect" else "SecRulesEnabled;")
            location.append(f'DeniedUrl "{denied}";')
            for name, value in self.check_thresholds().items():
                location.append(f'CheckRule "${name} >= {value}" BLOCK;')
        self._extra_locations = [
            f'location {denied} {{ internal; return 403 "Naxsi: request blocked\\n"; }}']
        return http, location, ["SecRulesDisabled;"]

    def parse_event(self, line: str) -> Alert | None:
        fmt = _NAXSI_FMT.search(line)
        if fmt is None:
            return None
        raw = fmt.group(1)
        ids = [int(value) for _, value in _NAXSI_IDS.findall(raw)]
        zones = [zone for _, zone in _NAXSI_ZONES.findall(raw)]
        variables = [var for _, var in _NAXSI_VARS.findall(raw) if var]
        total = _NAXSI_TOTAL.search(raw)
        score = int(total.group(1)) if total else 0
        client = _CLIENT_RE.search(line)
        uri_match = re.search(r"(?:^|&)uri=([^,&]*)", raw)
        rule_id = ids[0] if ids else 1000
        return Alert(
            rule_id=rule_id,
            message=f"Naxsi 拦截: 命中规则 {ids or [rule_id]}, 评分 {score}",
            severity=Severity.HIGH if score >= 8 else Severity.MEDIUM,
            client=client.group(1) if client else "-",
            url=uri_match.group(1) if uri_match else "/",
            category="naxsi",
            evidence=f"total_pts={score} zones={zones} vars={variables}",
            tags=tuple(["naxsi", *(f"zone:{z}" for z in zones)]),
        )

    def rule_index(self) -> list[RuleView]:
        core = self.core_rules
        out: list[RuleView] = []
        if not core or not core.exists():
            return out
        for line in core.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.startswith("MainRule"):
                continue
            rid = re.search(r"\bid:(\d+)", line)
            if not rid:
                continue
            msg = re.search(r'"msg:([^"]*)"', line)
            score = re.search(r"s:\$([A-Z_]+):(\d+)", line)
            points = int(score.group(2)) if score else 0
            out.append(RuleView(
                id=int(rid.group(1)),
                description=(msg.group(1) if msg else "Naxsi MainRule"),
                severity=Severity.HIGH if points >= 8 else Severity.MEDIUM,
                category=(score.group(1).lower() if score else "generic"),
                action="block", enabled=True, source="naxsi_core.rules",
                variables=re.findall(r"mz:([^\"']+)", line) or ["ARGS"],
                operator="libinjection",
                operator_arg=f"score>={points}" if points else "",
                secrule=line[:300],
            ))
        return out

    def export_rules(self, path) -> int:
        core = self.core_rules
        lines: list[str] = []
        count = 0
        if core and core.exists():
            for line in core.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("MainRule"):
                    lines.append(line)
                    count += 1
        for name, value in sorted(self.check_thresholds().items()):
            lines.append(f'CheckRule "${name} >= {value}" BLOCK;')
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return count

    def rules_summary(self) -> dict[str, int]:
        return {"naxsi_rules": self.rules_loaded,
                "thresholds": self.check_thresholds()}

    def status(self) -> EngineStatus:
        status = super().status()
        status.extra["reference"] = True
        return status
