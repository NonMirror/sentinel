"""ModSecurity 规则语言引擎 —— Sentinel 原生 SecRule 解释器.

**不再调用 libmodsecurity。** 规则语言由 :mod:`sentinel.waf.secrule` 自行解释,
规则数据来自 ``sentinel/vendor/crs`` (由 ``tools/vendor.py`` 从上游收敛入仓),
因此本引擎不依赖任何 C 工具链、不需要构建、也不依赖同级工程目录。

语义上刻意对齐 ModSecurity, 几个已经踩过并固化下来的点 (详见
:mod:`sentinel.waf.secrule.syntax`):

* 校验类算子 (``@validateByteRange`` / ``@validateUtf8Encoding`` /
  ``@validateUrlEncoding``) **命中于校验失败**, 与字面直觉相反;
* ``&TX:x`` 取的是**命中个数**, CRS 的默认值填充全靠它;
* ``SecDefaultAction ... pass`` 把规则里普遍的 ``block`` 降级为「只计分」,
  真正的拦截来自 ``REQUEST-949`` 的 ``deny``;
* Paranoia Level 由 ``skipAfter`` + ``SecMarker`` 分级跳转实现。

原始 nginx + libmodsecurity 数据面仍作为**参考实现**保留
(:mod:`sentinel.waf.engines.nginx_dataplane`), 用于对照与基准复现。
"""
from __future__ import annotations

import re
from pathlib import Path

_SOURCE_RE = re.compile(r"REQUEST-\d+-([A-Z-]+)")

from ...core.models import Decision, HttpRequest, Severity, Verdict
from ...vendor import crs_rules_dir, crs_setup_conf
from ..secrule import EngineVerdict, SecRuleEngine
from ..secrule.syntax import load_ruleset
from .base import RuleView
from .native import InProcessEngine, rule_summary_from

#: 引擎名称保留 ``modsecurity`` —— 它执行的是 ModSecurity 的规则语言与
#: OWASP CRS 规则库; ``display`` 与 ``upstream`` 会说明解释器是 Sentinel 自己的。
ENGINE_NAME = "modsecurity"


class ModSecurityEngine(InProcessEngine):
    """OWASP CRS 引擎 (原生 SecRule 解释器)."""

    name = ENGINE_NAME
    display = "ModSecurity 规则语言 + OWASP CRS (Sentinel 原生解释器)"
    upstream = ("owasp-modsecurity/ModSecurity (规则语言, Apache-2.0) + "
                "coreruleset/coreruleset (规则数据, Apache-2.0) — "
                "解释器为 sentinel.waf.secrule 自研实现")
    verdict_for_block = Verdict.BLOCK

    def __init__(self, config, *, bus=None, audit=None, metrics=None,
                 rules_dir: Path | None = None) -> None:
        super().__init__(config, bus=bus, audit=audit, metrics=metrics)
        self._rules_dir = Path(rules_dir) if rules_dir else crs_rules_dir()
        self.engine: SecRuleEngine | None = None
        self._load()

    # ------------------------------------------------------------------
    # 资源定位
    # ------------------------------------------------------------------
    @property
    def rules_dir(self) -> Path:
        return self._rules_dir

    @property
    def setup_conf(self) -> Path:
        return crs_setup_conf()

    def sources(self) -> list[Path]:
        """规则来源: crs-setup.conf 先于请求侧规则文件.

        只装载 ``REQUEST-*.conf``: 本引擎实现对**请求侧** (phase 1/2) 的两个
        阶段求值, ``RESPONSE-*`` 属于响应侧 (phase 3/4), 装进来只会虚报规则
        数量、拉长装载时间, 还会把响应侧特有的正则算进解释器覆盖率统计。
        """
        out: list[Path] = []
        setup = self.setup_conf
        if setup.exists():
            out.append(setup)
        if self.rules_dir.exists():
            out.extend(sorted(self.rules_dir.glob("REQUEST-*.conf")))
        return out

    @classmethod
    def available(cls) -> bool:
        """原生实现: 只要 vendor 里有 CRS 规则就可用."""
        return crs_rules_dir().exists() and any(crs_rules_dir().glob("*.conf"))

    # ------------------------------------------------------------------
    # 装载
    # ------------------------------------------------------------------
    def _load(self) -> None:
        paths = self.sources()
        if not paths:
            self.last_error = f"未找到 CRS 规则: {self.rules_dir}"
            self.engine = None
            return
        ruleset = load_ruleset([str(p) for p in paths])
        self.engine = SecRuleEngine(
            ruleset,
            paranoia_level=self.waf_config.paranoia_level,
            anomaly_threshold=self.waf_config.anomaly_threshold,
            enabled=self.waf_config.enabled,
            mode=self.waf_config.mode,
            max_body_bytes=self.waf_config.max_body_bytes,
        )
        self.last_error = ""

    def _sync_config(self) -> None:
        """把当前配置同步到解释器 (模式 / PL / 阈值改了就重建)."""
        engine = self.engine
        if engine is None:
            self._load()
            return
        waf = self.waf_config
        if (engine.paranoia_level != max(1, min(4, waf.paranoia_level))
                or engine.anomaly_threshold != waf.anomaly_threshold
                or engine.mode != waf.mode
                or engine.enabled != waf.enabled):
            self._load()

    # ------------------------------------------------------------------
    # 判定
    # ------------------------------------------------------------------
    def inspect(self, request: HttpRequest) -> Decision:
        self._sync_config()
        engine = self.engine
        if engine is None:
            return self.publish_decision(request, Decision(verdict=Verdict.PASS))
        verdict = engine.inspect(request)
        decision = self.to_decision(verdict, request)
        return self.publish_decision(request, decision, category="crs")

    def to_decision(self, verdict: EngineVerdict, request: HttpRequest) -> Decision:
        """把解释器的判定结果转成统一的 :class:`Decision`."""
        if verdict.blocked:
            raw = verdict.disruptive
            final = Verdict.DROP if raw == "drop" else Verdict.BLOCK
        elif verdict.hits:
            final = Verdict.LOG
        else:
            final = Verdict.PASS
        tags: set[str] = set()
        for hit in verdict.hits:
            tags.update(hit.tags)
        return Decision(
            verdict=final,
            severity=verdict.severity,
            anomaly_score=verdict.anomaly_score,
            matched_rules=list(verdict.matched_rules),
            messages=list(verdict.messages),
            tags=tags,
            phase=verdict.phase,
            elapsed_ms=verdict.elapsed_ms,
        )

    def set_paranoia(self, level: int) -> None:
        super().set_paranoia(level)

    # ------------------------------------------------------------------
    # 观测
    # ------------------------------------------------------------------
    def rule_count(self) -> int:
        return len(self.engine.rules) if self.engine else 0

    def version(self) -> str:
        if self.engine is None:
            return ""
        return f"sentinel-secrule/{len(self.engine.rules)} 条"

    def health(self) -> dict:
        if self.engine is None:
            return {"available": False}
        return self.engine.health()

    def rules_summary(self) -> dict:
        if self.engine is None:
            return {}
        by_source: dict[str, int] = {}
        for rule in self.engine.rules:
            by_source[rule.source] = by_source.get(rule.source, 0) + 1
        return {
            **self.engine.summary(),
            **rule_summary_from(self.rule_index()),
            "by_source": dict(sorted(by_source.items())),
        }

    def rule_index(self, limit: int | None = None) -> list[RuleView]:
        """规则清单 (TUI 的规则防御面板 / 报告)."""
        if self.engine is None:
            return []
        out: list[RuleView] = []
        for rule in self.engine.rules:
            out.append(RuleView(
                id=rule.id,
                description=rule.msg or f"{rule.source} #{rule.id}",
                severity=Severity(rule.severity) if rule.severity else Severity.MEDIUM,
                category=_category_of(rule),
                action=rule.disruptive or "pass",
                enabled=True,
                source=rule.source,
                variables=[str(v) for v in rule.variables],
                operator=rule.operator.name,
                operator_arg=rule.operator.argument[:160],
                transforms=list(rule.transforms),
                tags=list(rule.tags),
                secrule=rule.raw,
            ))
        return out[:limit] if limit else out

    def export_rules(self, path) -> int:
        """导出当前生效的 ModSecurity 规则文本 (规则语言原样)."""
        if self.engine is None:
            return 0
        lines: list[str] = [
            "# Sentinel 导出: ModSecurity 规则语言 (原生解释器执行)",
            f"# 规则数: {len(self.engine.rules)}",
            f"# paranoia_level: {self.waf_config.paranoia_level}",
            "",
        ]
        count = 0
        for rule in self.engine.rules:
            lines.append(f"# {rule.source}:{rule.line}")
            lines.append(_render_rule(rule))
            count += 1
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return count


def _category_of(rule) -> str:
    """从 tag 或来源文件名推断攻击类别 (供 TUI 分类统计)."""
    for tag in rule.tags:
        if tag.startswith("attack-"):
            return tag[len("attack-"):]
    match = _SOURCE_RE.search(rule.source or "")
    if match:
        return match.group(1).lower().replace("application-attack-", "")
    return "generic"


def _render_rule(rule) -> str:
    """把解析后的规则还原成 ModSecurity 语法 (可再次被本解释器读回)."""
    if not rule.variables:
        return f'SecAction "{_render_actions(rule)}"'
    head = (f'SecRule {_render_variables(rule)} '
            f'"{_render_operator(rule)}" "{_render_actions(rule)}"')
    # 链式规则的每一环独占一行并缩进, 与上游 CRS 的书写风格一致
    links = "\n".join(
        f'    SecRule {_render_variables(link)} "{_render_operator(link)}"'
        for link in rule.chain)
    return f"{head}\n{links}" if links else head


def _render_variables(rule) -> str:
    return "|".join(str(v) for v in rule.variables + rule.additions) or "REQUEST_URI"


def _render_operator(rule) -> str:
    prefix = "!" if rule.operator.negated else ""
    argument = f" {rule.operator.argument}" if rule.operator.argument else ""
    return f"{prefix}@{rule.operator.name}{argument}"


def _render_actions(rule) -> str:
    parts = [f"id:{rule.id}", f"phase:{rule.phase}"]
    parts += [f"t:{t}" for t in rule.transforms]
    if rule.msg:
        parts.append(f"msg:'{rule.msg}'")
    if rule.severity:
        parts.append(f"severity:'{rule.severity}'")
    parts += [f"tag:'{tag}'" for tag in rule.tags]
    parts += [f"setvar:{value}" for value in rule.setvars]
    parts += [f"ctl:{value}" for value in rule.ctl]
    if rule.status:
        parts.append(f"status:{rule.status}")
    if rule.capture:
        parts.append("capture")
    if rule.multi_match:
        parts.append("multiMatch")
    if not rule.log:
        parts.append("nolog")
    if rule.disruptive:
        parts.append(rule.disruptive)
    if rule.skip_after:
        parts.append(f"skipAfter:{rule.skip_after}")
    if rule.chained:
        parts.append("chain")
    return ", ".join(parts)
