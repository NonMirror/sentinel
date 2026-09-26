"""规则防御模块 — 决策管道.

管道顺序 (对应架构图 "请求解析 -> 协议解析和配置 -> 入侵检测 -> 规则防御 -> 日志审计"):
    1. 协议/URI 规范化与 phase-1 规则 (请求行、头部)
    2. phase-2 规则 (参数、请求体)
    3. 特征签名检测 (libinjection 风格 SQLi/XSS/RCE)
    4. 行为型 IDS 与速率限制
    5. 异常评分汇聚 -> 处置决策 (放行/记录/拦截/丢弃/限速)
"""
from __future__ import annotations

import time

from ..core.audit import AuditLog, AuditRecord
from ..core.config import WafConfig
from ..core.events import EventBus, Topic
from ..core.metrics import Metrics
from ..core.models import Alert, Decision, HttpRequest, Severity, Verdict
from .ids import IdsTracker
from .rules import Match, RuleSet


class WafEngine:
    def __init__(self, config: WafConfig | None = None, ruleset: RuleSet | None = None,
                 bus: EventBus | None = None, audit: AuditLog | None = None,
                 metrics: Metrics | None = None) -> None:
        self.config = config or WafConfig()
        if ruleset is None:
            from .rules import default_rules
            ruleset = RuleSet(default_rules(), self.config.paranoia_level)
        self.ruleset = ruleset
        self.ruleset.paranoia_level = self.config.paranoia_level
        self.bus = bus or EventBus()
        self.audit = audit
        self.metrics = metrics
        self.ids = IdsTracker(rate_limit_rps=self.config.rate_limit_rps,
                              rate_limit_burst=self.config.rate_limit_burst,
                              paranoia_level=self.config.paranoia_level)
        self.stats = {"inspected": 0, "blocked": 0, "logged": 0, "allowed": 0}

    # ------------------------------------------------------------------
    def inspect(self, req: HttpRequest) -> Decision:
        t0 = time.perf_counter()
        cfg = self.config
        decision = Decision()

        if not cfg.enabled or cfg.mode == "off":
            decision.verdict = Verdict.PASS
            self._finish(req, decision, t0)
            return decision

        matches: list[Match] = []
        if len(req.target) > cfg.max_uri_length:
            decision.messages.append(f"URI 超长 ({len(req.target)} > {cfg.max_uri_length})")
            decision.anomaly_score += 5
            decision.matched_rules.append(910001)
            decision.tags.add("protocol")
            decision.severity = max(decision.severity, Severity.MEDIUM, key=lambda s: s.weight)

        body_allowed = cfg.inspect_body and not (req.truncated and cfg.max_body_bytes)
        phase1 = [r for r in self.ruleset.active() if r.phase == 1]
        phase2 = [r for r in self.ruleset.active() if r.phase != 1]
        for rule in phase1:
            matches.extend(rule.matches(req))
        if body_allowed:
            for rule in phase2:
                matches.extend(rule.matches(req))

        forced: Verdict | None = None
        seen_rules: set[int] = set()
        for match in matches:
            rule = match.rule
            if rule.id in seen_rules:
                continue          # 同一规则在一次请求中只计分一次
            seen_rules.add(rule.id)
            decision.anomaly_score += rule.effective_score
            decision.matched_rules.append(rule.id)
            decision.messages.append(rule.description)
            decision.tags.update(rule.tags)
            decision.tags.add(rule.category)
            if rule.severity.weight > decision.severity.weight:
                decision.severity = rule.severity
            if rule.action == "drop":
                forced = Verdict.DROP
            elif rule.action == "block" and forced is None:
                forced = Verdict.BLOCK

        ids_alerts = self.ids.observe(req, decision.anomaly_score)
        for alert in ids_alerts:
            if alert is None:
                continue
            decision.messages.append(alert.message)
            decision.tags.add("ids")
            decision.matched_rules.append(alert.rule_id)
            self.bus.publish(Topic.IDS, alert)
            if self.metrics:
                self.metrics.ids_alerts.inc()
            if alert.severity.weight > decision.severity.weight:
                decision.severity = alert.severity
            if alert.rule_id == 980001:
                forced = forced or Verdict.RATE_LIMIT

        # 处置判定
        if cfg.mode == "detect":
            decision.verdict = Verdict.LOG if (matches or ids_alerts) else Verdict.PASS
        elif forced is not None:
            decision.verdict = forced
        elif (cfg.block_above_threshold
              and decision.anomaly_score >= cfg.anomaly_threshold):
            decision.verdict = Verdict.BLOCK
        elif matches or ids_alerts:
            decision.verdict = Verdict.LOG
        else:
            decision.verdict = Verdict.PASS

        # 高危单项直接拦截 (即使未达阈值, 例如 critical 规则)
        if (cfg.mode == "block" and decision.verdict in (Verdict.PASS, Verdict.LOG)
                and any(m.rule.severity is Severity.CRITICAL and m.rule.action == "block"
                        for m in matches)):
            decision.verdict = Verdict.BLOCK

        self._finish(req, decision, t0, len(matches))
        return decision

    # ------------------------------------------------------------------
    def _finish(self, req: HttpRequest, decision: Decision, t0: float,
                matches: int = 0) -> None:
        decision.elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self.stats["inspected"] += 1
        if decision.blocked:
            self.stats["blocked"] += 1
        elif decision.verdict is Verdict.LOG:
            self.stats["logged"] += 1
        else:
            self.stats["allowed"] += 1

        if self.metrics:
            self.metrics.waf_latency.observe(decision.elapsed_ms)

        self.bus.publish(Topic.DECISION, {
            "url": req.url, "client": req.remote_addr, "verdict": decision.verdict.value,
            "score": decision.anomaly_score, "rules": decision.matched_rules,
            "elapsed_ms": decision.elapsed_ms,
        })
        if decision.blocked:
            alert = Alert(
                rule_id=decision.matched_rules[0] if decision.matched_rules else 0,
                message=decision.messages[0] if decision.messages else "请求被拦截",
                severity=decision.severity, client=req.remote_addr, url=req.url,
                method=req.method, category="waf",
                evidence="; ".join(decision.messages[:3])[:200],
                tags=tuple(sorted(decision.tags))[:6],
            )
            self.bus.publish(Topic.BLOCK, alert)
            if self.audit:
                self.audit.append(AuditRecord(
                    action="block", client=req.remote_addr, method=req.method, url=req.url,
                    status=403, severity=decision.severity.value,
                    rules=tuple(decision.matched_rules[:8]),
                    latency_ms=decision.elapsed_ms,
                ))

    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        return {
            **self.stats,
            "mode": self.config.mode,
            "anomaly_threshold": self.config.anomaly_threshold,
            "rules_total": len(self.ruleset),
            "rules_active": len(self.ruleset.active()),
            "ids": self.ids.stats(),
        }

    def set_paranoia(self, level: int) -> None:
        self.config.paranoia_level = max(1, min(4, level))
        self.ruleset.paranoia_level = self.config.paranoia_level
