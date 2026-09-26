"""入侵检测模块 — 有状态行为分析 (速率/爆破/扫描/异常).

与无状态规则引擎互补: 维护每个来源 IP 的滑动窗口, 识别自动化扫描、认证爆破、
目录爆破与高频攻击等无法由单条规则发现的行为.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from ..core.models import Alert, HttpRequest, Severity

SENSITIVE_HINTS = (
    "/.env", "/.git", "/admin", "/wp-login", "/wp-admin", "/phpmyadmin", "/actuator",
    "/swagger", "/druid", "/.ssh", "/.aws", "/backup", "/config", "/debug", "/shell",
    "/manager/html", "/console", "/api/v1/users", "/etc/passwd",
)
AUTH_HINTS = ("/login", "/signin", "/auth", "/token", "/oauth", "/session", "/wp-login")


@dataclass
class ClientState:
    hits: deque = field(default_factory=lambda: deque(maxlen=4096))
    sensitive: deque = field(default_factory=lambda: deque(maxlen=512))
    auth: deque = field(default_factory=lambda: deque(maxlen=512))
    four_xx: deque = field(default_factory=lambda: deque(maxlen=2048))
    alerts: int = 0
    score: int = 0
    last_seen: float = 0.0
    buckets: dict = field(default_factory=dict)   # 令牌桶


class IdsTracker:
    """行为型 IDS. 线程安全, 常数级内存占用."""

    def __init__(self, window_s: float = 60.0, rate_limit_rps: float = 0.0,
                 rate_limit_burst: int = 0, paranoia_level: int = 1) -> None:
        self.window_s = window_s
        self.rate_limit_rps = rate_limit_rps
        self.rate_limit_burst = rate_limit_burst
        self.paranoia_level = paranoia_level
        self._clients: dict[str, ClientState] = defaultdict(ClientState)
        self._lock = threading.RLock()
        self._cooldown: dict[tuple[str, str], float] = {}

    # ---------- 观测 ----------
    def observe(self, req: HttpRequest, decision_score: int = 0) -> list[Alert]:
        now = time.time()
        ip = req.remote_addr
        alerts: list[Alert] = []
        with self._lock:
            state = self._clients[ip]
            state.hits.append((now, req.target))
            state.last_seen = now
            state.score += decision_score
            low = req.target.lower()
            if any(hint in low for hint in SENSITIVE_HINTS):
                state.sensitive.append((now, req.target))
            if any(hint in low for hint in AUTH_HINTS) and req.method == "POST":
                state.auth.append((now, req.target))
            self._evict(state, now)

            if self.rate_limit_rps > 0:
                limited, rps = self._rate_limit(state, now, req.remote_addr)
                if limited:
                    alerts.append(self._alert(
                        ip, req, 980001, "请求速率超限 (疑似 DoS/CC 攻击)",
                        Severity.HIGH, "ids.rate_limit", f"{rps:.1f} rps", "ids",
                        ("rate-limit", "dos"), cooldown=3.0))

            burst = len(state.hits)
            if burst >= 80:
                alerts.append(self._alert(
                    ip, req, 980002, "单 IP 高频请求 (疑似自动化工具)",
                    Severity.MEDIUM, "ids.high_frequency", f"{burst} req/{self.window_s:.0f}s",
                    "ids", ("scanner",), cooldown=8.0))
            if len(state.sensitive) >= 8:
                alerts.append(self._alert(
                    ip, req, 980003, "敏感路径批量探测 (疑似目录爆破)",
                    Severity.HIGH, "ids.sensitive_sweep",
                    f"{len(state.sensitive)} 次", "ids", ("recon", "bruteforce"),
                    cooldown=8.0))
            if len(state.auth) >= 12:
                alerts.append(self._alert(
                    ip, req, 980004, "认证接口高频尝试 (疑似暴力破解)",
                    Severity.HIGH, "ids.brute_force", f"{len(state.auth)} 次", "ids",
                    ("bruteforce",), cooldown=8.0))
            if state.score >= 30:
                alerts.append(self._alert(
                    ip, req, 980005, "来源 IP 累计异常评分过高",
                    Severity.CRITICAL, "ids.anomaly_accumulation",
                    f"score={state.score}", "ids", ("anomaly",), cooldown=5.0))
        return [a for a in alerts if a is not None]

    def record_response(self, ip: str, status: int) -> list[Alert]:
        now = time.time()
        alerts: list[Alert] = []
        with self._lock:
            state = self._clients.get(ip)
            if state is None:
                return []
            if status >= 400:
                state.four_xx.append((now, status))
            self._evict(state, now)
            count = len(state.four_xx)
            if count >= 25:
                key = (ip, "ids.fourxx")
                if now - self._cooldown.get(key, 0.0) >= 8.0:
                    self._cooldown[key] = now
                    state.alerts += 1
                    alerts.append(Alert(
                        rule_id=980006,
                        message="短时间内大量 4xx (疑似扫描/爆破)",
                        severity=Severity.HIGH,
                        client=ip,
                        url="*",
                        method="*",
                        category="ids",
                        evidence=f"{count} 次 4xx / {self.window_s:.0f}s",
                        tags=("scanner", "bruteforce"),
                    ))
                    state.four_xx.clear()
        return alerts

    # ---------- 供 TUI / 报告查询 ----------
    def top_clients(self, limit: int = 10) -> list[tuple[str, int, int, int]]:
        with self._lock:
            rows = [
                (ip, len(st.hits), len(st.sensitive), st.score)
                for ip, st in self._clients.items()
            ]
        rows.sort(key=lambda row: (row[3], row[1]), reverse=True)
        return rows[:limit]

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "tracked_clients": len(self._clients),
                "total_alerts": sum(st.alerts for st in self._clients.values()),
            }

    # ---------- 内部 ----------
    def _evict(self, state: ClientState, now: float) -> None:
        cutoff = now - self.window_s
        for buf in (state.hits, state.sensitive, state.auth, state.four_xx):
            while buf and buf[0][0] < cutoff:
                buf.popleft()

    def _rate_limit(self, state: ClientState, now: float, ip: str) -> tuple[bool, float]:
        burst = self.rate_limit_burst or max(1, int(self.rate_limit_rps * 2))
        tokens, last = state.buckets.get("token", (float(burst), now))
        tokens = min(float(burst), tokens + (now - last) * self.rate_limit_rps)
        allowed = tokens >= 1.0
        tokens = tokens - 1.0 if allowed else tokens
        state.buckets["token"] = (tokens, now)
        observed = len(state.hits) / max(0.001, self.window_s)
        return (not allowed), observed

    def _alert(self, ip: str, req: HttpRequest, rule_id: int, message: str,
               severity: Severity, category: str, evidence: str, tag: str,
               tags: tuple[str, ...] = (), cooldown: float = 5.0) -> Alert:
        key = (ip, category)
        now = time.time()
        if now - self._cooldown.get(key, 0.0) < cooldown:
            return None  # type: ignore[return-value]
        self._cooldown[key] = now
        self._clients[ip].alerts += 1
        return Alert(rule_id=rule_id, message=message, severity=severity, client=ip,
                     url=req.url, method=req.method, category=category,
                     evidence=evidence, tags=(tag, *tags))

    def reset(self) -> None:
        with self._lock:
            self._clients.clear()
            self._cooldown.clear()
