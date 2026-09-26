"""反向代理与负载均衡 — 后端选择与会话保持."""
from __future__ import annotations

import itertools
import random
import threading
import time
from dataclasses import dataclass, field

from ..core.config import BackendConfig


@dataclass
class Backend:
    config: BackendConfig
    healthy: bool = True
    active: int = 0
    total: int = 0
    failures: int = 0
    last_check: float = 0.0
    latency_ms: float = 0.0
    weight: int = 1

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def address(self) -> str:
        return self.config.address


class LoadBalancer:
    """支持 round_robin / least_conn / random / ip_hash 四种策略."""

    def __init__(self, backends: list[BackendConfig], strategy: str = "round_robin") -> None:
        self._backends = [Backend(cfg, weight=max(1, cfg.weight)) for cfg in backends]
        self.strategy = strategy
        self._lock = threading.RLock()
        self._rr = itertools.cycle(range(len(self._backends))) if self._backends else None
        self._rr_cursor = 0

    @property
    def backends(self) -> list[Backend]:
        return self._backends

    def healthy_backends(self) -> list[Backend]:
        return [b for b in self._backends if b.healthy]

    def pick(self, client: str = "") -> Backend | None:
        with self._lock:
            candidates = self.healthy_backends() or self._backends
            if not candidates:
                return None
            if self.strategy == "least_conn":
                return min(candidates, key=lambda b: (b.active, b.total))
            if self.strategy == "random":
                return random.choice(candidates)
            if self.strategy == "ip_hash":
                return candidates[hash(client) % len(candidates)]
            # round_robin (加权简化为整数权重轮转)
            pool: list[Backend] = []
            for backend in candidates:
                pool.extend([backend] * backend.weight)
            backend = pool[self._rr_cursor % len(pool)]
            self._rr_cursor += 1
            return backend

    def acquire(self, backend: Backend) -> None:
        with self._lock:
            backend.active += 1
            backend.total += 1

    def release(self, backend: Backend, ok: bool = True, latency_ms: float = 0.0) -> None:
        with self._lock:
            backend.active = max(0, backend.active - 1)
            if ok:
                backend.failures = 0
                backend.latency_ms = latency_ms
            else:
                backend.failures += 1
                if backend.failures >= 3:
                    backend.healthy = False
                    backend.last_check = time.time()

    def mark(self, backend: Backend, healthy: bool) -> None:
        with self._lock:
            backend.healthy = healthy
            backend.last_check = time.time()
            if healthy:
                backend.failures = 0

    def stats(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "name": b.name,
                    "address": b.address,
                    "healthy": b.healthy,
                    "active": b.active,
                    "total": b.total,
                    "failures": b.failures,
                    "latency_ms": round(b.latency_ms, 3),
                }
                for b in self._backends
            ]
