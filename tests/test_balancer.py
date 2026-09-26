"""负载均衡策略与健康检查测试."""
from __future__ import annotations

from collections import Counter

import pytest

from sentinel.core.config import BackendConfig
from sentinel.waf.balancer import LoadBalancer


def backends(n: int = 3):
    return [BackendConfig(f"app-{i}", "127.0.0.1", 9000 + i) for i in range(1, n + 1)]


def test_round_robin_cycles_evenly():
    lb = LoadBalancer(backends(3), "round_robin")
    picks = Counter(lb.pick("c").name for _ in range(30))
    assert set(picks.values()) == {10}


def test_round_robin_respects_weight():
    cfgs = [BackendConfig("a", "127.0.0.1", 9001, weight=3),
            BackendConfig("b", "127.0.0.1", 9002, weight=1)]
    lb = LoadBalancer(cfgs, "round_robin")
    picks = Counter(lb.pick("c").name for _ in range(40))
    assert picks["a"] == 30 and picks["b"] == 10


def test_least_conn_prefers_idle_backend():
    lb = LoadBalancer(backends(3), "least_conn")
    first = lb.pick("c")
    lb.acquire(first)
    lb.acquire(first)
    second = lb.pick("c")
    assert second is not first


def test_random_and_ip_hash_stay_in_pool():
    for strategy in ("random", "ip_hash"):
        lb = LoadBalancer(backends(3), strategy)
        names = {lb.pick("192.0.2.10").name for _ in range(40)}
        assert names <= {b.name for b in lb.backends}
    hashed = LoadBalancer(backends(3), "ip_hash")
    assert hashed.pick("192.0.2.10").name == hashed.pick("192.0.2.10").name


def test_unhealthy_backend_removed_from_pool():
    lb = LoadBalancer(backends(2), "round_robin")
    bad, good = lb.backends
    lb.mark(bad, False)
    assert {lb.pick("c").name for _ in range(10)} == {good.name}


def test_failures_mark_backend_unhealthy():
    lb = LoadBalancer(backends(1), "round_robin")
    backend = lb.backends[0]
    for _ in range(3):
        lb.acquire(backend)
        lb.release(backend, ok=False)
    assert backend.healthy is False
    lb.mark(backend, True)
    assert backend.healthy is True and backend.failures == 0


def test_acquire_release_tracks_connections():
    lb = LoadBalancer(backends(1))
    backend = lb.backends[0]
    lb.acquire(backend)
    lb.acquire(backend)
    assert backend.active == 2 and backend.total == 2
    lb.release(backend, ok=True, latency_ms=12.5)
    assert backend.active == 1 and backend.latency_ms == 12.5


def test_stats_structure():
    lb = LoadBalancer(backends(2))
    stats = lb.stats()
    assert len(stats) == 2
    assert set(stats[0]) >= {"name", "address", "healthy", "active", "total",
                             "failures", "latency_ms"}


def test_empty_backend_list_returns_none():
    assert LoadBalancer([], "round_robin").pick("c") is None


def test_allocation_is_thread_safe():
    import threading

    lb = LoadBalancer(backends(4), "round_robin")
    results: list[str] = []
    lock = threading.Lock()

    def worker():
        local = [lb.pick("c").name for _ in range(50)]
        with lock:
            results.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 400
