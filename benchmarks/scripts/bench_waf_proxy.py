"""WAF 端到端 (真实代理形态) bench.

启动 SentinelRuntime (原生 ModSecurity 引擎 + 靶场后端), 以原始报文回放
攻击/良性样本, 统计 403/200 与端到端延迟. 与进程内判定互为佐证.

    python bench_waf_proxy.py --engine modsecurity --attacks 400 --benign 120
"""
from __future__ import annotations

import argparse
import json
import socket
import statistics
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[2]))
sys.path.insert(0, str(_HERE.parent))

from bench_waf import build_attacks, load_benign  # noqa: E402
from benchmarks.corpus import build_corpus  # noqa: E402
from sentinel.core.config import Config  # noqa: E402
from sentinel.runtime import SentinelRuntime  # noqa: E402


def raw_status(base: str, raw: bytes, timeout: float = 15.0) -> tuple[int, float]:
    parts = urlsplit(base)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or 80
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(raw)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            status = int(data.split(b" ", 2)[1]) if data else -1
    except OSError:
        status = -1
    return status, (time.perf_counter() - t0) * 1000.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default="modsecurity")
    ap.add_argument("--attacks", type=int, default=400)
    ap.add_argument("--benign", type=int, default=120)
    ap.add_argument("--out", default="")
    ns = ap.parse_args()

    attacks, _meta = build_attacks(4096)
    benign, _ = load_benign()
    # 均匀抽样, 覆盖全部类别
    step = max(1, len(attacks) // ns.attacks)
    sample = attacks[::step][:ns.attacks]
    bstep = max(1, len(benign) // ns.benign)
    bsample = benign[::bstep][:ns.benign]

    cfg = Config()
    cfg.listener.host, cfg.listener.port = "127.0.0.1", 0
    cfg.lab.base_port, cfg.lab.instances = 0, 2
    cfg.audit_path = "/tmp/opencode/results/proxy-audit.jsonl"
    runtime = SentinelRuntime(cfg, engine=ns.engine).start()
    base = f"http://127.0.0.1:{runtime.front_port}"
    print(f"[*] 引擎 {runtime.engine_name} 前端 {base}")

    def replay(samples, expect):
        blocked = 0
        lat = []
        for raw in samples:
            payload = raw.raw if hasattr(raw, "raw") else raw
            status, ms = raw_status(base, payload)
            lat.append(ms)
            blocked += int(status == 403)
        ordered = sorted(lat)

        def pct(p):
            return round(ordered[min(len(ordered) - 1, max(0, int(len(ordered) * p) - 1))], 2)
        return {"n": len(samples), "blocked": blocked, "expect": expect,
                "p50": pct(0.50), "p90": pct(0.90), "p99": pct(0.99),
                "mean": round(statistics.fmean(lat), 2)}

    t0 = time.perf_counter()
    a = replay(sample, "block")
    b = replay(bsample, "pass")
    wall = time.perf_counter() - t0
    runtime.stop()

    out = {"engine": ns.engine, "front": base,
           "attack_recall": round(a["blocked"] / a["n"], 4) if a["n"] else 0.0,
           "false_positive_rate": round(b["blocked"] / b["n"], 4) if b["n"] else 0.0,
           "attacks": a, "benign": b,
           "seconds": round(wall, 2),
           "qps": round((a["n"] + b["n"]) / wall, 1) if wall else 0.0}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    if ns.out:
        Path(ns.out).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                encoding="utf-8")
        print(f"[+] JSON -> {ns.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
