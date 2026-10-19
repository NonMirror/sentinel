"""项目自带靶场多引擎扫描 (设计内目标).

    python bench_lab.py --out /tmp/opencode/results/lab-multi.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[2]))

from sentinel.core.config import Config  # noqa: E402
from sentinel.lab.flags import VULN_NAMES  # noqa: E402
from sentinel.runtime import SentinelRuntime  # noqa: E402

#: 漏洞类别 -> 该类别在扫描结果里可能出现的 vuln_type 关键词
EXPECT = {
    "sqli": ("sqli",),
    "xss_reflected": ("xss",),
    "xss_stored": ("xss",),
    "lfi": ("file_read", "lfi", "traversal", "download"),
    "ssrf": ("ssrf",),
    "open_redirect": ("redirect",),
    "cors": ("cors",),
    "jsonp": ("jsonp",),
    "admin": ("unauth", "admin", "access"),
    "debug": ("info", "disclosure", "exposure"),
    "api_leak": ("info", "disclosure", "error"),
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engines", default="nuclei,w13scan,builtin")
    ap.add_argument("--timeout", type=float, default=420.0)
    ap.add_argument("--out", default="")
    ns = ap.parse_args()

    cfg = Config()
    cfg.listener.host, cfg.listener.port = "127.0.0.1", 0
    cfg.lab.base_port, cfg.lab.instances = 0, 3
    cfg.audit_path = "/tmp/opencode/results/lab-audit.jsonl"
    runtime = SentinelRuntime(cfg, engine="modsecurity").start()
    try:
        targets = runtime.scan_targets()
        engines = [e.strip() for e in ns.engines.split(",") if e.strip()]
        print(f"[*] 靶场后端 {runtime.lab_urls()}")
        print(f"[*] 目标 {len(targets)} 个端点 · 引擎 {engines}")
        t0 = time.perf_counter()
        outcome = runtime.scan_multi(targets, engines=engines, timeout_s=ns.timeout)
        elapsed = time.perf_counter() - t0
    finally:
        runtime.stop()

    types = Counter(f.vuln_type for f in outcome.findings)
    sev = Counter(f.severity.value for f in outcome.findings)
    hit = {cls: any(any(k in t for t in types) for k in keys)
           for cls, keys in EXPECT.items()}
    print(f"\n[*] 用时 {elapsed:.1f}s · 融合 {len(outcome.findings)} 个发现")
    print(f"    严重度 {dict(sev)}")
    print(f"    类型 {dict(types)}")
    print("\n    靶场漏洞类别覆盖:")
    for cls, ok in hit.items():
        print(f"      [{'HIT ' if ok else 'MISS'}] {cls:16} {VULN_NAMES.get(cls, '')}")
    print(f"\n    覆盖 {sum(hit.values())}/{len(hit)} 类")
    for run in outcome.runs:
        print(f"    - {run.engine:9} ok={run.ok} 发现={run.findings} {run.seconds:.1f}s")

    if ns.out:
        Path(ns.out).write_text(json.dumps({
            "lab_urls": runtime.lab_urls(), "engines": engines,
            "seconds": round(elapsed, 3), "fused": len(outcome.findings),
            "by_type": dict(types), "by_severity": dict(sev),
            "coverage": hit,
            "runs": [r.as_dict() for r in outcome.runs],
            "findings": [f.as_dict() for f in outcome.findings],
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[+] JSON -> {ns.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
