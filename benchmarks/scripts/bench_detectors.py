"""Sentinel 内置检测器能力 bench (检测器级, 不经爬虫).

把靶场已知漏洞的 (端点, 参数, 位置) 直接交给检测器, 测"给到注入点能不能报",
从而把「检测能力」和「爬虫/鉴权能力」分开度量 (后者另有局限, 报告里单独说明).

    python bench_detectors.py --cases /tmp/opencode/results/cases-dvwa.json \
        --cookie '...' --out /tmp/opencode/results/dvwa-detectors.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[2]))

from sentinel.core.config import ScannerConfig  # noqa: E402
from sentinel.scanner.client import HttpClient  # noqa: E402
from sentinel.scanner.crawler import Endpoint, Target  # noqa: E402
from sentinel.scanner.detectors import (  # noqa: E402
    ENDPOINT_LEVEL, DetectorContext, run_detectors,
)
from sentinel.scanner.vulndb import default_db  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", required=True)
    ap.add_argument("--cookie", default="")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--out", default="")
    ns = ap.parse_args()

    spec = json.loads(Path(ns.cases).read_text(encoding="utf-8"))
    db = default_db()
    client = HttpClient(timeout=ns.timeout, cookie=ns.cookie)
    results = []
    print(f"[*] {spec.get('label')} · {len(spec['cases'])} 个已知漏洞点\n")
    for case in spec["cases"]:
        endpoint = Endpoint(url=case["endpoint"], method=case.get("method", "GET"),
                            params=[case["param"]] if case.get("position") != "form" else [],
                            form_fields=[case["param"]] if case.get("position") == "form" else [])
        target = Target(base_url=case["endpoint"], host="")
        target.endpoints[endpoint.key] = endpoint
        ctx = DetectorContext(client=client, db=db, target=target, endpoint=endpoint,
                              param=case["param"], position=case.get("position", "query"),
                              time_delay=1, time_threshold_s=2.0)
        names = [s.name for s in db.select(case["param"]) if s.name not in ENDPOINT_LEVEL]
        names += sorted(ENDPOINT_LEVEL)          # 端点级 (cors/unauth/信息泄露)
        t0 = time.perf_counter()
        findings = run_detectors(ctx, names)
        elapsed = time.perf_counter() - t0
        types = [f.vuln_type for f in findings]
        expect = case["expect"]
        hit = any(e in t for t in types for e in expect)
        status = "HIT " if hit else ("MISS" if expect else "-   ")
        print(f"[{status}] {case['name']:34} param={case['param']:12} "
              f"发现={types or '无'}  期望={expect}  ({elapsed:.2f}s)")
        results.append({"name": case["name"], "endpoint": case["endpoint"],
                        "param": case["param"], "position": case.get("position", "query"),
                        "expect": expect, "found": types, "hit": hit,
                        "seconds": round(elapsed, 3),
                        "findings": [f.as_dict() for f in findings]})

    hit_n = sum(1 for r in results if r["hit"])
    exp_n = sum(1 for r in results if r["expect"])
    print(f"\n检出 {hit_n}/{exp_n}")
    if ns.out:
        Path(ns.out).write_text(json.dumps(
            {"label": spec.get("label"), "hit": hit_n, "expected": exp_n,
             "results": results}, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[+] JSON -> {ns.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
