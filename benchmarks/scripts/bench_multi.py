"""Sentinel 多引擎扫描能力 bench.

把靶场**已知漏洞端点**作为目标列表喂给 nuclei / w13scan / builtin 三个引擎,
统计各自与融合后的发现, 便于和靶场已知漏洞清单对照.

    python bench_multi.py --targets /tmp/opencode/results/targets-dvwa.json \
        --label dvwa-low --cookie '...' --out /tmp/opencode/results/dvwa-multi.json
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

from sentinel.core.config import ScannerConfig  # noqa: E402
from sentinel.scanner.engines import (  # noqa: E402
    BuiltinEngine, NucleiEngine, W13ScanEngine, dedupe,
)
from sentinel.scanner.scanner import Scanner  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", required=True, help="JSON: {label, urls:[...]}")
    ap.add_argument("--label", default="target")
    ap.add_argument("--cookie", default="")
    ap.add_argument("--engines", default="nuclei,w13scan,builtin")
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--max-urls", type=int, default=200)
    ap.add_argument("--out", default="")
    ns = ap.parse_args()

    spec = json.loads(Path(ns.targets).read_text(encoding="utf-8"))
    urls: list[str] = spec["urls"]
    cfg = ScannerConfig(max_urls=ns.max_urls, max_depth=2, concurrency=12,
                        timeout_s=6.0)
    cfg.cookie = ns.cookie

    engines = {}
    for name in [e.strip() for e in ns.engines.split(",") if e.strip()]:
        if name == "nuclei":
            engines[name] = NucleiEngine(workers=8)
        elif name == "w13scan":
            engines[name] = W13ScanEngine(config=cfg)
        elif name == "builtin":
            engines[name] = BuiltinEngine(Scanner(cfg))

    print(f"[*] 目标 {spec.get('label', ns.label)} · {len(urls)} 个端点")
    print(f"[*] 引擎 {list(engines)} · deep={ns.deep} · cookie={'有' if ns.cookie else '无'}")

    runs = []
    merged = []
    for name, engine in engines.items():
        print(f"[*] {name} 扫描中 ...", flush=True)
        t0 = time.perf_counter()
        try:
            findings = engine.scan(urls, deep=ns.deep, timeout_s=ns.timeout)
            error = "" if findings else getattr(engine, "last_error", "")
            ok = True
        except Exception as exc:                    # noqa: BLE001
            findings, error, ok = [], str(exc), False
        seconds = time.perf_counter() - t0
        for f in findings:
            if not f.conn_id:
                f.conn_id = name
        merged.extend(findings)
        runs.append({"engine": name, "ok": ok, "findings": len(findings),
                     "seconds": round(seconds, 3), "error": error})
        print(f"    发现 {len(findings)} · {seconds:.1f}s"
              + (f" · {error[:80]}" if error else ""), flush=True)

    fused = dedupe(merged)
    sev = Counter(f.severity.value for f in fused)
    typ = Counter(f.vuln_type for f in fused)
    print(f"\n===== 融合去重后 {len(fused)} 个发现 =====")
    for f in sorted(fused, key=lambda x: (-x.severity.weight, x.vuln_type)):
        print(f"[{f.severity.value:8}] {f.vuln_type:28} {f.url[:74]} "
              f"param={f.param!r} via={f.conn_id}")

    if ns.out:
        Path(ns.out).write_text(json.dumps({
            "label": spec.get("label", ns.label), "deep": ns.deep,
            "targets": urls, "runs": runs, "fused_count": len(fused),
            "by_severity": dict(sev), "by_type": dict(typ),
            "findings": [f.as_dict() for f in fused],
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[+] JSON -> {ns.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
