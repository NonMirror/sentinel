"""Offline timing of ordinary byte-range inputs and unchanged framework decisions."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmarks.scripts.bench_frameworks import cases
from sentinel.core.config import Config
from sentinel.waf.engines.modsecurity import ModSecurityEngine
from sentinel.waf.parser import parse_request
from sentinel.waf.secrule.operators import evaluate
from sentinel.waf.secrule.syntax import Operator

RANGES = (("all-bytes", "0-255"), ("crs-pl4", "38,44-46,48-58,61,65-90,95,97-122"))


def timed(call, repeats, iterations):
    expected = call()
    samples = []
    for _ in range(repeats):
        start = time.perf_counter_ns()
        for _ in range(iterations):
            assert call() == expected
        samples.append((time.perf_counter_ns() - start) / iterations / 1_000_000)
    return expected, samples


def framework_request(case):
    body = bytes.fromhex(case["body_hex"])
    lines = [f"{case['expected']['method']} {case['target']} HTTP/1.1", "Host: fixture.local",
             "Accept: application/json", "User-Agent: Mozilla/5.0"]
    if case["content_type"]:
        lines.append("Content-Type: " + case["content_type"])
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return parse_request(("\r\n".join(lines) + "\r\n\r\n").encode() + body)


def run(repeats):
    if repeats < 3:
        raise ValueError("At least three repeats required")
    rows = []
    for label, spec in RANGES:
        op = Operator(name="validatebyterange", argument=spec)
        for size in (0, 32, 1024, 8192, 65536, 131072):
            inputs = {"letters": "a" * size}
            if size:
                inputs.update({"leading-space": " " + "a" * (size - 1),
                               "middle-space": "a" * (size // 2) + " " + "a" * (size - size // 2 - 1),
                               "trailing-space": "a" * (size - 1) + " "})
            for name, value in inputs.items():
                iterations = max(1, min(100, 65536 // max(1, size)))
                actual, samples = timed(lambda: evaluate(op, value), repeats, iterations)
                expected = label == "crs-pl4" and name != "letters"
                if actual != expected:
                    raise AssertionError(f"Unexpected byte-range decision: {label}/{size}/{name}")
                rows.append({"range": label, "spec": spec, "size": size, "case": name,
                             "input_sha256": hashlib.sha256(value.encode()).hexdigest(),
                             "matched": actual, "expected_match": expected, "iterations": iterations,
                             "samples_ms": samples, "median_ms": statistics.median(samples)})
    config = Config()
    config.waf.paranoia_level = 4
    driver = ModSecurityEngine(config)
    traces = []
    for case in cases(extended=True, referrer_boundaries=True):
        req = framework_request(case)
        verdict = driver.engine.inspect(req)
        traces.append({"case": case["name"], "blocked": verdict.blocked,
                       "hits": [{"rule_id": h.rule_id, "message": h.message, "targets": h.targets}
                                for h in verdict.hits]})
    engine_rows = []
    for size in (1024, 8192, 65536):
        body = b"note=" + b"a" * (size - 5)
        req = parse_request((f"POST /form HTTP/1.1\r\nHost: fixture.local\r\nAccept: application/json\r\n"
                             f"User-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                             f"Content-Length: {size}\r\n\r\n").encode() + body)
        def inspect():
            verdict = driver.engine.inspect(req)
            return verdict.blocked, tuple(h.rule_id for h in verdict.hits)
        decision, samples = timed(inspect, repeats, 1)
        engine_rows.append({"body_size": size, "input_sha256": hashlib.sha256(body).hexdigest(),
                            "blocked": decision[0], "rule_ids": decision[1],
                            "samples_ms": samples, "median_ms": statistics.median(samples)})
    return {"scope": "Self-authored benign in-process performance checks; not a new public benchmark source",
            "python": platform.python_version(), "platform": platform.platform(), "repeats": repeats,
            "operator_rows": rows, "engine_rows": engine_rows, "framework_pl4_traces": traces,
            "engine_errors": driver.engine.stats["errors"],
            "limitations": ["Warm caches, sequential runs, no CPU isolation or HTTP transport",
                            "Only letters and ordinary spaces; no attack generation or active scanning",
                            "Operator speed does not imply equivalent end-to-end proxy speed",
                            "PL4 framework traces reconstruct benchmark requests offline; live integration is separate"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.repeats)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"operator_cases": len(result["operator_rows"]), "engine_cases": len(result["engine_rows"]),
                      "engine_errors": result["engine_errors"]}))
