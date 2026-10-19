"""Self-authored, benign upload boundary checks on four loopback frameworks."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from bench_frameworks import backend, cases, send, snapshot
from sentinel.core.config import BackendConfig, Config
from sentinel.runtime import SentinelRuntime


def run(python, express_root, repeats):
    if repeats < 1:
        raise ValueError("repeats must be positive")
    limit = 1024
    corpus = []
    for size in (limit - 1, limit, limit + 1):
        body = b"note=" + b"a" * (size - 5)
        corpus.append({"name": f"body-{size}", "target": "/form", "body_hex": body.hex(),
                       "content_type": "application/x-www-form-urlencoded",
                       "expected": {"method": "POST", "path": "/form", "query": {}, "files": {},
                                    "json": None, "form": {"note": ["a" * (size - 5)]},
                                    "body_sha256": hashlib.sha256(body).hexdigest()}})
    rows, environments = [], []
    with tempfile.TemporaryDirectory(prefix="sentinel-body-limits-") as folder:
        for framework in ("django", "flask", "fastapi", "express"):
            with backend(python, framework, express_root) as info:
                environments.append({k: v for k, v in info.items() if k != "port"})
                for case in corpus:
                    direct = snapshot(send(info["port"], case))
                    if direct["status"] != 200 or direct["payload"] != case["expected"] or direct["error"]:
                        raise RuntimeError(f"Invalid direct oracle: {framework}/{case['name']}")
                for engine in ("python", "naxsi", "modsecurity"):
                    for mode in ("block", "detect", "off"):
                        config = Config()
                        config.listener.host, config.listener.port = "127.0.0.1", 0
                        config.backends = [BackendConfig(framework, "127.0.0.1", info["port"])]
                        config.audit_path = str(Path(folder) / f"{framework}-{engine}-{mode}.jsonl")
                        config.waf.max_body_bytes = limit
                        config.waf.backend_timeout_s = .5
                        config.waf.mode = mode
                        runtime = SentinelRuntime(config, start_lab=False, engine=engine)
                        try:
                            runtime.start()
                            if not runtime.front_port:
                                raise RuntimeError("Proxy failed to bind")
                            samples = []
                            for repeat in range(repeats):
                                for case in corpus:
                                    observed = snapshot(send(runtime.front_port, case))
                                    oversize = len(bytes.fromhex(case["body_hex"])) > limit
                                    expected_status = 413 if oversize else 200
                                    passed = (not observed["error"] and observed["status"] == expected_status
                                              and (oversize or observed["payload"] == case["expected"]))
                                    samples.append({"repeat": repeat, "case": case["name"], "passed": passed,
                                                    "status": observed["status"], "error": observed["error"]})
                                health = cases()[0]
                                observed = snapshot(send(runtime.front_port, health))
                                samples.append({"repeat": repeat, "case": "health-after-rejection",
                                                "passed": observed["status"] == 200 and not observed["error"]
                                                and observed["payload"] == health["expected"],
                                                "status": observed["status"], "error": observed["error"]})
                            rows.append({"framework": framework, "engine": engine, "mode": mode,
                                         "blocking_pl": 1, "samples": samples})
                        finally:
                            runtime.stop()
    samples = [s for row in rows for s in row["samples"]]
    return {"scope": "self-authored upload-limit extension to the existing four-framework integration suite",
            "limit_bytes": limit, "backend_timeout_s": .5, "repeats": repeats, "frameworks": environments,
            "cases": corpus, "corpus_sha256": hashlib.sha256(json.dumps(corpus, sort_keys=True).encode()).hexdigest(),
            "rows": rows, "summary": {"passed": sum(s["passed"] for s in samples), "total": len(samples)},
            "limitations": ["Ordinary Content-Length form uploads only; no chunked uploads or Expect handshake",
                            "No vulnerability scanning, attack recall or throughput measurement",
                            "Setup and direct oracle requests excluded; this is not a new public benchmark source",
                            "Post-rejection health checks use a new connection"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework-python", type=Path, required=True)
    parser.add_argument("--express-root", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.framework_python.absolute(), args.express_root.absolute(), args.repeats)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result["summary"]))
