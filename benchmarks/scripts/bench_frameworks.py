"""Real-framework benign forwarding and passive headers; loopback only."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import platform
import select
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel.core.config import BackendConfig, Config
from sentinel.runtime import SentinelRuntime
from sentinel.scanner.client import HttpClient
from sentinel.scanner.headers import inspect_security_headers

POLICY_NAMES = {"X-Content-Type-Options", "Referrer-Policy", "Cross-Origin-Resource-Policy",
                "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy"}
CONFIGURATIONS = [("direct", 0, 0), ("python", 1, 1), ("naxsi", 1, 1),
                  ("modsecurity", 1, 1), ("modsecurity", 4, 4), ("modsecurity", 1, 4)]


def cases(extended=False, referrer_boundaries=False, json_scalars=False):
    def case(name, target, body=b"", content_type="", **parsed):
        expected = {"method": "POST" if body else "GET", "path": target.split("?", 1)[0],
                    "body_sha256": hashlib.sha256(body).hexdigest(), "query": {}, "form": {},
                    "files": {}, "json": None}
        expected.update(parsed)
        return {"name": name, "target": target, "body_hex": body.hex(),
                "content_type": content_type, "expected": expected}

    body = b'{"name":"Alice","tags":["one","two"],"details":{"count":2}}'
    multipart = (b'--sentinelBoundary\r\nContent-Disposition: form-data; name="tag"\r\n\r\none\r\n'
                 b'--sentinelBoundary\r\nContent-Disposition: form-data; name="tag"\r\n\r\ntwo\r\n'
                 b'--sentinelBoundary\r\nContent-Disposition: form-data; name="note"; filename="note.txt"\r\n'
                 b'Content-Type: text/plain\r\n\r\nordinary text\n\r\n--sentinelBoundary--\r\n')
    return [
        case("empty", "/"),
        case("query", "/search?tag=one&tag=two&name=%E5%BC%A0%E4%B8%89&empty=",
             query={"tag": ["one", "two"], "name": ["张三"], "empty": [""]}),
        case("form", "/form", b"name=Alice&note=ordinary+text&tag=one&tag=two",
             "application/x-www-form-urlencoded", form={"name": ["Alice"], "note": ["ordinary text"],
                                                         "tag": ["one", "two"]}),
        case("json", "/json", body, "application/json", json=json.loads(body)),
        case("vendor-json", "/json", body, "application/vnd.example+json", json=json.loads(body)),
        case("multipart", "/upload", multipart, "multipart/form-data; boundary=sentinelBoundary",
             form={"tag": ["one", "two"]}, files={"note": [{"filename": "note.txt", "size": 14,
                           "sha256": hashlib.sha256(b"ordinary text\n").hexdigest()}]}),
        case("unicode-path", "/items/%E4%B9%A6", path="/items/书"),
        *[case(f"policy-{p}", f"/policy/{p}") for p in ("default", "valid", "invalid")],
        *([case("policy-repeated", "/policy/repeated"), case("cookies", "/cookies")] if extended else []),
        *([case("policy-referrer-invalid", "/policy/referrer-invalid"),
           case("policy-referrer-unknown", "/policy/referrer-unknown")] if referrer_boundaries else []),
        *([case("json-scalars", "/json",
                b'{"active":true,"archived":false,"numbers":[-0,1.2300,1e2,1e-2],"empty":null}',
                "application/json", json={"active": True, "archived": False,
                                          "numbers": [0, 1.23, 100, .01], "empty": None})] if json_scalars else []),
    ]


def send(port, case):
    headers = {"Host": "fixture.local", "Accept": "application/json"}
    if case["content_type"]:
        headers["Content-Type"] = case["content_type"]
    body = bytes.fromhex(case["body_hex"]) or None
    return HttpClient(timeout=5, user_agent="Mozilla/5.0").request(
        case["expected"]["method"], f"http://127.0.0.1:{port}{case['target']}", body, headers)


def snapshot(response):
    try:
        payload = json.loads(response.body)
    except (ValueError, UnicodeDecodeError):
        payload = None
    return {"status": response.status, "payload": payload, "error": response.error,
            "policy_headers": sorted(((k.lower(), v) for k, v in response.header_items
                                      if k.lower() in {n.lower() for n in POLICY_NAMES}), key=lambda p: p[0]),
            "cookies": [v for k, v in response.header_items if k.lower() == "set-cookie"]}


@contextmanager
def backend(python, framework, express_root=None):
    with tempfile.TemporaryFile(mode="w+") as errors:
        command = (["node", str(Path(__file__).with_name("framework_express.cjs")), str(express_root)]
                   if framework == "express" else
                   [str(python), str(Path(__file__).with_name("framework_apps.py")), framework])
        process = subprocess.Popen(command,
                                   stdout=subprocess.PIPE, stderr=errors, text=True)
        try:
            if not select.select([process.stdout], [], [], 30)[0]:
                raise RuntimeError(f"{framework}: startup handshake timed out")
            line = process.stdout.readline()
            if not line:
                errors.seek(0)
                raise RuntimeError(f"{framework}: failed to start: {errors.read()[-4000:]}")
            info = json.loads(line)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"{framework}: server exited before readiness")
                response = send(info["port"], cases()[0])
                if response.status == 200 and not response.error:
                    break
                time.sleep(.05)
            else:
                raise RuntimeError(f"{framework}: readiness timed out")
            yield info
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()


def evaluate(response, case, baseline, framework):
    observed = snapshot(response)
    exact = observed == baseline and observed["payload"] == case["expected"]
    result = {"case": case["name"], "status": response.status, "exact": exact,
              "error": response.error}
    if not exact:
        result["observed"] = observed
    if case["name"].startswith("policy-"):
        expected = POLICY_NAMES if case["name"] == "policy-invalid" else set()
        if case["name"] == "policy-default" and framework != "django":
            expected = {"X-Content-Type-Options"}
        if case["name"] == "policy-repeated":
            expected = {"Cross-Origin-Opener-Policy", "Referrer-Policy"}
        if case["name"] == "policy-referrer-invalid":
            expected = {"Referrer-Policy"}
        # A blocked/missing backend response cannot count as a passive check pass.
        findings = inspect_security_headers(response) if exact else []
        actual = {f.param for f in findings}
        result["passive"] = {"expected": sorted(expected), "actual": sorted(actual),
                             "passed": exact and actual == expected,
                             "false_positives": len(actual - expected) if exact else None,
                             "misses": len(expected - actual) if exact else None,
                             "all_info": all(f.severity.value == "info" for f in findings) if exact else None,
                             "backend_response_available": exact}
    return result


def run(python, repeats, *, express_root=None, extended=False, referrer_boundaries=False, json_scalars=False,
        crs_profile="standard"):
    if repeats < 1:
        raise ValueError("repeats must be positive")
    corpus = cases(extended, referrer_boundaries, json_scalars)
    rows, environments, baselines = [], [], {}
    with tempfile.TemporaryDirectory(prefix="sentinel-framework-proxy-") as folder:
        for framework in ("django", "flask", "fastapi") + (("express",) if express_root else ()):
            with backend(python, framework, express_root) as info:
                environments.append({k: v for k, v in info.items() if k != "port"})
                baseline = [snapshot(send(info["port"], c)) for c in corpus]
                for case, sample in zip(corpus, baseline):
                    if sample["status"] != 200 or sample["error"] or sample["payload"] != case["expected"]:
                        raise RuntimeError(f"Invalid direct oracle: {framework}/{case['name']}: {sample}")
                    if case["name"] == "cookies" and len(sample["cookies"]) != 2:
                        raise RuntimeError(f"Missing fixture cookies: {framework}")
                    if case["name"] == "policy-repeated":
                        for name in ("cross-origin-opener-policy", "referrer-policy"):
                            if sum(k == name for k, _ in sample["policy_headers"]) != 2:
                                raise RuntimeError(f"Missing repeated fixture policy: {framework}/{name}")
                baselines[framework] = baseline
                for engine, blocking, detection in CONFIGURATIONS:
                    runtime = None
                    port = info["port"]
                    try:
                        if engine != "direct":
                            config = Config()
                            config.listener.host, config.listener.port = "127.0.0.1", 0
                            config.backends = [BackendConfig(framework, "127.0.0.1", port)]
                            config.audit_path = str(Path(folder) / f"{framework}-{engine}-{blocking}-{detection}.jsonl")
                            config.waf.mode = "block"
                            config.waf.crs_profile = crs_profile
                            config.waf.paranoia_level = blocking
                            config.waf.detection_paranoia_level = detection
                            runtime = SentinelRuntime(config, start_lab=False, engine=engine)
                            runtime.start()
                            port = runtime.front_port
                            if not port:
                                raise RuntimeError("Proxy failed to bind")
                        runs = [[evaluate(send(port, case), case, sample, framework)
                                 for case, sample in zip(corpus, baseline)] for _ in range(repeats)]
                        rows.append({"framework": framework, "engine": engine, "blocking_pl": blocking,
                                     "crs_profile": crs_profile if engine == "modsecurity" else None,
                                     "detection_pl": detection, "runs": runs})
                    finally:
                        if runtime:
                            runtime.stop()
    return {"scope": "self-authored benign integrations on public web frameworks; not vulnerability coverage",
            "python": platform.python_version(), "platform": platform.platform(), "frameworks": environments,
            "cases": corpus, "corpus_sha256": hashlib.sha256(json.dumps(corpus, sort_keys=True).encode()).hexdigest(),
            "repeats": repeats, "baselines": baselines, "rows": rows,
            "limitations": ["No attack traffic, authentication, database, TLS or browser execution",
                            "One minimal application per framework, not its upstream benchmark suite",
                            "Python apps use uvicorn; Django uses SecurityMiddleware; Flask uses WsgiToAsgi",
                            "Repeated policies appended by fixture ASGI middleware or Express response API",
                            "Sequential correctness checks; no throughput claims",
                            "Readiness and direct-oracle setup requests excluded from measured counts"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework-python", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--extended", action="store_true", help="Include repeated policy fields and two cookies")
    parser.add_argument("--referrer-boundaries", action="store_true", help="Include invalid syntax and unknown referrer policies")
    parser.add_argument("--json-scalars", action="store_true", help="Include ordinary boolean, decimal and exponent JSON values")
    parser.add_argument("--crs-profile", choices=["standard", "balanced"], default="standard")
    parser.add_argument("--express-root", type=Path, help="Isolated npm installation containing express and multer")
    args = parser.parse_args()
    result = run(args.framework_python.absolute(), args.repeats, extended=args.extended,
                 express_root=args.express_root.absolute() if args.express_root else None,
                 referrer_boundaries=args.referrer_boundaries, json_scalars=args.json_scalars,
                 crs_profile=args.crs_profile)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    samples = [s for row in result["rows"] for run in row["runs"] for s in run]
    print(json.dumps({"requests": len(samples), "exact": sum(s["exact"] for s in samples),
                      "passive_passed": sum(s.get("passive", {}).get("passed", False) for s in samples)}))


if __name__ == "__main__":
    main()
