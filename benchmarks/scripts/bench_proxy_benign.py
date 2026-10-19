"""Loopback-only benign forwarding/latency benchmark; no exploit traffic."""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sentinel.core.config import BackendConfig, Config
from sentinel.runtime import SentinelRuntime

CASES = [
    ("GET", "/health", b"", ""),
    ("GET", "/search?name=Alice&tag=one&tag=two", b"", ""),
    ("GET", "/items?page=2&limit=20", b"", ""),
    ("POST", "/form", b"name=Alice&note=ordinary+text&tag=one&tag=two", "application/x-www-form-urlencoded"),
    ("POST", "/json", '{"name":"张三","tags":["one","two"]}'.encode(), "application/json"),
    ("POST", "/xml", b'<note language="en">ordinary text</note>', "application/xml"),
]


def expected(method, path, body):
    return {"method": method, "target": path, "body_sha256": hashlib.sha256(body).hexdigest()}


class EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        payload = json.dumps(expected(self.command, self.path, body)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    do_POST = do_GET

    def log_message(self, *args):
        pass


class EchoServer(ThreadingHTTPServer):
    request_queue_size = 64
    daemon_threads = True


def send(port, case):
    method, target, body, content_type = case
    headers = {"Host": "fixture.local", "User-Agent": "Mozilla/5.0", "Accept": "application/json",
               "Connection": "close"}
    if content_type:
        headers["Content-Type"] = content_type
    connection = HTTPConnection("127.0.0.1", port, timeout=10)
    start = time.perf_counter()
    status, correct, error = 0, False, ""
    try:
        connection.request(method, target, body=body if body else None, headers=headers)
        response = connection.getresponse()
        status = response.status
        raw = response.read()
        correct = status == 200 and json.loads(raw) == expected(method, target, body)
    except Exception as exc:
        error = type(exc).__name__
    finally:
        connection.close()
    return {"status": status, "correct": correct, "error": error,
            "ms": (time.perf_counter() - start) * 1000}


def measure(port, count, concurrency):
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(lambda i: send(port, CASES[i % len(CASES)]), range(count)))
    elapsed = time.perf_counter() - start
    times = sorted(r["ms"] for r in results)
    return {"requests": count, "concurrency": concurrency,
            "forwarded_exactly": sum(r["correct"] for r in results),
            "statuses": dict(Counter(str(r["status"]) for r in results)),
            "errors": dict(Counter(r["error"] for r in results if r["error"])),
            "seconds": round(elapsed, 4), "completed_rps": round(count / elapsed, 2),
            "latency_ms": {"p50": round(statistics.median(times), 3),
                           "p95": round(times[min(len(times) - 1, int(len(times) * .95))], 3)},
            "failures": [{"case": i % len(CASES), **r} for i, r in enumerate(results) if not r["correct"]]}


def run(count, repeats, *, split_crs=False):
    if count < len(CASES) or repeats < 1:
        raise ValueError("At least six requests and one repeat are required")
    server = EchoServer(("127.0.0.1", 0), EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    rows = []
    try:
        with tempfile.TemporaryDirectory(prefix="sentinel-benign-proxy-") as folder:
            configurations = [("direct", 0, None), ("python", 1, None), ("naxsi", 1, None),
                              ("modsecurity", 1, None), ("modsecurity", 4, None)]
            if split_crs:
                configurations.append(("modsecurity", 1, 4))
            for engine, pl, detection_pl in configurations:
                runtime = None
                port = server.server_port
                try:
                    if engine != "direct":
                        config = Config()
                        config.listener.host, config.listener.port = "127.0.0.1", 0
                        config.backends = [BackendConfig("echo", "127.0.0.1", server.server_port)]
                        config.audit_path = str(Path(folder) / f"{engine}-{pl}-{detection_pl}.jsonl")
                        config.waf.paranoia_level = pl
                        config.waf.detection_paranoia_level = detection_pl
                        config.waf.mode = "block"
                        runtime = SentinelRuntime(config, start_lab=False, engine=engine)
                        runtime.start()
                        port = runtime.front_port
                        if not port:
                            raise RuntimeError("Proxy failed to bind")
                    warmup = [send(port, c) for c in CASES]
                    rows.append({"engine": engine, "paranoia_level": pl,
                                 "detection_paranoia_level": detection_pl or pl,
                                 "warmup_exact": sum(r["correct"] for r in warmup),
                                 "runs": [measure(port, count, concurrency)
                                          for concurrency in (1, 8) for _ in range(repeats)]})
                finally:
                    if runtime:
                        runtime.stop()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return {"scope": "loopback benign forwarding with fresh TCP connections, not attack quality",
            "python": platform.python_version(), "platform": platform.platform(),
            "corpus_sha256": hashlib.sha256(repr(CASES).encode()).hexdigest(),
            "case_count": len(CASES), "requests_per_run": count, "repeats": repeats,
            "audit_enabled": True, "rows": rows,
            "limitations": ["Synthetic benign corpus, no production traffic distribution",
                            "No TLS, keep-alive, attack traffic, CPU pinning or saturation search",
                            "Rates include client threads and echo backend; direct baseline reported separately"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=120)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--split-crs", action="store_true", help="Also test detection PL4 with blocking PL1")
    args = parser.parse_args()
    result = run(args.requests, args.repeats, split_crs=args.split_crs)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"runs": sum(len(r["runs"]) for r in result["rows"]),
                      "exact": sum(s["forwarded_exactly"] for r in result["rows"] for s in r["runs"]),
                      "requests": sum(s["requests"] for r in result["rows"] for s in r["runs"])}))


if __name__ == "__main__":
    main()
