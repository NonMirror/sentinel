"""Offline WAF semantics, scanner boundaries and reporting benchmarks.

No targets are contacted. WAF quality uses the existing project corpus;
--external adds the existing GoTestWAF fixture directory and fails if absent.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.corpus import build_corpus
from benchmarks.scripts.bench_waf import Attack, build_attacks, load_benign, run_engine
from sentinel.core.models import Finding, Severity
from sentinel.scanner.client import HttpResult
from sentinel.scanner.crawler import Target, TargetRecognizer
from sentinel.scanner.engines.base import ScannerEngine, dedupe
from sentinel.scanner.engines.manager import ScannerEngineManager
from sentinel.waf.naxsi.engine import NativeNaxsiEngine
from sentinel.waf.parser import iter_variable_values, parse_request
from sentinel.waf.secrule.syntax import Variable
from sentinel.waf.secrule.variables import Transaction


def request(target="/", body=b"", content_type="application/x-www-form-urlencoded"):
    head = (f"POST {target} HTTP/1.1\r\nHost: example.test\r\n"
            f"Content-Type: {content_type}\r\nContent-Length: {len(body)}\r\n\r\n")
    return parse_request(head.encode() + body)


class MemoryClient:
    def __init__(self, page):
        self.page = page
        self.requests = []

    def get(self, url):
        self.requests.append(url)
        body = self.page if url == "https://example.test/" else ""
        return HttpResult(url=url, method="GET", status=200, body=body.encode())


class PartialEngine(ScannerEngine):
    name = "partial"

    @classmethod
    def available(cls):
        return True

    def scan(self, targets, **kwargs):
        self.last_error = "fixture incomplete"
        return [Finding("fixture", "https://example.test/", Severity.INFO)]


def semantic_checks():
    checks = {}
    tx = Transaction(request("/?id=one&id=two&query=yes", b"id=three&post=yes"))

    def values(name, selector=None):
        return [m.value for m in tx.resolve(Variable(
            name=name, selectors=(selector,) if selector else ()))]

    checks["waf_duplicate_args"] = values("ARGS", "id") == ["one", "two", "three"]
    checks["waf_get_isolation"] = values("ARGS_GET", "id") == ["one", "two"]
    checks["waf_post_isolation"] = values("ARGS_POST", "id") == ["three"]
    checks["waf_missing_selector"] = values("ARGS", "absent") == []
    checks["waf_regex_selector"] = values("ARGS", "/^po/") == ["yes"]
    checks["waf_post_names"] = values("ARGS_POST_NAMES") == ["id", "post"]
    checks["waf_body_length"] = values("REQUEST_BODY_LENGTH") == ["17"]
    count = tx.resolve(Variable(name="ARGS", selectors=("id",), count=True))
    checks["waf_duplicate_count"] = count[0].value == "3"
    req = request("/?id=one&id=two", b"id=three")
    checks["python_duplicate_values"] = iter_variable_values(req, "ARGS:id") == ["one", "two", "three"]
    req = request("/files/a+b%2520.txt")
    checks["parser_path_plus"] = req.path == "/files/a+b%20.txt"
    checks["naxsi_decode_once"] = NativeNaxsiEngine._surfaces(req)["URL"] == ["/files/a+b%20.txt"]
    tx = Transaction(req)
    checks["secrule_decode_once"] = tx.resolve(Variable(name="REQUEST_FILENAME"))[0].value == "/files/a+b%20.txt"
    tx.set_tx("counter", "1")
    tx.resolve(Variable(name="TX", selectors=("counter",)))
    tx.set_tx("counter", "2")
    checks["tx_cache_invalidation"] = tx.resolve(Variable(name="TX", selectors=("counter",)))[0].value == "2"

    client = MemoryClient("".join(f'<a href="/page/{i}">p</a>' for i in range(500)))
    target = TargetRecognizer(client, max_urls=8).recognize("https://example.test/")
    checks["scanner_endpoint_budget"] = target.url_count <= 8
    client = MemoryClient("".join(f'<a href="/page?id={i}">p</a>' for i in range(500)))
    TargetRecognizer(client, max_urls=8).recognize("https://example.test/")
    checks["scanner_request_budget"] = len(client.requests) <= 10
    target = Target("https://example.test/", "example.test")
    for path in ("/logout.php", "/delete/1", "//outside.test/", '/api/"bad'):
        target.add(path)
    checks["scanner_unsafe_candidates"] = target.url_count == 0
    findings = [Finding("fixture", "https://example.test/item?q=1", Severity.INFO,
                        method=method, conn_id="fixture") for method in ("GET", "POST")]
    checks["report_method_identity"] = len(dedupe(findings)) == 2
    checks["report_provenance"] = findings[0].as_dict().get("conn_id") == "fixture"
    # Construct only the fake engine; no real scanner is instantiated or run.
    manager = ScannerEngineManager.__new__(ScannerEngineManager)
    from sentinel.core.events import EventBus
    from sentinel.core.metrics import Metrics
    manager.bus, manager.metrics = EventBus(), Metrics()
    manager.engines = {"partial": PartialEngine()}
    outcome = manager.scan(["https://example.test/"], engines=["partial"])
    checks["report_partial_error"] = not outcome.runs[0].ok and outcome.runs[0].error == "fixture incomplete"
    checks["report_partial_findings"] = len(outcome.findings) == 1
    empty = manager.scan(["https://example.test/"], engines=[])
    checks["explicit_empty_engine_selection"] = empty.runs == []
    unknown = manager.scan(["https://example.test/"], engines=["missing"])
    checks["report_unknown_engine"] = len(unknown.runs) == 1 and not unknown.runs[0].ok
    return {"passed": sum(checks.values()), "total": len(checks), "checks": checks}


def argument_scaling(repeats):
    result = []
    for count in (10, 100, 500):
        req = request("/?" + "&".join(f"p{i}=v{i}" for i in range(count)))
        durations = []
        for _ in range(repeats):
            start = time.perf_counter()
            tx = Transaction(req)
            for name in ("ARGS_GET", "ARGS_POST", "ARGS_GET_NAMES", "ARGS_POST_NAMES"):
                tx.resolve(Variable(name=name))
            durations.append((time.perf_counter() - start) * 1000)
        result.append({"parameters": count, "median_ms": statistics.median(durations)})
    return result


def run(repeats=3, external=False):
    corpus = build_corpus()
    attacks = [Attack(s.raw, s.category, "fixture", "project") for s in corpus if s.expect_block]
    benign = [s.raw for s in corpus if not s.expect_block]
    if external:
        attacks, _ = build_attacks(4096, "GoTestWAF")
        benign, text_count = load_benign()
        if not attacks or not text_count:
            raise ValueError("Requested GoTestWAF fixtures are missing")
    digest = hashlib.sha256()
    for label, raw in [(b"attack", a.raw) for a in attacks] + [(b"benign", b) for b in benign]:
        digest.update(label + len(raw).to_bytes(8, "big") + raw)
    results = []
    for name in ("python", "naxsi", "modsecurity"):
        for pl in ((1,) if name == "python" else (1, 2, 4)):
            runs = [run_engine(name, attacks, benign, pl, 5) for _ in range(repeats)]
            results.append({"engine": name, "paranoia_level": pl,
                            "runs": runs, "stable_counts": len({(r["blocked"], r["false_positives"]) for r in runs}) == 1})
    return {"python": platform.python_version(), "platform": platform.platform(),
            "scope": "offline only; scanner responses and engines are simulated",
            "repeats": repeats, "source": "GoTestWAF+project-benign" if external else "project",
            "corpus_sha256": digest.hexdigest(), "semantics": semantic_checks(),
            "argument_scaling": argument_scaling(max(5, repeats)), "quality": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--external", action="store_true")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    result = run(args.repeats, args.external)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.out), "semantics": result["semantics"]}))


if __name__ == "__main__":
    main()
