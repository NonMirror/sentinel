"""Replay public CRS/go-ftw request fixtures inside the WAF; never send HTTP.

Measures expected rule IDs, not global false-positive rate. A negative assertion
only means that particular rules should not match. Unsupported cases are listed.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlsplit

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sentinel.core.config import Config
from sentinel.core.models import HttpRequest
from sentinel.waf.engines.modsecurity import ModSecurityEngine
from sentinel.waf.secrule import SecRuleEngine


_REPEAT_TEMPLATE = re.compile(r'\{\{\s*"([^"\\\r\n]*)"\s*\|\s*repeat\s+([0-9]{1,7})\s*\}\}')
_TEMPLATE_MAX_BYTES = 1024 * 1024


def render_body(value: str) -> bytes:
    """Render the literal repeat subset used by this fixed CRS corpus.

    shortcut: no general Go template execution; report other expressions as
    unsupported until their semantics and resource bounds are implemented.
    """
    if "{{" not in value:
        return value.encode("utf-8")
    chunks, size, cursor = [], 0, 0
    while True:
        start = value.find("{{", cursor)
        literal = value[cursor:start if start >= 0 else len(value)].encode("utf-8")
        size += len(literal)
        if size > _TEMPLATE_MAX_BYTES:
            raise ValueError("template-size-limit")
        chunks.append(literal)
        if start < 0:
            return b"".join(chunks)
        match = _REPEAT_TEMPLATE.match(value, start)
        if match is None:
            raise ValueError("unsupported-body-template")
        token, count = match[1].encode("utf-8"), int(match[2])
        size += len(token) * count
        if size > _TEMPLATE_MAX_BYTES:
            raise ValueError("template-size-limit")
        chunks.append(token * count)
        cursor = match.end()


def load_cases(root):
    cases, skipped = [], []
    digest = hashlib.sha256()
    files = sorted((root / "tests/regression/tests").glob("REQUEST-*/*.yaml"))
    if not files:
        raise ValueError("No CRS request fixtures found")
    for path in files:
        relative = str(path.relative_to(root))
        blob = path.read_bytes()
        digest.update(relative.encode() + b"\0" + blob)
        doc = yaml.safe_load(blob) or {}
        for test in doc.get("tests", []):
            identifier = f"{relative}:{test.get('test_id')}"
            stages = test.get("stages", [])
            reason = ""
            if len(stages) != 1:
                reason = "multi-stage"
            else:
                stage = stages[0]
                data, output = stage.get("input") or {}, stage.get("output") or {}
                log = output.get("log") or {}
                if set(output) != {"log"} or not log or set(log) - {"expect_ids", "no_expect_ids"}:
                    reason = "unsupported-output"
                elif "encoded_request" in data or data.get("autocomplete_headers") is False:
                    reason = "raw-wire-semantics"
                elif not isinstance(data.get("data", ""), str):
                    reason = "non-text-body"
                elif not all(isinstance(v, list) and all(isinstance(n, int) for n in v) for v in log.values()):
                    reason = "non-numeric-rule-assertion"
            if reason:
                skipped.append({"id": identifier, "reason": reason})
                continue
            try:
                body = render_body(data.get("data", ""))
            except ValueError as exc:
                skipped.append({"id": identifier, "reason": str(exc)})
                continue
            # go-ftw writes YAML strings as UTF-8 bytes; HttpRequest keeps raw
            # request-line/header bytes in Latin-1, just like parse_request.
            headers = {str(k).encode("utf-8").decode("latin-1"):
                       str(v).encode("utf-8").decode("latin-1")
                       for k, v in data.get("headers", {}).items()}
            lower = {k.lower() for k in headers}
            if body and "content-type" not in lower:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            if body and "content-length" not in lower:
                headers["Content-Length"] = str(len(body))
            target = data.get("uri", "/").encode("utf-8").decode("latin-1")
            try:
                parts = urlsplit(target)
            except ValueError:
                skipped.append({"id": identifier, "reason": "invalid-uri"})
                continue
            req = HttpRequest(method=data.get("method", "GET"), target=target,
                              path=unquote(parts.path) or "/", query=parts.query,
                              version=data.get("version", "HTTP/1.1"),
                              headers=headers, body=body, remote_addr="127.0.0.1")
            cases.append((identifier, path.parent.name, req, log))
    return cases, skipped, digest.hexdigest()


def load_test_limits(root):
    """Read only the four size limits explicitly set by upstream test compose."""
    path = root / "tests/docker-compose.yml"
    blob = path.read_bytes()
    environment = yaml.safe_load(blob)["x-common-env"]
    limits = {}
    for name in ("ARG_LENGTH", "TOTAL_ARG_LENGTH", "MAX_FILE_SIZE", "COMBINED_FILE_SIZES"):
        value = str(environment[name])
        if not value.isascii() or not value.isdigit() or not 0 < int(value) <= 2**31 - 1:
            raise ValueError(f"Invalid upstream test limit: {name}")
        limits[name.lower()] = int(value)
    return limits, hashlib.sha256(blob).hexdigest()


def run(root, *, upstream_test_limits=False):
    cases, skipped, digest = load_cases(root)
    cfg = Config()
    cfg.waf.paranoia_level = 4
    cfg.waf.mode = "detect"  # Evaluate all phases; do not stop at an early block.
    driver = ModSecurityEngine(cfg)
    engine = driver.engine
    configuration = {"engine": "modsecurity", "paranoia_level": 4, "mode": "detect"}
    if upstream_test_limits:
        limits, config_digest = load_test_limits(root)
        configuration.update(test_limits=limits, test_config_sha256=config_digest,
                             limit_profile="upstream-test-compose")
        with tempfile.TemporaryDirectory(prefix="sentinel-crs-test-limits-") as directory:
            path = Path(directory) / "test-limits.conf"
            assignments = ",".join(f"setvar:tx.{key}={value}" for key, value in limits.items())
            path.write_text(f'SecAction "id:9990000,phase:1,pass,nolog,{assignments}"\n')
            engine = SecRuleEngine.from_paths([path, *driver.sources()], paranoia_level=4, mode="detect")
    by_category = {}
    failures = []
    timings = []
    for identifier, category, request, expected in cases:
        verdict = engine.inspect(request)
        timings.append((verdict.elapsed_ms, identifier))
        matched = set(verdict.matched_rules)
        positive = set(expected.get("expect_ids", []))
        negative = set(expected.get("no_expect_ids", []))
        positive_ok = positive <= matched
        negative_ok = not (negative & matched)
        counts = by_category.setdefault(category, Counter())
        counts["cases"] += 1
        counts["passed"] += int(positive_ok and negative_ok)
        for label, ids, ok in (("positive", positive, positive_ok), ("negative", negative, negative_ok)):
            if ids:
                counts[label + "_cases"] += 1
                counts[label + "_passed"] += int(ok)
        if not positive_ok or not negative_ok:
            failures.append({"id": identifier, "missing_ids": sorted(positive - matched),
                             "unexpected_ids": sorted(negative & matched)})
    commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    totals = Counter()
    for counts in by_category.values():
        totals.update(counts)
    return {"source": "https://github.com/coreruleset/coreruleset", "commit": commit,
            "fixture_sha256": digest, "scope": "in-process CRS/go-ftw fixture adapter, not official go-ftw execution",
            "configuration": configuration,
            "adapter": {"body_templates": "literal repeat only", "template_max_bytes": _TEMPLATE_MAX_BYTES,
                        "request_line_and_headers": "UTF-8 source bytes in Latin-1 strings"},
            "totals": dict(totals), "by_category": by_category,
            "skipped": skipped, "failures": failures, "engine_errors": engine.stats["errors"],
            "slowest_cases": [{"id": identifier, "elapsed_ms": round(ms, 3)}
                              for ms, identifier in sorted(timings, reverse=True)[:10]],
            "limitations": ["No backend, response rules, multi-stage or raw wire tests",
                            "No global benign/attack labels; rule-ID compatibility only",
                            "Only bounded, unescaped double-quoted literal repeat body templates; other templates skipped",
                            "No platform overrides; optional upstream size-limit profile is recorded separately",
                            "Upstream fixture revision may differ from vendored CRS rules"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crs-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--upstream-test-limits", action="store_true",
                        help="Use four size limits from upstream tests/docker-compose.yml; never change default config")
    args = parser.parse_args()
    result = run(args.crs_root, upstream_test_limits=args.upstream_test_limits)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"totals": result["totals"], "skipped": len(result["skipped"]),
                      "engine_errors": result["engine_errors"]}))


if __name__ == "__main__":
    main()
