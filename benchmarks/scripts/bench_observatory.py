"""Replay selected MDN Observatory header fixtures without network requests."""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.scripts.bench_passive_public import CapturedClient
from sentinel.scanner.crawler import Endpoint, Target
from sentinel.scanner.detectors import DETECTORS, DetectorContext
from sentinel.scanner.vulndb import default_db


HEADERS = ("x-content-type-options", "cross-origin-resource-policy", "referrer-policy",
           "cross-origin-opener-policy", "cross-origin-embedder-policy")
JS_STRING = r'''"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*' '''.strip()


def isolation_cases(text, relative, header):
    """Read the two table-driven loops and two literal tests; never execute JS."""
    rows = []
    for table, assertion in (("invalidHeaders", "False"), ("validHeaders", "True")):
        match = re.search(rf"const {table} = [{{\[](.*?)\n  [}}\]];", text, re.S)
        loop = re.search(rf"for \([^\n]+\b{table}\b[^\n]*\) \{{(.*?)\n  \}}", text, re.S)
        if not match or not loop or f"assert.is{assertion}(result.pass)" not in loop[1]:
            raise ValueError(f"Unadapted table assertions: {relative}:{table}")
        pattern = (rf"(?:{JS_STRING})\s*:\s*({JS_STRING})" if table == "invalidHeaders"
                   else rf"\[\s*({JS_STRING})\s*,\s*Expectation\.\w+\s*,?\s*\]")
        values = [ast.literal_eval(m[1]) for m in re.finditer(pattern, match[1])]
        if not values:
            raise ValueError(f"No literals: {relative}:{table}")
        for index, value in enumerate(values):
            rows.append({"id": f"{relative}:{table}:{index}", "header": header,
                         "value": value, "expected_alert": assertion == "False"})
    for title in ("checks for missing", "checks for multiple headers"):
        block = re.search(rf'it\("{title}", function \(\) \{{(.*?)\n  \}}\);', text, re.S)
        if not block or not (assertion := re.search(r"assert\.is(True|False)\(result.pass\)", block[1])):
            raise ValueError(f"Missing assertion: {relative}:{title}")
        value = None
        if "multiple" in title:
            array = re.search(r'headers\["[^\"]+"\] = \[(.*?)\];', block[1], re.S)
            if not array:
                raise ValueError(f"Missing header array: {relative}")
            value = ", ".join(ast.literal_eval(m[0]) for m in re.finditer(JS_STRING, array[1]))
        rows.append({"id": f"{relative}:{title}", "header": header,
                     "value": value, "expected_alert": assertion[1] == "False"})
    if len(re.findall(r"\bit\(", text)) != 4:
        raise ValueError(f"Unadapted test blocks: {relative}")
    return rows


def load_cases(root, *, headers=HEADERS):
    """Read literals and pass assertions; report the two meta cases separately."""
    cases, skipped, digest = [], [], hashlib.sha256()
    for header in headers:
        relative = f"test/{header}.test.js"
        blob = (root / relative).read_bytes()
        digest.update(relative.encode() + b"\0" + blob)
        text = blob.decode()
        if header in {"cross-origin-opener-policy", "cross-origin-embedder-policy"}:
            cases.extend(isolation_cases(text, relative, header))
            continue
        if header == "referrer-policy":
            for marker, name in (("// Test with a meta/http-equiv header", "meta-only"),
                                 ("// The meta/http-equiv header has precendence", "meta-and-http")):
                if marker in text:
                    skipped.append({"id": f"{relative}:meta:{name}",
                                    "reason": "HTML meta precedence outside header-only scope"})
        blocks = re.split(r'\bit\("', text)[1:]
        if not blocks:
            raise ValueError(f"No test blocks in {relative}")
        for block in blocks:
            title = block.split('"', 1)[0]
            # Header-only part of the first referrer test precedes its meta subcases.
            http_block = block.split('// Test with a meta/http-equiv header')[0]
            passed = re.search(r'assert\.is(True|False)\(result\.pass\)', http_block)
            if not passed:
                raise ValueError(f"Missing pass assertion: {relative}:{title}")
            expected_alert = passed[1] == "False"
            array = re.search(r'const \w+ = \[(.*?)\];', http_block, re.S)
            assignment = re.search(r'reqs\.responses\.auto\.headers\["[^"]+"\] = (\[.*?\]|"(?:[^"\\]|\\.)*");', http_block, re.S)
            if array:
                values = [json.loads(m[0]) for m in re.finditer(r'"(?:[^"\\]|\\.)*"', array[1])]
            elif assignment:
                value = json.loads(assignment[1].replace(',\n    ]', '\n    ]'))
                values = [", ".join(value) if isinstance(value, list) else value]
            elif "missing" in title:
                values = [None]
            else:
                raise ValueError(f"Unadapted case: {relative}:{title}")
            for index, value in enumerate(values):
                cases.append({"id": f"{relative}:{title}:{index}", "header": header,
                              "value": value, "expected_alert": expected_alert})
    return cases, skipped, digest.hexdigest()


def run(root):
    cases, skipped, digest = load_cases(root)
    detector = DETECTORS.get("security_headers")
    db, rows, counts = default_db(), [], {}
    for case in cases:
        headers = {"Content-Type": "text/html", "X-Content-Type-Options": "nosniff"}
        headers = {k: v for k, v in headers.items() if k.lower() != case["header"]}
        if case["value"] is not None:
            headers[case["header"]] = case["value"]
        url = "https://fixture.invalid/"
        client = CapturedClient(url, {"status": 200, "headers": headers, "body": ""})
        ctx = DetectorContext(client=client, db=db, target=Target(url, "fixture.invalid"), endpoint=Endpoint(url))
        findings = detector(ctx) if detector else []
        relevant = [f for f in findings if f.param.lower() == case["header"]]
        passed = bool(relevant) == case["expected_alert"]
        count = counts.setdefault(case["header"], Counter())
        count.update(total=1, passed=int(passed), expected_alerts=int(case["expected_alert"]),
                     false_positives=int(bool(relevant) and not case["expected_alert"]),
                     missed=int(not relevant and case["expected_alert"]))
        rows.append({**case, "actual_alert": bool(relevant), "passed": passed,
                     "requests": len(client.requests), "severities": [f.severity.value for f in relevant]})
    totals = Counter()
    for count in counts.values():
        totals.update(count)
    return {"source": "https://github.com/mdn/mdn-http-observatory",
            "commit": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
            "fixture_sha256": digest, "detector_available": detector is not None,
            "totals": totals, "by_header": counts, "cases": rows, "skipped": skipped,
            "limitations": ["Selected header-only assertions from five upstream test files",
                            "No official runner, site grade, CSP, TLS, cookies, meta or browser evaluation",
                            "No HTTP requests or active vulnerability probes"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observatory-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.observatory_root)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"totals": result["totals"], "skipped": len(result["skipped"])}))


if __name__ == "__main__":
    main()
