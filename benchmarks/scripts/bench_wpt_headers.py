"""Offline WPT nosniff parsing and CORP syntax observations, not a browser run."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sentinel.scanner.client import HttpResult
from sentinel.scanner.headers import has_nosniff, inspect_security_headers


NOSNIFF = "fetch/nosniff/resources/x-content-type-options.json"
CORP = "fetch/cross-origin-resource-policy/syntax.any.js"
SUPPORT = ("fetch/nosniff/parsing-nosniff.window.js", "fetch/nosniff/resources/nosniff.py")


def load_cases(root):
    cases = []
    for index, case in enumerate(json.loads((root / NOSNIFF).read_text())):
        if set(case) != {"input", "nosniff"} or not isinstance(case["input"], str) or type(case["nosniff"]) is not bool:
            raise ValueError("Unadapted WPT nosniff assertion")
        items = []
        for line in case["input"].split("\r\n"):
            name, colon, value = line.partition(":")
            if not colon or not name or any(c in name + value for c in "\r\n"):
                raise ValueError("Unsupported WPT raw header framing")
            # HTTP whitespace only: preserve vertical tab and form feed fixtures.
            items.append((name, value.strip(" \t")))
        cases.append({"id": f"{NOSNIFF}:{index}", "category": "nosniff",
                      "header_items": items, "expected": case["nosniff"]})
    text = (root / CORP).read_text()
    table = re.search(r'\[\s*(.*?)\s*\]\.forEach\(incorrectHeaderValue =>', text, re.S)
    if not table or 'return fetch(crossOriginURL + encodeURIComponent(incorrectHeaderValue), { mode: "no-cors" });' not in text:
        raise ValueError("Unadapted WPT CORP assertion")
    # This file's single table contains only JSON strings and line comments.
    literals = []
    for line in table[1].splitlines():
        match = re.fullmatch(r'\s*("(?:[^"\\]|\\.)*")\s*,?\s*(?://.*)?', line)
        if not match:
            if line.strip():
                raise ValueError("Unadapted WPT CORP table entry")
            continue
        literals.append(json.loads(match[1]))
    if not literals or text.count("promise_test(") != 1:
        raise ValueError("Unadapted WPT CORP test coverage")
    for index, value in enumerate(literals):
        cases.append({"id": f"{CORP}:{index}", "category": "corp-invalid",
                      "header_items": [("Cross-Origin-Resource-Policy", value)], "expected": True})
    files = [root / p for p in (NOSNIFF, CORP, *SUPPORT)]
    if not cases or not all(p.is_file() for p in files):
        raise ValueError("Missing WPT fixtures or supporting source files")
    return cases, files


def run(root):
    cases, files = load_cases(root)
    rows, by_category = [], {}
    for case in cases:
        response = HttpResult(url="https://fixture.invalid/", method="GET", status=220,
                              headers={}, header_items=case["header_items"])
        findings = inspect_security_headers(response)
        header = "X-Content-Type-Options" if case["category"] == "nosniff" else "Cross-Origin-Resource-Policy"
        relevant = [f for f in findings if f.param == header]
        value = ", ".join(v for k, v in case["header_items"] if k.lower() == header.lower())
        actual = has_nosniff(value) if case["category"] == "nosniff" else bool(relevant)
        passed = actual == case["expected"]
        count = by_category.setdefault(case["category"], Counter())
        count.update(total=1, passed=int(passed))
        rows.append({**case, "actual": actual, "passed": passed,
                     "configuration_alert": bool(relevant), "proof": [f.proof for f in relevant],
                     "severities": [f.severity.value for f in relevant]})
    totals = Counter()
    for count in by_category.values():
        totals.update(count)
    return {"source": "https://github.com/web-platform-tests/wpt",
            "commit": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
            "scope": "Offline adaptation: nosniff effective-value parsing and CORP invalid-value observations",
            "source_files": [{"path": str(p.relative_to(root)), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in files],
            "totals": totals, "by_category": by_category, "cases": rows,
            "limitations": ["Two selected WPT files, not the complete WPT suite or a browser run",
                            "nosniff activation and canonical configuration syntax are distinct; both are recorded",
                            "CORP assertions adapt only the upstream invalid-value table, not cross-origin enforcement",
                            "No network requests, script execution, active scans, MIME-type or destination checks"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wpt-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.wpt_root)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result["totals"]))


if __name__ == "__main__":
    main()
