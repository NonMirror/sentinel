"""Public passive-scanner fixture comparison and captured-page crawl checks.

Reads ZAP unit-test strings and saved local application pages. No HTTP requests,
injection, active scanner engine, or JavaScript execution are used.
"""
from __future__ import annotations

import argparse
import hashlib
from html import unescape
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sentinel.scanner.client import HttpResult
from sentinel.scanner.crawler import Endpoint, Target, TargetRecognizer
from sentinel.scanner.detectors import DetectorContext, detect_information_disclosure
from sentinel.scanner.vulndb import default_db

JAVA_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')


def zap_cases(root):
    folder = root / "addOns/pscanrules/src/test/java/org/zaproxy/zap/extension/pscanrules"
    source = folder / "InformationDisclosureDebugErrorsScanRuleUnitTest.java"
    text = source.read_text()
    default = json.loads(re.search(r'DEFAULT_ERROR_MESSAGE = ("[^"\n]+");', text)[1])
    values = re.search(r"DEBUG_ERRORS\s*=\s*List.of\((.*?)\);", text, re.S)[1]
    positives = [default] + [json.loads(m.group()) for m in JAVA_STRING.finditer(values)]
    negatives = re.search(r"@ValueSource\(\s*strings = \{(.*?)\}\)", text, re.S)[1]
    negatives = [json.loads(m.group()) for m in JAVA_STRING.finditer(negatives)]
    cases = [(f"debug-positive-{i}", f"<html>{value}</html>", True)
             for i, value in enumerate(positives)]
    cases += [("debug-lower", f"<html>{default.lower()}</html>", True),
              ("debug-upper", f"<html>{default.upper()}</html>", True)]
    cases += [(f"debug-negative-{i}", f"<html>{value}</html>", False)
              for i, value in enumerate(negatives)]
    cases.append(("debug-empty", "", False))
    bundled = folder / "ApplicationErrorScanRuleBundledStringsUnitTest.java"
    expr = re.search(r"msg.setResponseBody\((.*?)\);", bundled.read_text(), re.S)[1]
    body = "".join(json.loads(m.group()) for m in JAVA_STRING.finditer(expr))
    cases.append(("application-error-express", body, True))
    return cases, [source, bundled]


class CapturedClient:
    def __init__(self, url, page):
        self.url, self.page, self.requests = url, page, []

    def get(self, url, headers=None):
        self.requests.append(url)
        page = self.page if url == self.url else {"status": 404, "body": ""}
        return HttpResult(url=url, method="GET", status=page["status"],
                          headers=page.get("headers", {}), body=page["body"].encode())


def run(zap_root, pages_path):
    cases, sources = zap_cases(zap_root)
    db = default_db()
    rows = []
    for name, body, expected in cases:
        url = "https://fixture.invalid/"
        client = CapturedClient(url, {"status": 200, "body": body})
        ctx = DetectorContext(client=client, db=db, target=Target(url, "fixture.invalid"),
                              endpoint=Endpoint(url))
        findings = detect_information_disclosure(ctx)
        rows.append({"id": name, "expected_alert": expected, "actual_alert": bool(findings),
                     "passed": bool(findings) == expected, "requests": len(client.requests),
                     "finding_types": [f.vuln_type for f in findings],
                     "severities": [f.severity.value for f in findings]})
    pages = []
    for name, page in json.loads(pages_path.read_text()).items():
        url = "https://fixture.invalid" + page["path"]
        client = CapturedClient(url, page)
        target = TargetRecognizer(client, max_urls=20, max_depth=1).recognize(url)
        title = re.search(r"<title[^>]*>(.*?)</title>", page["body"], re.I | re.S)
        expected_title = unescape(title[1]).strip() if title else ""
        checks = {"title": target.title == expected_title,
                  "endpoint_budget": target.url_count <= 20,
                  "request_budget": len(client.requests) <= 22,
                  "same_origin": all(u.startswith("https://fixture.invalid/") for u in client.requests)}
        pages.append({"application": name, "status": page["status"],
                      "body_sha256": hashlib.sha256(page["body"].encode()).hexdigest(),
                      "title": target.title, "urls": target.url_count,
                      "requests": len(client.requests), "checks": checks})
    return {"scope": "passive fixture compatibility and page metadata/boundaries only; not vulnerability recall",
            "zap_source": "https://github.com/zaproxy/zap-extensions",
            "zap_commit": subprocess.check_output(["git", "-C", str(zap_root), "rev-parse", "HEAD"], text=True).strip(),
            "source_files": [{"path": str(p.relative_to(zap_root)), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in sources],
            "passive_cases": rows, "passive_passed": sum(r["passed"] for r in rows),
            "passive_total": len(rows), "pages": pages,
            "limitations": ["Selected two ZAP unit-test classes, not a full ZAP run",
                            "ZAP generic-error alerts and Sentinel detailed-disclosure alerts have different scope",
                            "Only captured login/home pages, no authentication, browser or active exploit validation"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zap-root", type=Path, required=True)
    parser.add_argument("--pages", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.zap_root, args.pages)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passive_passed": result["passive_passed"], "passive_total": result["passive_total"], "pages": result["pages"]}))


if __name__ == "__main__":
    main()
