"""Offline collection-name assertions from ModSecurity's ordinary JSON regression."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel.core.models import HttpRequest
from sentinel.waf.secrule.syntax import Variable
from sentinel.waf.secrule.variables import Transaction

FIXTURE = "test/test-cases/regression/issue-1576.json"


def run(root):
    blob = (root / FIXTURE).read_bytes()
    cases = json.loads(blob)
    if not cases:
        raise ValueError("Missing JSON collection cases")
    rows = []
    for index, case in enumerate(cases):
        source = case["request"]
        expectation = case["expected"].get("debug_log", "")
        if (case.get("enabled") != 1 or source["headers"].get("Content-Type") != "application/json"
                or not isinstance(source["body"], list) or not source["body"]
                or not all(isinstance(line, str) for line in source["body"])
                or "Variable: ARGS:json." not in expectation
                or not any("ctl:requestBodyProcessor=JSON" in rule for rule in case["rules"])):
            raise ValueError(f"Unadapted JSON collection assertion: {index}")
        body = "\n".join(source["body"]).encode()
        path, _, query = source["uri"].partition("?")
        req = HttpRequest(method=source["method"], target=source["uri"], path=path, query=query,
                          headers=source["headers"], body=body)
        tx = Transaction(req)
        matches = tx.resolve(Variable(name="ARGS"))
        # Apply the upstream value/name expectation to rendered collection entries,
        # not a claim to reproduce its native debug log or phase-3 execution.
        actual = [f'{m.value}" (Variable: {m.name}:{m.key})' for m in matches]
        passed = tx.resolve(Variable(name="REQBODY_ERROR"))[0].value == "0" and any(
            re.search(expectation, line) for line in actual)
        rows.append({"id": f"{FIXTURE}:{index}", "title": case["title"],
                     "expected_debug_pattern": expectation, "body_sha256": hashlib.sha256(body).hexdigest(),
                     "arguments": [[m.key, m.value] for m in matches], "passed": passed})
    return {"source": "https://github.com/owasp-modsecurity/ModSecurity",
            "commit": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
            "fixture": FIXTURE, "fixture_sha256": hashlib.sha256(blob).hexdigest(),
            "totals": {"total": len(rows), "passed": sum(r["passed"] for r in rows),
                       "failed": sum(not r["passed"] for r in rows)}, "cases": rows,
            "limitations": ["One selected public regression file, not the complete native suite",
                            "Only expected value/name visibility is checked; no native log, response status or phase-3 assertion",
                            "Body lines joined with LF and inspected in memory; no HTTP framing or active requests",
                            "Same ModSecurity source as the operator suite; not counted as another public source"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modsecurity-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.modsecurity_root)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result["totals"]))
