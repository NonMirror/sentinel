"""Isolated offline JSONTestSuite acceptance checks for the WAF body parser."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel.waf.parser import parse_json_arguments


def inspect(body):
    start = time.perf_counter_ns()
    fields = parse_json_arguments(body)
    return {"accepted": fields is not None, "field_count": len(fields) if fields is not None else None,
            "parse_ms": (time.perf_counter_ns() - start) / 1_000_000}


def run_case(body):
    try:
        process = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--worker"],
                                 input=body, capture_output=True, timeout=5)
    except subprocess.TimeoutExpired:
        return {"outcome": "timeout", "accepted": None}
    if process.returncode:
        return {"outcome": "crash", "accepted": None, "returncode": process.returncode,
                "error": process.stderr.decode("utf-8", "replace")[-1000:]}
    result = json.loads(process.stdout)
    if type(result.get("accepted")) is not bool:
        raise ValueError("Invalid parser worker result")
    return {"outcome": "accepted" if result["accepted"] else "rejected", **result}


def run(root):
    files = sorted((root / "test_parsing").glob("*.json"))
    if not files:
        raise ValueError("Missing JSONTestSuite parsing fixtures")
    rows, counts, digest = [], Counter(), hashlib.sha256()
    for path in files:
        category = path.name[:2]
        if category not in ("y_", "n_", "i_"):
            raise ValueError(f"Unknown JSONTestSuite expectation: {path.name}")
        blob = path.read_bytes()
        relative = str(path.relative_to(root))
        digest.update(relative.encode() + b"\0" + blob)
        result = run_case(blob)
        expected = True if category == "y_" else False if category == "n_" else None
        passed = result["accepted"] is expected if expected is not None else None
        counts["executed"] += 1
        counts[category + "total"] += 1
        counts[result["outcome"]] += 1
        if expected is not None:
            counts["required_expectations"] += 1
            counts["passed"] += int(passed)
            counts["failed"] += int(not passed)
        else:
            counts["implementation_defined_" + result["outcome"]] += 1
        rows.append({"id": relative, "size": len(blob), "input_sha256": hashlib.sha256(blob).hexdigest(),
                     "expected_accept": expected, "passed": passed, **result})
    unselected = [str(p.relative_to(root)) for p in sorted((root / "test_transform").glob("*.json"))]
    return {"source": "https://github.com/nst/JSONTestSuite",
            "commit": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
            "fixture_sha256": digest.hexdigest(), "timeout_seconds": 5, "totals": counts, "cases": rows,
            "unselected_transform_files": unselected,
            "limitations": ["All test_parsing files, each in a fresh process; no HTTP, proxy, rule engine or active scans",
                            "Implementation-defined i_ files are observed separately, not counted as required passes",
                            "test_transform files have no acceptance oracle here and are not executed",
                            "Existing parser depth limit still applies; rejecting a required-valid input remains a failure",
                            "Acceptance checks do not prove scalar value fidelity; separate regression tests cover that"]}


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        print(json.dumps(inspect(sys.stdin.buffer.read())))
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--json-suite-root", type=Path, required=True)
        parser.add_argument("--out", type=Path, required=True)
        args = parser.parse_args()
        result = run(args.json_suite_root)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(result["totals"]))
