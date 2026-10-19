"""Offline HTTPWG Item-syntax validation for passive scanner policy headers.

Checks accept/reject and primary tokens, not typed trees or serialization.
Lists/dictionaries and optional can_fail cases remain in reported totals.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sentinel.scanner.structured_headers import inspect_structured_item


def run(root):
    files = sorted(root.glob("*.json"))
    if not files:
        raise ValueError("No HTTPWG fixture JSON files found")
    digest, rows, skipped, totals, by_file = hashlib.sha256(), [], [], Counter(), {}
    for path in files:
        blob = path.read_bytes()
        digest.update(path.name.encode() + b"\0" + blob)
        cases = json.loads(blob)
        count = by_file.setdefault(path.name, Counter())
        for index, case in enumerate(cases):
            identifier = f"{path.name}:{index}:{case['name']}"
            count["total"] += 1
            if case["header_type"] != "item" or case.get("can_fail"):
                reason = "non-item-container" if case["header_type"] != "item" else "optional-acceptance"
                count["skipped"] += 1
                skipped.append({"id": identifier, "reason": reason})
                continue
            if not isinstance(case.get("raw"), list) or not all(isinstance(v, str) for v in case["raw"]):
                raise ValueError(f"Invalid raw fixture: {identifier}")
            expected_valid = not case.get("must_fail", False)
            actual = inspect_structured_item(", ".join(case["raw"]))
            passed = (actual is not None) == expected_valid
            if expected_valid and isinstance(case["expected"][0], dict) and case["expected"][0].get("__type") == "token":
                passed = passed and actual == ("token", case["expected"][0]["value"])
            count.update(executed=1, passed=int(passed), expected_valid=int(expected_valid),
                         rejected_valid=int(expected_valid and actual is None),
                         accepted_invalid=int(not expected_valid and actual is not None))
            rows.append({"id": identifier, "expected_valid": expected_valid,
                         "actual_valid": actual is not None, "passed": passed})
        totals.update(count)
    return {"source": "https://github.com/httpwg/structured-field-tests",
            "commit": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
            "fixture_sha256": digest.hexdigest(), "totals": totals, "by_file": by_file,
            "cases": rows, "skipped": skipped,
            "limitations": ["Protocol component benchmark, not vulnerability detection or a browser test",
                            "Item accept/reject and primary token only; no typed-value/parameter-tree equality",
                            "List/dictionary containers, optional can_fail cases and serialization are not executed",
                            "No network requests, upstream code execution or dependency installation"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--httpwg-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.httpwg_root)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["totals"]))


if __name__ == "__main__":
    main()
