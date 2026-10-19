"""Replay upstream ModSecurity operator/transformation fixtures without HTTP."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import statistics
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sentinel.waf.secrule.operators import evaluate
from sentinel.waf.secrule.syntax import OPERATOR_DISPLAY, Operator, _prepare
from sentinel.waf.secrule.transforms import TRANSFORMS


def fixture_bytes(text):
    """Match the upstream unit harness's UTF-8 strings and json2bin byte escapes."""
    value = text.encode("utf-8").decode("latin-1")
    for pattern in (r"\\x([0-9a-fA-F]{2})", r"\\u([0-9a-fA-F]{4})"):
        while re.search(pattern, value):
            value = re.sub(pattern, lambda m: chr(int(m[1], 16) & 255), value)
    return value


def run(root):
    language = root / "test/test-cases/secrules-language-tests"
    files = sorted((language / "operators").glob("*.json")) + sorted((language / "transformations").glob("*.json"))
    if not files:
        raise ValueError("Missing secrules-language-tests submodule")
    files += sorted((root / "test/test-cases/unit").glob("*.json"))
    digest = hashlib.sha256()
    counts, failures, skipped = {}, [], []
    for path in files:
        blob = path.read_bytes()
        relative = str(path.relative_to(root))
        digest.update(relative.encode() + b"\0" + blob)
        for index, case in enumerate(json.loads(blob)):
            identifier = f"{relative}:{index}"
            name = case["name"].lower().replace("_", "").replace("normalise", "normalize")
            category = f"{case['type']}:{name}"
            count = counts.setdefault(category, Counter())
            count["total"] += 1
            reason = ""
            if case.get("capture") or case.get("libinjection_override"):
                reason = "capture-or-native-error-hook"
            elif case.get("resource"):
                reason = "external-resource"
            elif case["type"] == "tfn" and name not in TRANSFORMS:
                reason = "unsupported-transformation"
            elif case["type"] == "op" and name not in OPERATOR_DISPLAY:
                reason = "unsupported-operator"
            elif case["type"] not in ("op", "tfn"):
                reason = "unsupported-type"
            if reason:
                count["skipped"] += 1
                skipped.append({"id": identifier, "category": category, "reason": reason})
                continue
            value = fixture_bytes(case["input"])
            try:
                if case["type"] == "tfn":
                    # The official runner compares output bytes, not the legacy tfn ret flag.
                    actual = TRANSFORMS[name](value)
                    expected = fixture_bytes(case["output"])
                else:
                    operator = Operator(name=name, argument=case.get("param", ""))
                    _prepare(operator, root / "test")
                    actual, expected = int(evaluate(operator, value)), case["ret"]
                passed = actual == expected
                error = ""
            except Exception as exc:
                passed, error = False, type(exc).__name__
            count["executed"] += 1
            count["passed"] += int(passed)
            if not passed:
                failures.append({"id": identifier, "category": category, "error": error})
    totals = Counter()
    for count in counts.values():
        totals.update(count)
    return {"source": "https://github.com/owasp-modsecurity/ModSecurity",
            "commit": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
            "language_tests_commit": subprocess.check_output(["git", "-C", str(language), "rev-parse", "HEAD"], text=True).strip(),
            "fixture_sha256": digest.hexdigest(), "totals": dict(totals),
            "macro_pass_rate_all_categories": statistics.mean(c["passed"] / c["total"] for c in counts.values()),
            "by_operation": counts, "failures": failures, "skipped": skipped,
            "limitations": ["In-process operator/transformation adapter, not the native ModSecurity runner",
                            "No HTTP, rule configuration, native error hooks, capture or external database checks",
                            "Unsupported tests stay in total and macro-rate denominators; IP tests dominate raw totals"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modsecurity-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.modsecurity_root)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"totals": result["totals"], "macro_pass_rate": result["macro_pass_rate_all_categories"]}))


if __name__ == "__main__":
    main()
