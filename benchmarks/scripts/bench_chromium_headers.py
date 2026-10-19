"""Offline adaptation of two Chromium Referrer-Policy unit-test tables."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel.scanner.headers import parse_referrer_policy

SOURCE = "https://chromium.googlesource.com/chromium/src/"
SOURCE_PATH = "third_party/blink/renderer/platform/weborigin/"
STRING = r'"(?:[^"\\]|\\.)*"'
POLICIES = {"kOrigin": "origin", "kNever": "no-referrer", "kDefault": ""}


def block(text, name):
    match = re.search(rf"TEST\(SecurityPolicyTest, {name}\) \{{(.*?)(?=\nTEST\(|\nclass |\Z)", text, re.S)
    if not match:
        raise ValueError(f"Missing Chromium test: {name}")
    return match[1]


def load_cases(root):
    text = (root / "security_policy_test.cc").read_text()
    table = block(text, "ReferrerPolicyFromHeaderValue")
    normalized = re.sub(r"\s+", "", table)
    for assertion in ("EXPECT_EQ(test.is_valid,SecurityPolicy::ReferrerPolicyFromHeaderValue(test.header,test.keywords,&actual_policy));",
                      "if(test.is_valid)EXPECT_EQ(test.expected_policy,actual_policy);"):
        if assertion not in normalized:
            raise ValueError("Unadapted Chromium header assertion")
    match = re.search(r"TestCase inputs\[\] = \{(.*?)\n  \};", table, re.S)
    if not match:
        raise ValueError("Missing Chromium header table")
    pattern = re.compile(rf"\{{\s*({STRING}),\s*(true|false),\s*(k(?:DoNot)?SupportReferrerPolicyLegacyKeywords),"
                         r"\s*network::mojom::ReferrerPolicy::(\w+)\s*\}")
    if pattern.sub("", match[1]).strip(" \t\r\n,"):
        raise ValueError("Unadapted Chromium header table entry")
    cases, skipped = [], []
    for index, row in enumerate(pattern.finditer(match[1])):
        if row[4] not in POLICIES:
            raise ValueError("Unadapted Chromium policy enum")
        case = {"id": f"ReferrerPolicyFromHeaderValue:{index}", "input": json.loads(row[1]),
                "expected_valid": row[2] == "true", "expected_policy": POLICIES[row[4]]}
        if row[3] == "kSupportReferrerPolicyLegacyKeywords":
            skipped.append({**case, "reason": "Legacy meta keywords are outside HTTP header scope"})
        else:
            cases.append(case)
    table = block(text, "ReferrerPolicyToAndFromString")
    normalized = re.sub(r"\s+", "", table)
    for assertion in ("EXPECT_TRUE(SecurityPolicy::ReferrerPolicyFromString(policy,kDoNotSupportReferrerPolicyLegacyKeywords,&result));",
                      "EXPECT_EQ(string_result,policy);"):
        if assertion not in normalized:
            raise ValueError("Unadapted Chromium string assertion")
    match = re.search(r"const char\* policies\[\] = \{(.*?)\};", table, re.S)
    if not match or re.sub(STRING, "", match[1]).strip(" \t\r\n,"):
        raise ValueError("Unadapted Chromium string table")
    for index, literal in enumerate(re.findall(STRING, match[1])):
        value = json.loads(literal)
        cases.append({"id": f"ReferrerPolicyToAndFromString:{index}", "input": value,
                      "expected_valid": True, "expected_policy": value})
    if not cases or not skipped:
        raise ValueError("Incomplete Chromium fixtures")
    return cases, skipped


def run(root):
    cases, skipped = load_cases(root)
    metadata = json.loads((root / "source.json").read_text())
    if metadata["source"] != SOURCE or not re.fullmatch(r"[0-9a-f]{40}", metadata["commit"]):
        raise ValueError("Invalid Chromium source metadata")
    rows = []
    for case in cases:
        actual = parse_referrer_policy(case["input"])
        passed = bool(actual) == case["expected_valid"] and (not case["expected_valid"] or actual == case["expected_policy"])
        rows.append({**case, "actual_policy": actual, "actual_valid": bool(actual), "passed": passed})
    return {**metadata, "source_files": [
                {"path": SOURCE_PATH + name, "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest()}
                for name in ("security_policy.cc", "security_policy_test.cc")],
            "totals": {"total": len(rows) + len(skipped), "executed": len(rows),
                       "passed": sum(r["passed"] for r in rows), "failed": sum(not r["passed"] for r in rows),
                       "unsupported": len(skipped)}, "cases": rows, "skipped": skipped,
            "limitations": ["Two selected unit-test tables, not all Chromium security tests or a browser run",
                            "Canonical string round-trip cases adapt only policy selection, not the native serializer",
                            "One legacy-keyword case is explicitly unsupported, not counted as passed",
                            "HTTP header parsing only; no DOM/meta, referrer URL generation or active scans"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chromium-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.chromium_root)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result["totals"]))
