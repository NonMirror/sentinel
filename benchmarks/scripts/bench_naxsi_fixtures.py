"""Offline static-request subset of upstream Naxsi Test::Nginx fixtures.

Never evaluates Perl, starts nginx, or transmits fixture requests. Compares the
allow/block implication of error_code, not response bytes, logging or nginx routing.
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
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sentinel.core.models import HttpRequest
from sentinel.vendor import naxsi_core_rules
from sentinel.waf.naxsi.engine import NativeNaxsiEngine
from sentinel.waf.naxsi.syntax import load_naxsi_rules, parse_check_rule, parse_main_rule


def sections(block):
    pieces = re.split(r"(?m)^--- ([^\n]+)\n", block)
    result = {}
    for index in range(1, len(pieces), 2):
        label, separator, inline = pieces[index].partition(":")
        result[label.strip()] = inline.strip() if separator else pieces[index + 1].rstrip("\n")
    return result


def run(root):
    files = sorted((root / "t").glob("*.t"))
    if not files:
        raise ValueError("No Naxsi Test::Nginx fixtures found")
    core = root / "naxsi_config/naxsi_core.rules"
    if core.read_bytes() != naxsi_core_rules().read_bytes():
        raise ValueError("Fixture core rules differ from the vendored core; compare versions explicitly")
    digest, counts, rows, skipped = hashlib.sha256(), {}, [], []
    for path in files:
        relative = str(path.relative_to(root))
        blob = path.read_bytes()
        digest.update(relative.encode() + b"\0" + blob)
        parts = re.split(r"(?m)^=== ([^\n]*)\n", blob.decode("utf-8", "replace"))
        for index in range(1, len(parts), 2):
            identifier = f"{relative}:{(index + 1) // 2}:{parts[index]}"
            data = sections(parts[index + 1])
            count = counts.setdefault(path.name, Counter())
            count["total"] += 1
            config = "\n".join(line.split("#", 1)[0] for line in data.get("config", "").splitlines())
            reason = ""
            if "request" not in data or any("eval" in key or key.startswith("raw_request") for key in data):
                reason = "dynamic-perl-or-raw-request"
            elif re.search(r"\b(?:BasicRule|LearningMode|SecRulesDisabled|IgnoreIP|IgnoreCIDR|LibInjectionSql|LibInjectionXss)\b|\bset\s+\$naxsi", config):
                reason = "unsupported-runtime-configuration"
            elif any(name not in {"config", "main_config", "http_config", "request", "more_headers", "error_code", "response_body", "error_log", "no_error_log", "user_files", "response_body_like"} for name in data):
                reason = "unsupported-test-sections"
            elif data.get("error_code") not in {"200", "404", "405", "412"}:
                reason = "unsupported-status-expectation"
            elif re.findall(r"\blocation\s+([^\s{]+)", config) != ["/", "/RequestDenied"]:
                reason = "location-routing"
            elif "SecRulesEnabled;" not in config or not re.search(r"\breturn\s+412\s*;", config):
                reason = "unsupported-enforcement-configuration"
            elif re.sub(r"(?m)^include\s+\S*/naxsi_core\.rules;\s*$|(?m:^MainRule[^\n]*$)", "", data.get("http_config", "")).strip():
                reason = "external-http-configuration"
            if reason:
                count["skipped"] += 1
                skipped.append({"id": identifier, "reason": reason})
                continue
            request_line, _, body_text = data["request"].partition("\n")
            method, _, target = request_line.partition(" ")
            if not target or any(c.isspace() for c in target):
                count["skipped"] += 1
                skipped.append({"id": identifier, "reason": "nonliteral-request-target"})
                continue
            headers = {"Host": "localhost"}
            for line in data.get("more_headers", "").splitlines():
                key, separator, value = line.partition(":")
                if not separator:
                    raise ValueError(f"Invalid static header in {identifier}")
                headers[key.strip()] = value.strip()
            body = body_text.encode()
            if body:
                headers["Content-Length"] = str(len(body))
                if not any(k.lower() == "content-type" for k in headers):
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
            uri = urlsplit(target)
            request = HttpRequest(method=method, target=target, path=unquote(uri.path), query=uri.query,
                                  headers=headers, body=body, remote_addr="127.0.0.1")
            rules = load_naxsi_rules([core])
            for line in data.get("http_config", "").splitlines():
                if line.strip().startswith("MainRule"):
                    rule = parse_main_rule(line.strip())
                    if rule:
                        rules.rules.append(rule)
            rules.checks = [parse_check_rule(m[0]) for m in re.finditer(r'CheckRule\s+[^;]+;', config)]
            if not rules.checks or any(c is None for c in rules.checks):
                count["skipped"] += 1
                skipped.append({"id": identifier, "reason": "unsupported-check-rule"})
                continue
            verdict = NativeNaxsiEngine(rules).inspect(request)
            expected = data["error_code"] == "412"
            passed = verdict.blocked == expected
            count.update(executed=1, passed=int(passed), expected_block=int(expected),
                         missed=int(expected and not verdict.blocked),
                         unexpected_block=int(not expected and verdict.blocked))
            rows.append({"id": identifier, "expected_block": expected, "actual_block": verdict.blocked,
                         "passed": passed, "rules": verdict.matched_rules()})
    totals = Counter()
    for count in counts.values():
        totals.update(count)
    return {"source": "https://github.com/nbs-system/naxsi", "commit": subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
            "fixture_sha256": digest.hexdigest(), "core_sha256": hashlib.sha256(core.read_bytes()).hexdigest(),
            "totals": totals, "by_file": counts, "cases": rows, "skipped": skipped,
            "limitations": ["Archived original upstream; static request subset of Test::Nginx fixtures",
                            "No Perl eval, nginx module, response/log assertions or routing validation",
                            "Missing body content type defaults to form encoding in the adapter",
                            "Skipped blocks remain in the full-suite denominator"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--naxsi-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.naxsi_root)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["totals"]))


if __name__ == "__main__":
    main()
