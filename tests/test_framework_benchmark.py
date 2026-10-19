"""Benchmark accounting must not count proxy errors as successful passive checks."""
import json

from benchmarks.scripts.bench_frameworks import cases, evaluate, snapshot
from sentinel.scanner.client import HttpResult


def test_backend_response_failure_is_never_a_passive_success():
    case = next(c for c in cases() if c["name"] == "policy-valid")
    response = HttpResult("http://fixture.local/policy/valid", "GET", status=200,
                          body=json.dumps(case["expected"]).encode(),
                          headers={"X-Content-Type-Options": "nosniff"},
                          header_items=[("X-Content-Type-Options", "nosniff")])
    baseline = snapshot(response)
    assert evaluate(response, case, baseline, "flask")["passive"]["passed"]
    response.body = b"not a JSON response"
    result = evaluate(response, case, baseline, "flask")
    assert not result["exact"] and not result["passive"]["passed"]
    assert result["passive"]["misses"] is None
    response.status = 403
    assert not evaluate(response, case, baseline, "flask")["passive"]["passed"]


def test_snapshot_does_not_sort_away_policy_order_or_duplicate_cookies():
    response = HttpResult("http://fixture.local/", "GET", status=200, body=b"{}", header_items=[
        ("Referrer-Policy", "unsafe-url"), ("Referrer-Policy", "same-origin"),
        ("Set-Cookie", "first=ordinary"), ("Set-Cookie", "second=another")])
    original = snapshot(response)
    response.header_items[:2] = reversed(response.header_items[:2])
    assert snapshot(response) != original
    response.header_items.pop()
    assert len(snapshot(response)["cookies"]) == 1 and len(original["cookies"]) == 2
