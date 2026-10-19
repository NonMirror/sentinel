"""Header observations use captured responses and never issue active probes."""
import pytest

from benchmarks.scripts.bench_observatory import load_cases, isolation_cases
from benchmarks.scripts.bench_passive_public import CapturedClient
from sentinel.core.models import Severity
from sentinel.scanner.client import HttpResult
from sentinel.scanner.crawler import Endpoint, Target
from sentinel.scanner.detectors import DetectorContext, detect_security_headers
from sentinel.scanner.headers import inspect_security_headers
from sentinel.scanner.vulndb import default_db


def findings(headers, status=200):
    return inspect_security_headers(HttpResult(url="https://fixture.invalid/", method="GET", status=status,
                                              headers={"X-Content-Type-Options": "nosniff", **headers}))


@pytest.mark.parametrize("policy,alert", [
    ("no-referrer, unknown-policy", False),
    ("unsafe-url, strict-origin", False),
    ("strict-origin, unsafe-url", True),
    ("unknown-policy", True),
    ("", True),
])
def test_referrer_uses_last_recognized_policy(policy, alert):
    assert bool(findings({"Referrer-Policy": policy})) == alert


def test_optional_headers_absent_are_not_vulnerability_findings():
    assert findings({}) == []
    assert findings({"Referrer-Policy": "unsafe-url"}, status=0) == []


def test_duplicate_header_names_cannot_hide_invalid_combination():
    result = findings({"x-content-type-options": "invalid"})
    assert [f.param for f in result] == ["X-Content-Type-Options"]
    assert result[0].severity == Severity.INFO


def test_header_values_preserve_corp_case_and_reject_combined_policies():
    assert findings({"Cross-Origin-Resource-Policy": "SAME-ORIGIN"})
    assert findings({"Cross-Origin-Resource-Policy": "same-origin, cross-origin"})
    assert not findings({"Cross-Origin-Resource-Policy": " same-origin "})


def test_detector_checks_empty_response_with_one_ordinary_get():
    url = "https://fixture.invalid/"
    client = CapturedClient(url, {"status": 204, "body": "", "headers": {}})
    ctx = DetectorContext(client=client, db=default_db(), target=Target(url, "fixture.invalid"), endpoint=Endpoint(url))
    result = detect_security_headers(ctx)
    assert len(result) == 1 and result == ctx.findings
    assert client.requests == [url]
    assert not result[0].payload


def test_observatory_adapter_does_not_succeed_without_sources(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_cases(tmp_path)


def test_observatory_adapter_preserves_cases_and_upstream_assertions(tmp_path):
    folder = tmp_path / "test"
    folder.mkdir()
    source = '''it("checks header validity", function () {
  const values = ["ordinary", "ordinary, ordinary"];
  assert.isFalse(result.pass);
});
it("checks for missing", function () {
  assert.isTrue(result.pass);
});'''
    for name in ("x-content-type-options", "cross-origin-resource-policy", "referrer-policy"):
        (folder / f"{name}.test.js").write_text(source)
    cases, skipped, digest = load_cases(tmp_path, headers=(
        "x-content-type-options", "cross-origin-resource-policy", "referrer-policy"))
    assert len(cases) == 9 and not skipped
    assert [c["expected_alert"] for c in cases[:3]] == [True, True, False]
    assert cases[2]["value"] is None and len(digest) == 64


def test_observatory_isolation_tables_keep_opposite_expectations():
    source = '''
  const invalidHeaders = {
    "unknown": "ordinary",
  };
  for (const [description, value] of Object.entries(invalidHeaders)) {
    it(`rejects ${description}`, function () {
      assert.isFalse(result.pass);
    });
  }
  const validHeaders = [
    ["same-origin", Expectation.Valid],
  ];
  for (const [value, expected] of validHeaders) {
    it(`accepts ${value}`, function () {
      assert.isTrue(result.pass);
    });
  }
  it("checks for missing", function () {
    assert.isTrue(result.pass);
  });
  it("checks for multiple headers", function () {
    reqs.responses.auto.headers["cross-origin-opener-policy"] = ["same-origin", "unsafe-none"];
    assert.isFalse(result.pass);
  });
'''
    rows = isolation_cases(source, "fixture.js", "cross-origin-opener-policy")
    assert [r["expected_alert"] for r in rows] == [True, False, False, True]
    assert rows[-1]["value"] == "same-origin, unsafe-none"
    with pytest.raises(ValueError, match="Unadapted table assertions"):
        isolation_cases(source.replace("assert.isTrue", "assert.isFalse"), "fixture.js", "cross-origin-opener-policy")
