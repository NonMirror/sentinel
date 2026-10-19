"""Response classification only: all requests are replaced with memory fixtures."""
import json
from pathlib import Path

import pytest

from sentinel.core.models import Severity
from sentinel.scanner.client import HttpResult
from sentinel.scanner.crawler import Endpoint, Target
from sentinel.scanner.plugins.base import PluginContext
from sentinel.scanner.plugins.sensitive import ErrorPage, SensitiveInfo


class CapturedResponseClient:
    def __init__(self, body, status=404):
        self.body = body.encode()
        self.status = status
        self.requests = []

    def request(self, method, url, body=None, headers=None):
        assert method == "GET" and body is None
        self.requests.append(url)
        return HttpResult(url=url, method=method, status=self.status, body=self.body)


def classify(body, status=404):
    url = "https://fixture.invalid/"
    client = CapturedResponseClient(body, status)
    context = PluginContext(client=client, target=Target(url, "fixture.invalid"),
                            endpoint=Endpoint(url))
    findings = ErrorPage().run(context)
    return findings, client.requests


@pytest.mark.parametrize("banner", ["Apache/2.4.25", "nginx/1.20.0",
                                    "Microsoft-IIS/10.0", "Tomcat/9.0"])
@pytest.mark.parametrize("status", [200, 404, 500])
def test_banner_is_informational_regardless_of_status(banner, status):
    findings, requests = classify(f"<address>{banner}</address>", status)
    assert len(findings) == 1 and len(requests) == 1
    finding = findings[0]
    assert finding.vuln_type == "server_banner"
    assert finding.severity is Severity.INFO
    assert "未确认可利用漏洞" in finding.proof


def test_diagnostic_evidence_is_not_downgraded_when_banner_is_present():
    findings, requests = classify("Traceback (most recent call last):\nApache/2.4.25")
    assert len(findings) == 1 and len(requests) == 1
    assert findings[0].vuln_type == "errorpage"
    assert findings[0].severity is Severity.LOW
    assert "Python 异常" in findings[0].proof


def test_plain_error_page_is_not_reported_as_disclosure():
    findings, _ = classify("<h1>Not Found</h1><p>This page does not exist.</p>")
    assert findings == []


def test_saved_dvwa_banner_evidence_is_informational():
    source = Path(__file__).resolve().parents[1] / "benchmarks/data/20261018/dvwa-multi.json"
    historical = [row for row in json.loads(source.read_text())["findings"]
                  if row["vuln_type"] == "errorpage"]
    assert len(historical) == 10
    for row in historical:
        findings, requests = classify(row["evidence"])
        assert len(findings) == 1 and len(requests) == 1
        assert findings[0].vuln_type == "server_banner"
        assert findings[0].severity is Severity.INFO


def test_saved_juice_findings_respect_current_crawl_boundary():
    source = Path(__file__).resolve().parents[1] / "benchmarks/data/20261018/juice-multi.json"
    rows = json.loads(source.read_text())["findings"]
    rejected = []
    for row in rows:
        target = Target("http://127.0.0.1:3000/", "127.0.0.1:3000")
        target.add(row["url"])
        if not target.endpoints:
            rejected.append(row)
    assert len(rows) == 83 and len(rejected) == 54
    assert {row["vuln_type"] for row in rejected} == {
        "html_res_information_disclosure", "sensitive"}


def test_css_stacktrace_identifier_is_not_reported_as_a_debug_trace():
    url = "https://fixture.invalid/ftp"
    client = CapturedResponseClient("<style>#stacktrace { margin-top: 15px; }</style>", 200)
    context = PluginContext(client=client, target=Target(url, "fixture.invalid"),
                            endpoint=Endpoint(url))
    assert SensitiveInfo().run(context) == []


def test_stacktrace_heading_remains_detectable():
    url = "https://fixture.invalid/error"
    client = CapturedResponseClient("Stacktrace:\n at app.main(app.py:7)", 500)
    context = PluginContext(client=client, target=Target(url, "fixture.invalid"),
                            endpoint=Endpoint(url))
    findings = SensitiveInfo().run(context)
    assert len(findings) == 1 and findings[0].vuln_type == "sensitive"
