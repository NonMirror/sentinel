"""Passive header syntax and public-fixture adapter contracts."""
import json
from unittest.mock import patch

import pytest

from benchmarks.scripts.bench_structured_headers import run
from sentinel.scanner.structured_headers import inspect_structured_item
from tests.test_passive_headers import findings


@pytest.mark.parametrize("value", [
    'same-origin', 'same-origin; report-to="endpoint"', 'same-origin; report-to',
    'same-origin; extra=123', 'same-origin; extra=?0', 'same-origin; extra=:YWJj:',
    'same-origin; extra=@123', 'same-origin; extra=%"%c3%bc"',
    'same-origin; extra="a,b;c"', 'same-origin; extra=1; extra=2', 'same-origin; extra',
])
def test_valid_policy_token_with_parameters(value):
    assert inspect_structured_item(value) == ("token", "same-origin")
    assert not findings({"Cross-Origin-Opener-Policy": value})


@pytest.mark.parametrize("value", [
    '', '"same-origin"', 'Same-Origin', 'same-origin, same-origin',
    'same-origin; report-to=invalid endpoint', 'same-origin; Report-To=x',
    'same-origin; extra="unfinished', 'same-origin; extra=1.2345',
    'same-origin; extra=%"%C3%BC"', 'same-origin; extra=%"%ff"',
    'same-origin; extra=:a:', 'same-origin; extra=?2',
    'same-origin; extra=9999999999999999',
])
def test_invalid_coop_is_informational(value):
    result = findings({"Cross-Origin-Opener-Policy": value})
    assert len(result) == 1 and result[0].severity.value == "info"


@pytest.mark.parametrize("value,valid", [
    ('require-corp', True), ('credentialless', True), ('unsafe-none', True),
    ('require-corp; report-to="endpoint"', True), ('require-corp; report-to', True),
    ('Require-Corp', False), ('"require-corp"', False), ('same-origin', False),
    ('require-corp; report-to=two words', False),
])
def test_coep_header_values(value, valid):
    assert bool(findings({"Cross-Origin-Embedder-Policy": value})) is not valid


def test_httpwg_adapter_keeps_invalid_optional_and_unsupported_cases(tmp_path):
    cases = [
        {"name": "token", "raw": ["plain"], "header_type": "item",
         "expected": [{"__type": "token", "value": "plain"}, []]},
        {"name": "bad", "raw": ["plain, other"], "header_type": "item", "must_fail": True},
        {"name": "optional", "raw": [":YQ:"], "header_type": "item", "can_fail": True},
        {"name": "list", "raw": ["one,two"], "header_type": "list", "expected": []},
    ]
    (tmp_path / "item.json").write_text(json.dumps(cases))
    with patch("benchmarks.scripts.bench_structured_headers.subprocess.check_output", return_value="fixture\n"):
        result = run(tmp_path)
    assert result["totals"]["total"] == 4 and result["totals"]["passed"] == 2
    assert result["totals"]["skipped"] == 2
    assert {r["reason"] for r in result["skipped"]} == {"optional-acceptance", "non-item-container"}


def test_httpwg_adapter_fails_when_sources_are_missing(tmp_path):
    with pytest.raises(ValueError, match="No HTTPWG"):
        run(tmp_path)
