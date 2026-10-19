"""Offline public-fixture adapters and defensive JSON contracts."""
import json
from pathlib import Path

import pytest

from benchmarks.scripts.bench_crs_fixtures import load_cases, render_body
from benchmarks.scripts.bench_passive_public import CapturedClient
from benchmarks.scripts.bench_regressions import request
from sentinel.vendor import naxsi_core_rules
from sentinel.core.models import Severity
from sentinel.scanner.crawler import Endpoint, Target
from sentinel.scanner.detectors import DetectorContext, detect_information_disclosure
from sentinel.scanner.vulndb import default_db
from sentinel.waf.naxsi import NativeNaxsiEngine, load_naxsi_rules
from sentinel.waf.parser import iter_variable_values, parse_json_arguments, parse_xml_values
from sentinel.waf.parser import parse_request
from sentinel.waf.secrule.syntax import Variable
from sentinel.waf.secrule.variables import Transaction
from tests.test_secrule import build_engine


@pytest.mark.parametrize("content_type", ["application/json", "application/problem+json; charset=utf-8"])
def test_json_fields_preserve_duplicates_and_decode_values(content_type):
    req = request(body=b'{"name":"sentinel-\\u006dark","name":"ordinary"}', content_type=content_type)
    assert iter_variable_values(req, "ARGS:name") == ["sentinel-mark", "ordinary"]
    tx = Transaction(req)
    assert [m.value for m in tx.resolve(Variable(name="ARGS_POST", selectors=("json.name",)))] == ["sentinel-mark", "ordinary"]
    engine = build_engine('SecRule ARGS:json.name "@streq sentinel-mark" "id:1,phase:2,deny"')
    assert engine.inspect(req).blocked


def test_nested_json_arrays_and_null_remain_visible():
    fields = parse_json_arguments('{"users":[{"name":"Alice"},{"name":null}]}')
    assert fields == [("users[0].name", "Alice"), ("users[1].name", "")]


@pytest.mark.parametrize("content_type", ["text/xml", "application/xml", "application/soap+xml"])
def test_xml_text_attributes_and_numeric_references_are_inspected(content_type):
    body = b'<root name="sentinel-&#109;ark">sentinel-<child>mark</child></root>'
    req = request(body=body, content_type=content_type)
    tx = Transaction(req)
    assert [m.value for m in tx.resolve(Variable(name="XML", selectors=("/*",)))] == ["sentinel-mark"]
    assert [m.value for m in tx.resolve(Variable(name="XML", selectors=("//@*",)))] == ["sentinel-mark"]
    assert tx.resolve(Variable(name="REQBODY_ERROR"))[0].value == "0"
    for selector in ("/*", "//@*"):
        engine = build_engine(f'SecRule XML:{selector} "@streq sentinel-mark" "id:1,phase:2,deny"')
        assert engine.inspect(req).blocked


@pytest.mark.parametrize("body", [b'<root>', b'<!DOCTYPE root><root/>',
                                   '<!DOCTYPE root><root/>'.encode('utf-16'),
                                   b'<r>' * 33 + b'</r>' * 33])
def test_invalid_dtd_or_deep_xml_preserves_raw_inspection(body):
    assert parse_xml_values(body) is None
    tx = Transaction(request(body=body, content_type="application/xml"))
    assert tx.resolve(Variable(name="REQBODY_ERROR"))[0].value == "1"
    assert tx.resolve(Variable(name="XML", selectors=("/*",)))[0].value


@pytest.mark.parametrize("body", [b'{"name":', b'{"name":"\xff"}', b'[' * 12 + b'"marker"' + b']' * 12])
def test_invalid_or_deep_json_is_inspected_raw_and_reports_error(body):
    assert parse_json_arguments(body) is None
    tx = Transaction(request(body=body, content_type="application/json"))
    assert tx.resolve(Variable(name="REQBODY_ERROR"))[0].value == "1"
    assert tx.resolve(Variable(name="ARGS"))
    assert NativeNaxsiEngine._surfaces(tx.request)["BODY"]


@pytest.mark.parametrize("body", [b'{}', b'[]', b'{"name":"Alice","active":true}', '{"城市":"北京"}'.encode()])
def test_json_syntax_does_not_trigger_naxsi_rules(body):
    engine = NativeNaxsiEngine(load_naxsi_rules([naxsi_core_rules()]))
    verdict = engine.inspect(request(body=body, content_type="application/json"))
    assert not verdict.blocked, verdict.as_dict()


def test_naxsi_does_not_score_generated_array_indexes():
    req = request(body=b'{"tags":["one","two"],"literal[0]":"ordinary"}', content_type="application/json")
    values = NativeNaxsiEngine._surfaces(req)["BODY"]
    assert "tags[0]" not in values and "literal[0]" in values
    assert "one" in values and "two" in values
    assert parse_json_arguments(req.body)[0] == ("tags[0]", "one")


@pytest.mark.parametrize("content_type,body", [
    ("application/json", b'{"tags":["one","two"]}'),
    ("application/xml", b'<note language="en">ordinary text</note>'),
])
def test_naxsi_structured_benign_bodies_pass(content_type, body):
    engine = NativeNaxsiEngine(load_naxsi_rules([naxsi_core_rules()]))
    assert not engine.inspect(request(body=body, content_type=content_type)).blocked


def test_naxsi_xml_decoded_values_and_invalid_body_remain_visible():
    req = request(body=b'<note language="&#65;">&#66;</note>', content_type="application/xml")
    assert NativeNaxsiEngine._surfaces(req)["BODY"] == ["B", "language", "A"]
    req.body = b'<!DOCTYPE note><note>ordinary</note>'
    assert NativeNaxsiEngine._surfaces(req)["BODY"] == [req.body.decode()]


def test_crs_adapter_preserves_rule_specific_negatives_and_reports_skips(tmp_path):
    folder = tmp_path / "tests/regression/tests/REQUEST-999-TEST"
    folder.mkdir(parents=True)
    doc = {"tests": [
        {"test_id": 1, "stages": [{"input": {"uri": "/", "data": "name=ordinary"},
                                    "output": {"log": {"no_expect_ids": [999001]}}}]},
        {"test_id": 2, "stages": [{"input": {"encoded_request": ""},
                                    "output": {"log": {"expect_ids": [999001]}}}]},
        {"test_id": 3, "stages": []},
    ]}
    (folder / "999001.yaml").write_text(json.dumps(doc))
    cases, skipped, digest = load_cases(tmp_path)
    assert len(cases) == 1 and cases[0][3] == {"no_expect_ids": [999001]}
    assert cases[0][2].body == b"name=ordinary"
    assert {s["reason"] for s in skipped} == {"raw-wire-semantics", "multi-stage"}
    assert len(digest) == 64


def test_crs_adapter_rejects_missing_fixture_directory(tmp_path):
    with pytest.raises(ValueError, match="No CRS"):
        load_cases(tmp_path)


@pytest.mark.parametrize("body,expected", [
    ('ordinary text', b'ordinary text'),
    ('name={{ "ab" | repeat 3 }}\n', b'name=ababab\n'),
    ('{{ "a" | repeat 0 }}{{ "b" | repeat 2 }}', b'bb'),
    ('{{ "城" | repeat 2 }}', '城城'.encode()),
    ('{{ "x" | repeat 1048576 }}', b'x' * 1048576),
])
def test_crs_repeat_template_preserves_literal_body_bytes(body, expected):
    assert render_body(body) == expected


@pytest.mark.parametrize("body,reason", [
    ('{{ env "HOME" }}', 'unsupported-body-template'),
    ('{{ "a" | repeat -1 }}', 'unsupported-body-template'),
    ('{{ "a" | repeat 99999999999999999999 }}', 'unsupported-body-template'),
    (r'{{ "a\n" | repeat 2 }}', 'unsupported-body-template'),
    ('{{ incomplete', 'unsupported-body-template'),
    ('{{ "城" | repeat 400000 }}', 'template-size-limit'),
    ('{{ "x" | repeat 524288 }}{{ "x" | repeat 524289 }}', 'template-size-limit'),
    ('x{{ "x" | repeat 1048576 }}', 'template-size-limit'),
])
def test_crs_template_limits_and_unsupported_forms_are_explicit(body, reason):
    with pytest.raises(ValueError, match=reason):
        render_body(body)


def test_crs_adapter_renders_before_content_length_and_lists_unsupported(tmp_path):
    folder = tmp_path / 'tests/regression/tests/REQUEST-999-TEST'
    folder.mkdir(parents=True)
    tests = []
    for index, (body, headers) in enumerate([
        ('{{ "x" | repeat 12 }}', {}),
        ('{{ "x" | repeat 12 }}', {'Content-Length': '7'}),
        ('{{ env "HOME" }}', {}),
        ('{{ "x" | repeat 1048577 }}', {}),
    ]):
        tests.append({'test_id': index, 'stages': [{'input': {'data': body, 'headers': headers},
                                                   'output': {'log': {'expect_ids': [999001]}}}]})
    (folder / '999001.yaml').write_text(json.dumps({'tests': tests}))
    cases, skipped, _ = load_cases(tmp_path)
    assert len(cases) == 2
    assert all(case[2].body == b'x' * 12 for case in cases)
    assert [case[2].headers['Content-Length'] for case in cases] == ['12', '7']
    assert [s['reason'] for s in skipped] == ['unsupported-body-template', 'template-size-limit']


@pytest.mark.parametrize('target,header', [
    ('/?note=北京', 'café'), ('/ordinary?note=é', '北京'),
    ('/ordinary?note=%C3%A9', 'ordinary'),
])
def test_crs_adapter_matches_utf8_request_line_and_header_bytes(tmp_path, target, header):
    folder = tmp_path / 'tests/regression/tests/REQUEST-999-TEST'
    folder.mkdir(parents=True)
    data = {'uri': target, 'headers': {'Host': 'fixture.invalid', 'X-Note': header}}
    doc = {'tests': [{'test_id': 1, 'stages': [{'input': data, 'output': {'log': {'expect_ids': [999001]}}}]}]}
    (folder / '999001.yaml').write_text(json.dumps(doc))
    cases, skipped, _ = load_cases(tmp_path)
    assert not skipped and len(cases) == 1
    direct = parse_request(f'GET {target} HTTP/1.1\r\nHost: fixture.invalid\r\nX-Note: {header}\r\n\r\n'.encode())
    adapted = cases[0][2]
    assert (adapted.target, adapted.query, adapted.path, adapted.headers) == (
        direct.target, direct.query, direct.path, direct.headers)


@pytest.mark.parametrize("body,expected", [
    ("<pre>ReferenceError: missingName is not defined</pre>", True),
    ("<h1>500 Internal Server Error</h1>", True),
    ("<p>This guide explains Internal Server Error responses.</p>", False),
    ("<p>We document the SyntaxError: class below.</p>", False),
    ("<html>Healthy service</html>", False),
])
def test_passive_error_observations_are_informational(body, expected):
    url = "https://fixture.invalid/"
    client = CapturedClient(url, {"status": 200, "body": body})
    ctx = DetectorContext(client=client, db=default_db(), target=Target(url, "fixture.invalid"),
                          endpoint=Endpoint(url))
    findings = detect_information_disclosure(ctx)
    assert bool(findings) is expected
    assert all(f.severity is Severity.INFO and f.vuln_type == "response_error" for f in findings)
    assert client.requests == [url]


def test_detailed_traceback_keeps_existing_severity():
    url = "https://fixture.invalid/"
    client = CapturedClient(url, {"status": 500, "body": "<pre>Traceback (most recent call last):</pre>"})
    ctx = DetectorContext(client=client, db=default_db(), target=Target(url, "fixture.invalid"),
                          endpoint=Endpoint(url))
    findings = detect_information_disclosure(ctx)
    assert findings[0].severity is Severity.MEDIUM
