"""Native array names without rewriting literal object keys or losing fields."""
import json

import pytest

from benchmarks.scripts.bench_json_collections import FIXTURE, run
from benchmarks.scripts.bench_regressions import request
from sentinel.waf.parser import parse_json_arguments
from sentinel.waf.secrule.syntax import Variable
from sentinel.waf.secrule.variables import Transaction
from tests.test_secrule import build_engine


def transaction(body, content_type="application/json"):
    return Transaction(request(body=body.encode(), content_type=content_type))


@pytest.mark.parametrize("body,expected", [
    ('{"tags":["one","two"]}', [("json.tags.array_0", "one"), ("json.tags.array_1", "two")]),
    ('["one","two"]', [("json.array_0", "one"), ("json.array_1", "two")]),
    ('{"rows":[{},[],{"tag":["one","two"]},"end"]}',
     [("json.rows.array_2.tag.array_0", "one"), ("json.rows.array_2.tag.array_1", "two"), ("json.rows.array_3", "end")]),
    ('{"tag":["one"],"tag":["two"]}', [("json.tag.array_0", "one"), ("json.tag.array_0", "two")]),
    ('{"tag[0]":"literal","tag":["indexed"]}', [("json.tag[0]", "literal"), ("json.tag.array_0", "indexed")]),
    ('{"tag.array_0":"literal","tag":["indexed"]}', [("json.tag.array_0", "literal"), ("json.tag.array_0", "indexed")]),
    ('[["one"],["two",["three"]]]', [("json.array_0.array_0", "one"), ("json.array_1.array_0", "two"),
                                       ("json.array_1.array_1.array_0", "three")]),
    ('{"标签":["一"]}', [("json.标签.array_0", "一")]),
    ('"marker"', [("json", "marker")]),
    ('{"nested":{"name":"ordinary"}}', [("json.nested.name", "ordinary")]),
    ('[null,0]', [("json.array_0", ""), ("json.array_1", "0")]),
    ('{}', []),
])
def test_secrule_collection_names_and_value_order(body, expected):
    tx = transaction(body)
    assert [(m.key, m.value) for m in tx.resolve(Variable(name="ARGS"))] == expected
    assert tx.resolve(Variable(name="REQBODY_ERROR"))[0].value == "0"
    assert tx.resolve(Variable(name="REQUEST_BODY"))[0].value == body.encode().decode("latin-1")


def test_other_parser_consumers_keep_their_existing_naming():
    body = '{"tags":["one","two"],"literal[0]":"kept"}'
    assert parse_json_arguments(body) == [("tags[0]", "one"), ("tags[1]", "two"), ("literal[0]", "kept")]
    assert parse_json_arguments(body, indexed_arrays=False) == [("tags", "one"), ("tags", "two"), ("literal[0]", "kept")]


@pytest.mark.parametrize("content_type", ["application/json", "application/vnd.example+json"])
def test_native_selector_and_names_only_rule(content_type):
    tx = transaction('{"tags":["one","two"]}', content_type)
    assert [m.value for m in tx.resolve(Variable(name="ARGS_POST", selectors=("json.tags.array_1",)))] == ["two"]
    assert [m.value for m in tx.resolve(Variable(name="ARGS_NAMES"))] == ["json.tags.array_0", "json.tags.array_1"]
    engine = build_engine('SecRule ARGS:json.tags.array_1 "@streq two" "id:1,phase:2,deny"')
    assert engine.inspect(tx.request).blocked
    names = build_engine('SecRule ARGS_NAMES "@contains [" "id:1,phase:2,deny"')
    assert not names.inspect(tx.request).blocked
    assert names.inspect(transaction('{"literal[0]":"ordinary"}', content_type).request).blocked


def test_array_values_remain_inspected_with_exact_native_names():
    engine = build_engine('SecRule ARGS "@contains [" "id:1,phase:2,deny"')
    assert engine.inspect(transaction('{"tags":["ordinary [note]"]}').request).blocked


def test_override_invalidates_names_and_size_tracks_new_byte_lengths():
    tx = transaction('{"tags":["one","two"]}', "text/plain")
    assert tx.resolve(Variable(name="ARGS_NAMES")) == []
    assert tx.resolve(Variable(name="ARGS_COMBINED_SIZE"))[0].value == "0"
    tx.set_body_processor("JSON")
    assert [m.value for m in tx.resolve(Variable(name="ARGS_NAMES"))] == ["json.tags.array_0", "json.tags.array_1"]
    assert tx.resolve(Variable(name="ARGS_COMBINED_SIZE"))[0].value == "40"
    tx = transaction('{"标签":["一"]}')
    assert tx.resolve(Variable(name="ARGS_COMBINED_SIZE"))[0].value == "22"


@pytest.mark.parametrize("body", ['{"tags":', '[' * 12 + '"ordinary"' + ']' * 12])
def test_invalid_or_deep_json_still_has_error_and_raw_fallback(body):
    tx = transaction(body)
    assert tx.resolve(Variable(name="REQBODY_ERROR"))[0].value == "1"
    assert tx.resolve(Variable(name="ARGS"))[0].key == "json.BODY"
    assert tx.resolve(Variable(name="REQUEST_BODY"))[0].value == body


def fixture(root):
    path = root / FIXTURE
    path.parent.mkdir(parents=True)
    case = {"enabled": 1, "title": "Ordinary nested array", "request": {
        "method": "POST", "uri": "/", "headers": {"Content-Type": "application/json"},
        "body": ['{"tags":["one","two"]}']}, "expected": {
            "debug_log": r'two" \(Variable: ARGS:json.tags.array_1\)'},
            "rules": ['SecAction "ctl:requestBodyProcessor=JSON"']}
    path.write_text(json.dumps([case]))
    return path, case


def test_public_adapter_preserves_expected_name_and_value(tmp_path, monkeypatch):
    fixture(tmp_path)
    monkeypatch.setattr("benchmarks.scripts.bench_json_collections.subprocess.check_output", lambda *a, **k: "a" * 40)
    result = run(tmp_path)
    assert result["totals"] == {"total": 1, "passed": 1, "failed": 0}
    assert result["cases"][0]["arguments"] == [["json.tags.array_0", "one"], ["json.tags.array_1", "two"]]


def test_public_adapter_rejects_unadapted_assertion(tmp_path):
    path, case = fixture(tmp_path)
    case["expected"] = {"http_code": 200}
    path.write_text(json.dumps([case]))
    with pytest.raises(ValueError, match="Unadapted"):
        run(tmp_path)
