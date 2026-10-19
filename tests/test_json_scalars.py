"""JSON scalar text must reach WAF collections unchanged and invalid syntax remain visible."""
import subprocess
from types import SimpleNamespace

import pytest

from benchmarks.scripts import bench_json_parser
from benchmarks.scripts.bench_regressions import request
from sentinel.waf.naxsi.engine import NativeNaxsiEngine
from sentinel.waf.parser import parse_json_arguments, iter_variable_values
from sentinel.waf.secrule.syntax import Variable
from sentinel.waf.secrule.variables import Transaction
from tests.test_secrule import build_engine


@pytest.mark.parametrize("token,expected", [
    ("true", "true"), ("false", "false"), ("null", ""), ("-0", "-0"),
    ("-0.0", "-0.0"), ("1.2300", "1.2300"), ("1e2", "1e2"), ("1E+02", "1E+02"),
    ("1e-10000", "1e-10000"), ("1e10000", "1e10000"),
    ("123456789012345678901234567890", "123456789012345678901234567890"),
    ('"NaN"', "NaN"), ('"Infinity"', "Infinity"),
])
def test_scalar_spelling_and_quoted_strings_are_preserved(token, expected):
    assert parse_json_arguments(token) == [("", expected)]
    body = ('{"value":' + token + '}').encode()
    req = request(body=body, content_type="application/json")
    assert iter_variable_values(req, "ARGS:value") == [expected]
    tx = Transaction(req)
    assert [m.value for m in tx.resolve(Variable(name="ARGS", selectors=("json.value",)))] == [expected]
    assert tx.resolve(Variable(name="REQUEST_BODY"))[0].value == body.decode()
    assert expected in NativeNaxsiEngine._surfaces(req)["BODY"]


def test_large_integer_is_not_limited_by_python_integer_conversion():
    token = "9" * 5000
    assert parse_json_arguments('{"value":' + token + '}') == [("value", token)]


def test_duplicate_scalars_preserve_lexemes_and_order():
    body = '{"n":1e2,"n":1.00,"n":-0,"active":true,"active":false}'
    assert parse_json_arguments(body) == [("n", "1e2"), ("n", "1.00"), ("n", "-0"),
                                          ("active", "true"), ("active", "false")]


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
@pytest.mark.parametrize("wrapper", ["{}", "[{}]", '{{"value":{}}}'])
def test_nonstandard_constants_are_rejected_and_raw_fallback_is_kept(token, wrapper):
    body = wrapper.format(token).encode()
    assert parse_json_arguments(body) is None
    req = request(body=body, content_type="application/json")
    tx = Transaction(req)
    assert tx.resolve(Variable(name="REQBODY_ERROR"))[0].value == "1"
    assert [(m.key, m.value) for m in tx.resolve(Variable(name="ARGS"))] == [("json.BODY", body.decode())]
    assert tx.resolve(Variable(name="REQUEST_BODY"))[0].value == body.decode()
    assert body.decode() in NativeNaxsiEngine._surfaces(req)["BODY"]


def test_literal_scalar_rule_and_argument_size_follow_received_text():
    engine = build_engine('SecRule ARGS:json.n "@streq 1E+02" "id:1,phase:2,deny"')
    req = request(body=b'{"n":1E+02,"active":true}', content_type="application/json")
    assert engine.inspect(req).blocked
    tx = Transaction(req)
    # json.n + 1E+02 = 11; json.active + true = 15.
    assert tx.resolve(Variable(name="ARGS_COMBINED_SIZE"))[0].value == "26"


def test_parser_worker_timeout_is_not_a_successful_rejection(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 5)
    monkeypatch.setattr(bench_json_parser.subprocess, "run", timeout)
    assert bench_json_parser.run_case(b"ordinary") == {"outcome": "timeout", "accepted": None}


def test_parser_worker_crash_is_not_a_successful_rejection(monkeypatch):
    monkeypatch.setattr(bench_json_parser.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=2, stderr=b"fixture error"))
    result = bench_json_parser.run_case(b"ordinary")
    assert result["outcome"] == "crash" and result["accepted"] is None


def test_public_adapter_keeps_implementation_defined_results_separate(tmp_path, monkeypatch):
    folder = tmp_path / "test_parsing"
    folder.mkdir()
    for name, body in (("y_plain.json", b"true"), ("n_plain.json", b"invalid"), ("i_plain.json", b"optional")):
        (folder / name).write_bytes(body)
    (tmp_path / "test_transform").mkdir()
    (tmp_path / "test_transform/number.json").write_text("123")
    monkeypatch.setattr(bench_json_parser.subprocess, "check_output", lambda *a, **k: "a" * 40)
    monkeypatch.setattr(bench_json_parser, "run_case", lambda body: {
        "outcome": "accepted" if body == b"true" else "rejected", "accepted": body == b"true"})
    result = bench_json_parser.run(tmp_path)
    assert result["totals"]["executed"] == 3 and result["totals"]["required_expectations"] == 2
    assert result["totals"]["passed"] == 2 and result["totals"]["implementation_defined_rejected"] == 1
    assert result["cases"][0]["passed"] is None
    assert result["unselected_transform_files"] == ["test_transform/number.json"]


def test_public_adapter_fails_without_fixtures(tmp_path):
    with pytest.raises(ValueError, match="Missing"):
        bench_json_parser.run(tmp_path)
