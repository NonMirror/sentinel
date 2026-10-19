"""Defensive multipart and SecRule contracts using inert marker values."""
import pytest

from benchmarks.scripts.bench_regressions import request
from sentinel.waf.parser import collect_arguments, iter_variable_values, parse_multipart
from sentinel.waf.secrule.operators import evaluate
from sentinel.waf.secrule.syntax import Operator, Variable
from sentinel.waf.secrule.variables import Transaction
from tests.test_secrule import build_engine


def multipart(*parts, boundary="sample-boundary"):
    return b"".join(b"--" + boundary.encode() + b"\r\n" + p + b"\r\n" for p in parts) + b"--" + boundary.encode() + b"--\r\n"


def values(tx, name, selector=None):
    return [m.value for m in tx.resolve(Variable(name=name, selectors=(selector,) if selector else ()))]


def test_fields_files_duplicates_and_exact_body_bytes():
    body = multipart(
        b'Content-Disposition: form-data; name="note"\r\n\r\n  ordinary -- text  ',
        b'content-disposition: form-data; name="note"\r\n\r\nsentinel-mark',
        b'Content-Disposition: form-data; name="upload"; filename="notes.txt"\r\nContent-Type: text/plain\r\n\r\n\x00bytes\r\n',
    )
    req = request(body=body, content_type='multipart/form-data; boundary="sample-boundary"')
    parsed = parse_multipart(body, req.content_type)
    assert not parsed.errors
    assert parsed.parts[0].value == b"  ordinary -- text  "
    assert parsed.parts[-1].value == b"\x00bytes\r\n"
    tx = Transaction(req)
    assert values(tx, "ARGS_POST", "note") == ["  ordinary -- text  ", "sentinel-mark"]
    assert values(tx, "ARGS_POST", "upload") == []
    assert values(tx, "FILES") == ["notes.txt"]
    assert values(tx, "FILES_NAMES") == ["upload"]
    assert values(tx, "FILES_SIZES", "upload") == ["8"]
    assert values(tx, "FILES_COMBINED_SIZE") == ["8"]
    assert "Content-Type: text/plain" in values(tx, "MULTIPART_PART_HEADERS", "upload")
    assert values(tx, "REQBODY_ERROR") == ["0"]
    assert iter_variable_values(req, "FILES_NAMES") == ["upload"]
    assert collect_arguments(req)["note"] == "  ordinary -- text  "
    engine = build_engine('SecRule ARGS:note "@streq sentinel-mark" "id:1,phase:2,deny"')
    assert engine.inspect(req).blocked


def test_literal_boundary_prefix_in_value_is_not_a_delimiter():
    body = multipart(b'Content-Disposition: form-data; name="note"\r\n\r\nfirst\r\n--sample-boundary-extra\r\nlast')
    parsed = parse_multipart(body, "multipart/form-data; boundary=sample-boundary")
    assert not parsed.errors
    assert parsed.parts[0].value == b"first\r\n--sample-boundary-extra\r\nlast"


@pytest.mark.parametrize("disposition,name,filename", [
    (br'form-data; name="ordinary\note"; filename="C:\notes\report.txt"',
     r'ordinary\note', r'C:\notes\report.txt'),
    (br'form-data; name="or\dinary"; filename="report.t\x\t"',
     r'or\dinary', r'report.t\x\t'),
    (br'form-data; name="a\"b"; filename="a\"b\\c.txt"', 'a"b', 'a"b\\c.txt'),
    (br'form-data; name="\"note\""; filename="report.txt"', '"note"', 'report.txt'),
    (b"form-data; name*=utf-8''caf%C3%A9; filename*=utf-8''caf%C3%A9.txt",
     'café', 'café.txt'),
    (b'form-data; name="note";\r\n filename="report.txt"', 'note', 'report.txt'),
])
def test_multipart_parameter_decoding_preserves_http_backslashes(disposition, name, filename):
    body = multipart(b'Content-Disposition: ' + disposition + b'\r\n\r\nordinary')
    req = request(body=body, content_type='multipart/form-data; boundary=sample-boundary')
    parsed = parse_multipart(body, req.content_type)
    assert not parsed.errors
    assert [(p.name, p.filename, p.value) for p in parsed.parts] == [(name, filename, b'ordinary')]
    tx = Transaction(req)
    assert values(tx, 'FILES_NAMES') == [name]
    assert values(tx, 'FILES') == [filename]


@pytest.mark.parametrize("content_type,body,collection", [
    ("application/xml", b'<marker marker="ordinary">ordinary</marker>', "XML"),
    ("multipart/form-data; boundary=sample-boundary",
     multipart(b'Content-Disposition: form-data; name="note"\r\n\r\nordinary'), "ARGS"),
])
def test_parsed_body_exposes_values_without_reinspecting_serialization(content_type, body, collection):
    tx = Transaction(request(body=body, content_type=content_type))
    assert values(tx, "REQUEST_BODY") == []
    assert "ordinary" in values(tx, collection, "/*" if collection == "XML" else None)
    assert values(tx, "REQUEST_BODY_LENGTH") == [str(len(body))]


@pytest.mark.parametrize("content_type,body", [
    ("application/json", b'{"note":'),
    ("application/xml", b'<note>ordinary'),
    ("multipart/form-data; boundary=x", b'ordinary'),
    ("application/x-www-form-urlencoded", b'note=ordinary'),
    ("text/plain", b'ordinary'),
])
def test_unparsed_body_keeps_raw_inspection(content_type, body):
    tx = Transaction(request(body=body, content_type=content_type))
    assert values(tx, "REQUEST_BODY") == [body.decode("latin-1")]


def test_json_raw_keys_and_empty_containers_remain_visible():
    body = b'{"notes":[],"labels":["ordinary"]}'
    tx = Transaction(request(body=body, content_type="application/json"))
    assert values(tx, "REQUEST_BODY") == [body.decode()]
    assert "ordinary" in values(tx, "ARGS")


def test_empty_json_body_still_reports_selected_processor():
    tx = Transaction(request(body=b"", content_type="application/json"))
    assert values(tx, "REQBODY_PROCESSOR") == ["JSON"]
    assert values(tx, "REQBODY_ERROR") == ["1"]


def test_tag_target_exclusion_is_scoped_to_tag_target_and_transaction():
    engine = build_engine('''
SecRule REQUEST_HEADERS:X-Skip "@streq yes" "id:1,phase:1,pass,ctl:ruleRemoveTargetByTag=sample;REQUEST_FILENAME"
SecRule REQUEST_FILENAME|ARGS "@contains marker" "id:2,phase:2,deny,tag:sample"
SecRule REQUEST_FILENAME "@contains marker" "id:3,phase:2,deny,tag:other"
''')
    req = request(target="/marker?q=ordinary")
    req.headers["X-Skip"] = "yes"
    assert engine.inspect(req).matched_rules == [1, 3]
    req.headers.pop("X-Skip")
    assert 2 in engine.inspect(req).matched_rules
    req = request(target="/marker?q=marker")
    req.headers["X-Skip"] = "yes"
    assert 2 in engine.inspect(req).matched_rules


@pytest.mark.parametrize("content_type,body", [
    ("multipart/form-data", b"unparsed-marker"),
    ("multipart/form-data; boundary=x", b"--x\r\nContent-Disposition: form-data; name=note\r\n\r\nmarker"),
    ("multipart/form-data; boundary=x", b"--x\r\nMissing: name\r\n\r\nmarker\r\n--x--\r\n"),
    ("multipart/form-data; boundary=x\r\nOther: value", b"marker"),
])
def test_malformed_multipart_keeps_raw_body_visible(content_type, body):
    req = request(body=body, content_type=content_type)
    tx = Transaction(req)
    assert values(tx, "REQBODY_ERROR") == ["1"]
    assert values(tx, "ARGS", "BODY") == [body.decode("latin-1")]
    assert iter_variable_values(req, "ARGS:BODY")


def test_empty_fields_and_repeated_uploads_remain_distinct():
    body = multipart(b'Content-Disposition: form-data; name="empty"\r\n\r\n',
                     b'Content-Disposition: form-data; name="files"; filename="one.txt"\r\n\r\na',
                     b'Content-Disposition: form-data; name="files"; filename="two.txt"\r\n\r\nbc')
    tx = Transaction(request(body=body, content_type="multipart/form-data; boundary=sample-boundary"))
    assert values(tx, "ARGS", "empty") == [""]
    assert values(tx, "FILES", "files") == ["one.txt", "two.txt"]
    assert values(tx, "FILES_COMBINED_SIZE") == ["3"]


def test_deep_mime_header_cannot_escape_the_inspection_error_boundary():
    content_type = "multipart/form-data; " + "(" * 1200 + "note" + ")" * 1200 + "; boundary=x"
    tx = Transaction(request(body=b"--x--\r\n", content_type=content_type))
    assert values(tx, "REQBODY_ERROR") == ["1"]
    assert values(tx, "ARGS", "BODY") == ["--x--\r\n"]


@pytest.mark.parametrize("count,valid", [(1000, True), (1001, False)])
def test_part_limit(count, valid):
    body = multipart(*([b'Content-Disposition: form-data; name="field"\r\n\r\nx'] * count))
    parsed = parse_multipart(body, "multipart/form-data; boundary=sample-boundary")
    assert bool(parsed.errors) is not valid
    assert len(parsed.parts) == 1000


def test_tx_regex_selector_and_dynamic_assignment_names():
    tx = Transaction(request())
    tx.set_tx("headers_0", "first")
    tx.set_tx("headers_1", "second")
    assert values(tx, "TX", "/^HEADERS_[0-9]+$/") == ["first", "second"]
    engine = build_engine('''
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.counter=0'"
SecAction "id:2,phase:1,pass,nolog,setvar:'tx.headers_%{tx.counter}=sentinel-mark'"
SecRule TX:/^HEADERS_[0-9]+$/ "@streq sentinel-mark" "id:3,phase:1,deny"
''')
    assert engine.inspect(request()).blocked


@pytest.mark.parametrize("needle,haystack,expected", [
    ("POST", "GET,POST,HEAD", True), ("|utf-8|", "|utf-8| |iso-8859-1|", True),
    ("range", "content-range", True), ("/range/", "/content-range/", False),
    ("post", "GET,POST,HEAD", False), ("", "anything", True),
])
def test_within_is_case_sensitive_substring_matching(needle, haystack, expected):
    assert evaluate(Operator(name="within", argument=haystack), needle) is expected


def test_chain_side_effects_feed_next_link_and_survive_failed_chain():
    engine = build_engine('''
SecRule ARGS:note "@streq ordinary" "id:1,phase:2,pass,nolog,setvar:'tx.first=ready',chain"
    SecRule TX:first "@streq ready" "setvar:'tx.second=ready',chain"
    SecRule TX:second "@streq different"
SecRule TX:second "@streq ready" "id:2,phase:2,deny"
''')
    verdict = engine.inspect(request(target="/?note=ordinary"))
    assert verdict.matched_rules == [2]


def test_pass_actions_run_for_each_matching_variable():
    engine = build_engine('''
SecAction "id:1,phase:2,pass,nolog,setvar:'tx.count=0'"
SecRule ARGS "@streq marker" "id:2,phase:2,pass,nolog,setvar:'tx.count=+1'"
SecRule TX:count "@eq 2" "id:3,phase:2,deny"
''')
    assert engine.inspect(request(target="/?a=marker&b=marker&c=ordinary")).blocked


def test_multimatch_checks_pre_transform_value():
    engine = build_engine('SecRule ARGS "@streq Marker" "id:1,phase:2,deny,t:lowercase,multiMatch"')
    assert engine.inspect(request(target="/?a=Marker")).blocked


def test_chain_sees_last_parent_assignment_and_counts_child_once():
    engine = build_engine('''
SecRule ARGS "@rx (.*)" "id:1,phase:2,pass,nolog,capture,setvar:'tx.note=%{tx.1}',chain"
    SecRule TX:note "@streq marker" "setvar:'tx.count=+1'"
SecRule TX:count "@eq 1" "id:2,phase:2,deny"
''')
    assert engine.inspect(request(target="/?a=ordinary&b=marker")).blocked


def test_matched_collection_keeps_all_values_and_colons_in_selector():
    engine = build_engine('''
SecRule ARGS "@rx marker" "id:1,phase:2,deny,t:lowercase,chain"
    SecRule &MATCHED_VARS:/^ARGS:/ "@eq 2" "chain"
    SecRule MATCHED_VARS "@streq 2"
''')
    assert engine.inspect(request(target="/?a=MARKER&b=marker")).blocked


def test_matched_var_cache_tracks_successive_operators_without_setvar():
    engine = build_engine('''
SecRule ARGS:a "@streq first" "id:1,phase:2,pass,nolog,chain"
    SecRule MATCHED_VAR "@streq first"
SecRule ARGS:b "@streq second" "id:2,phase:2,deny,chain"
    SecRule MATCHED_VAR "@streq second"
''')
    assert engine.inspect(request(target="/?a=first&b=second")).blocked
