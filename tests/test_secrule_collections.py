"""Collection resolution contracts using inert labels, without network requests."""
import pytest

from sentinel.waf.secrule.syntax import Variable
from sentinel.waf.secrule.variables import Transaction
from tests.test_secrule import build_engine, make_request


@pytest.mark.parametrize("name,selector,expected", [
    ("REQUEST_HEADERS", "/^x-label$/", ["ordinary"]),
    ("REQUEST_HEADERS_NAMES", "/^x-label$/", ["X-Label"]),
    ("REQUEST_COOKIES", "/^label$/", ["first", "second"]),
    ("REQUEST_COOKIES_NAMES", "/^label$/", ["Label", "Label"]),
    ("ARGS", "/^label$/", ["third"]),
    ("REQUEST_COOKIES", "/^missing$/", []),
    ("REQUEST_HEADERS", "/[/", []),
])
def test_regex_collections_and_duplicates(name, selector, expected):
    tx = Transaction(make_request(target="/?LABEL=third", headers={
        "X-Label": "ordinary", "Cookie": "Label=first; Label=second; other=untouched"}))
    assert [m.value for m in tx.resolve(Variable(name=name, selectors=(selector,)))] == expected


def test_cookie_collection_keeps_bare_names_and_native_whitespace_boundaries():
    tx = Transaction(make_request(headers={"Cookie": " label; label=first=second; =ignored; padded = value ; final=done \t"}))
    values = tx.resolve(Variable(name="REQUEST_COOKIES"))
    assert [(m.key, m.value) for m in values] == [
        ("label", ""), ("label", "first=second"), ("padded ", " value "), ("final", "done")]
    assert tx.resolve(Variable(name="REQUEST_COOKIES", selectors=("/^label$/",), count=True))[0].value == "2"


def test_regex_exclusion_removes_only_matching_header():
    waf = build_engine('SecRule REQUEST_HEADERS|!REQUEST_HEADERS:/^x-label$/ "@streq ordinary" "id:1,phase:1,deny"')
    assert not waf.inspect(make_request(headers={"X-Label": "ordinary"})).blocked
    assert waf.inspect(make_request(headers={"X-Label": "ordinary", "X-Other": "ordinary"})).blocked


@pytest.mark.parametrize("target,basename", [("/", ""), ("/folder/", ""), ("/folder/note.txt", "note.txt"),
                                             ("/folder%5Cnote.txt", "note.txt")])
def test_basename_has_a_value_even_for_directory_paths(target, basename):
    tx = Transaction(make_request(target=target))
    values = tx.resolve(Variable(name="REQUEST_BASENAME"))
    assert len(values) == 1 and values[0].value == basename
    waf = build_engine('SecRule REQUEST_BASENAME "!@endsWith .pdf" "id:1,phase:1,deny"')
    assert waf.inspect(make_request(target=target)).blocked
    assert not waf.inspect(make_request(target="/folder/note.pdf")).blocked
