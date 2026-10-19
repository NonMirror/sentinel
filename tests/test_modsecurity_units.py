"""Independent inert regressions for public ModSecurity fixture findings."""
import hashlib

import pytest

from benchmarks.scripts.bench_modsecurity_units import fixture_bytes, run
from sentinel.waf.secrule.operators import evaluate
from sentinel.waf.secrule.syntax import Operator
from sentinel.waf.secrule.transforms import TRANSFORMS, apply_chain, load_unicode_mapping
from benchmarks.scripts.bench_regressions import request
from tests.test_secrule import build_engine


def test_fixture_byte_decoding_matches_upstream_harness():
    assert fixture_bytes(r"\x41\u0142") == "AB"
    assert fixture_bytes("é") == "\xc3\xa9"
    assert fixture_bytes(r"\0") == r"\0"


def test_missing_language_tests_fail_explicitly(tmp_path):
    with pytest.raises(ValueError, match="submodule"):
        run(tmp_path)


@pytest.mark.parametrize("name", ["md5", "sha1"])
def test_hash_transform_returns_binary_before_explicit_hex_encoding(name):
    expected = getattr(hashlib, name)(b"ordinary").digest()
    assert TRANSFORMS[name]("ordinary").encode("latin-1") == expected
    assert apply_chain((name, "hexEncode"), "ordinary") == expected.hex()


def test_utf8_conversion_is_not_silently_disabled_by_format_error():
    assert TRANSFORMS["utf8tounicode"]("北京".encode().decode("latin-1")) == "%u5317%u4eac"


@pytest.mark.parametrize("name,value,expected", [
    ("cmdline", 'Ordinary , /Path', "ordinary/path"),
    ("cmdline", " A ; B ", " a b "),
    ("normalizepath", "/../../ordinary", "/ordinary"),
    ("normalizepath", "../ordinary", "../ordinary"),
    ("normalizepath", r"a\b", r"a\b"),
    ("normalizepathwin", r"a\b", "a/b"),
    ("urlencode", "ordinary value_*", "ordinary+value%5f*"),
])
def test_documented_transform_semantics(name, value, expected):
    assert TRANSFORMS[name](value) == expected


@pytest.mark.parametrize("name,param,value,expected", [
    ("contains", "Marker", "marker", False),
    ("containsword", "mark", "1mark2", True),
    ("containsword", "mark", "remark", False),
    ("strmatch", "mark", "a marker", True),
    ("eq", "0", "ordinary", True),
    ("gt", "10", "12suffix", True),
    ("eq", "0", "9" * 5000, True),
    ("gt", "10", "9" * 5000, True),
    ("rx", "", "ordinary", True),
    ("validatebyterange", "", "ordinary", True),
])
def test_operator_contracts(name, param, value, expected):
    assert evaluate(Operator(name=name, argument=param), value) is expected


@pytest.mark.parametrize("name,value,expected", [
    ("urldecodeuni", "ordinary+name%2B", "ordinary name+"),
    ("urldecodeuni", "%u0020%uFF1F%u1101", " ?\x01"),
    ("urldecodeuni", "\xe9%20", "\xe9 "),
    ("cssdecode", r"\12345", "E"),
    ("cssdecode", "x\\\ny\\", "xy"),
    ("cssdecode", r"\5c 31", r"\31"),
    ("escapeseqdecode", r"\X41\666", "A\xb6"),
    ("hexdecode", "4142f", "AB"),
    ("hexdecode", "0z", "#"),
    ("htmlentitydecode", "&#65 &#X42;&COLON;&lbrack;", "A B:["),
    ("htmlentitydecode", "&ltest;&caret;&tilde;&hyphen;", "&ltest;&caret;&tilde;&hyphen;"),
    ("htmlentitydecode", "&#" + "9" * 5000 + ";", "\xff"),
    ("removecomments", "a<!-- ordinary -->b/* unfinished", "ab "),
    ("removecomments", "a# remainder", "a"),
    ("replacecomments", "a/* unfinished", "a "),
    ("base64decode", "QQ==\x00Qg==", "A"),
    ("base64decode", "!!!!", "!!!!"),
    ("base64decodeext", "?QQ==", "A"),
    ("base64decodeext", "QQQQQ==QQ", ""),
    ("base64decodeext", "Pz8_", "???"),
    ("base64encode", "A\x00B", "QQBC"),
])
def test_byte_transform_contracts(name, value, expected):
    assert TRANSFORMS[name](value) == expected


def test_unicode_mapping_uses_only_the_declared_default_codepage(tmp_path):
    path = tmp_path / "unicode.mapping"
    path.write_text("1252 (other)\n0020:40 00e9:58\n20127 (US-ASCII)\n00e9:65\n37 (other)\n00e9:59\n")
    assert load_unicode_mapping(str(path)) == {0xE9: "e"}


@pytest.mark.parametrize("name,odd", [("parityeven7bit", False), ("parityodd7bit", True)])
def test_parity_preserves_ascii_payload_bits(name, odd):
    result = TRANSFORMS[name]("".join(map(chr, range(128))))
    for original, char in enumerate(result):
        assert ord(char) & 127 == original
        assert ord(char).bit_count() % 2 == odd


def test_zero_parity_clears_only_the_high_bit():
    result = TRANSFORMS["parityzero7bit"]("".join(map(chr, range(256))))
    assert list(map(ord, result)) == [i & 127 for i in range(256)]


@pytest.mark.parametrize("huge", ["1e9999", "9" * 5000, "-1e9999"])
def test_unbounded_score_input_does_not_abort_later_rules(huge):
    engine = build_engine(f'''
SecAction "id:1,phase:1,pass,nolog,setvar:'tx.current={huge}'"
SecAction "id:2,phase:1,pass,nolog,setvar:'tx.current=+{huge}'"
SecRule ARGS:note "@streq ordinary" "id:3,phase:2,deny"
''')
    verdict = engine.inspect(request(target="/?note=ordinary"))
    assert verdict.blocked
    assert engine.stats["errors"] == 0
