"""Byte-preserving URL-encoded WAF collections, using ordinary marker values."""
from urllib.parse import quote_from_bytes

import pytest

from benchmarks.scripts.bench_regressions import request
from sentinel.waf.parser import parse_request
from sentinel.waf.secrule.syntax import Variable
from sentinel.waf.secrule.transforms import apply_chain
from sentinel.waf.secrule.variables import Transaction, query_pairs
from tests.test_secrule import build_engine


def values(tx, collection):
    return [(m.key, m.value) for m in tx.resolve(Variable(name=collection))]


@pytest.mark.parametrize('post', [False, True])
def test_all_percent_encoded_bytes_survive_collection_parsing(post):
    raw = bytes(range(256))
    form = 'note=' + quote_from_bytes(raw, safe='')
    req = (request(body=form.encode(), content_type='application/x-www-form-urlencoded')
           if post else request(target='/?' + form))
    tx = Transaction(req)
    assert values(tx, 'ARGS_POST' if post else 'ARGS_GET') == [('note', raw.decode('latin-1'))]


@pytest.mark.parametrize('raw', ['北京'.encode(), b'caf\xc3\xa9', b'ordinary', b'\xff\xfe'])
def test_literal_wire_bytes_and_percent_encoded_forms_agree(raw):
    literal = parse_request(b'GET /?note=' + raw + b' HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n')
    encoded = request(target='/?note=' + quote_from_bytes(raw, safe=''))
    assert values(Transaction(literal), 'ARGS_GET') == values(Transaction(encoded), 'ARGS_GET')


def test_invalid_utf8_names_and_values_remain_distinct_and_repeated():
    assert query_pairs('%ff=%fe&%fe=%ff&%ff=ordinary') == [('\xff', '\xfe'), ('\xfe', '\xff'), ('\xff', 'ordinary')]


def test_form_decoding_occurs_once_and_keeps_empty_values():
    assert query_pairs('note=%2541+%2B&empty=&bare&bad=%xy') == [
        ('note', '%41 +'), ('empty', ''), ('bare', ''), ('bad', '%xy')]


def test_explicit_utf8_transformation_receives_original_bytes():
    tx = Transaction(request(target='/?note=' + quote_from_bytes('北京'.encode())))
    value = values(tx, 'ARGS_GET')[0][1]
    assert apply_chain(('utf8toUnicode',), value) == '%u5317%u4eac'
    assert apply_chain(('length',), value) == '6'


def test_body_processor_override_uses_the_same_byte_contract():
    tx = Transaction(request(target='/?query=%ff', body=b'note=%fe', content_type='text/plain'))
    assert tx.set_body_processor('URLENCODED')
    assert values(tx, 'ARGS_GET') == [('query', '\xff')]
    assert values(tx, 'ARGS_POST') == [('note', '\xfe')]


def test_custom_rule_byte_length_and_capture_agree():
    engine = build_engine('''
SecRule ARGS:note "@rx ^(.{6})$" "id:1,phase:2,deny,nolog,capture,chain"
    SecRule TX:1 "@eq 6" "t:length"
''')
    result = engine.inspect(request(target='/?note=' + quote_from_bytes('北京'.encode())))
    assert result.blocked and engine.stats['errors'] == 0


@pytest.mark.parametrize('name', ['lowercase', 'uppercase'])
def test_case_transform_changes_ascii_bytes_only(name):
    raw = bytes(range(256))
    expected = raw.lower() if name == 'lowercase' else raw.upper()
    assert apply_chain((name,), raw.decode('latin-1')) == expected.decode('latin-1')


@pytest.mark.parametrize('name,expected', [
    ('trim', '\xa0note\x85'),
    ('trimLeft', '\xa0note\x85 \t\r\n\v\f'),
    ('trimRight', ' \t\r\n\v\f\xa0note\x85'),
])
def test_trim_keeps_non_ascii_bytes(name, expected):
    value = ' \t\r\n\v\f\xa0note\x85 \t\r\n\v\f'
    assert apply_chain((name,), value) == expected


@pytest.mark.parametrize('name', ['removeWhitespace', 'compressWhitespace'])
def test_whitespace_transform_matches_byte_classification(name):
    import re
    raw = bytes(range(256))
    # removeWhitespace explicitly includes the two NBSP bytes upstream;
    # compressWhitespace uses only the C-locale whitespace class.
    expected = (raw.translate(None, b' \t\r\n\v\f\xc2\xa0') if name == 'removeWhitespace'
                else re.sub(rb'\s+', b' ', raw)).decode('latin-1')
    assert apply_chain((name,), raw.decode('latin-1')) == expected


def test_command_line_case_conversion_does_not_corrupt_utf8_bytes():
    value = 'CAFÉ, REPORT'.encode().decode('latin-1')
    assert apply_chain(('cmdLine',), value) == 'cafÉ report'.encode().decode('latin-1')
