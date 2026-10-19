"""Argument size accounting and explicit test limits using ordinary data."""
import json

import pytest

from benchmarks.scripts.bench_crs_fixtures import load_test_limits
from benchmarks.scripts.bench_regressions import request
from sentinel.waf.secrule.syntax import Variable
from sentinel.waf.secrule.variables import Transaction
from tests.test_secrule import build_engine
from tests.test_waf_multipart import multipart


def size(tx):
    return [m.value for m in tx.resolve(Variable(name='ARGS_COMBINED_SIZE'))]


def test_empty_argument_size_is_an_existing_zero_scalar():
    tx = Transaction(request())
    assert size(tx) == ['0']
    assert tx.resolve(Variable(name='ARGS_COMBINED_SIZE', count=True))[0].value == '1'


@pytest.mark.parametrize('target,body,expected', [
    ('/?a=one', b'b=two', '8'),
    ('/?k=1&k=2', b'k=3', '6'),
    ('/?note=%E5%8C%97%E4%BA%AC', b'', '10'),
    ('/?%ff=%fe', b'n=%ff', '4'),
    ('/?empty=&bare', b'=value', '14'),
])
def test_total_counts_names_values_duplicates_and_decoded_bytes(target, body, expected):
    assert size(Transaction(request(target=target, body=body))) == [expected]


def test_json_argument_size_counts_utf8_names_and_values():
    body = '{"é":"北京"}'.encode()
    tx = Transaction(request(target='/?a=1', body=body, content_type='application/json'))
    # a + 1 = 2; json.é = 7 bytes; 北京 = 6 bytes.
    assert size(tx) == ['15']


def test_surrogate_json_text_does_not_abort_size_accounting():
    tx = Transaction(request(body=b'{"x":"\\ud800"}', content_type='application/json'))
    assert size(tx) == ['9']


def test_multipart_arguments_exclude_file_contents():
    body = multipart(b'Content-Disposition: form-data; name="note"\r\n\r\n\x80\xff',
                     b'Content-Disposition: form-data; name="file"; filename="report.txt"\r\n\r\n' + b'x' * 1000)
    tx = Transaction(request(target='/?a=1', body=body, content_type='multipart/form-data; boundary=sample-boundary'))
    assert size(tx) == ['8']


def test_body_processor_override_recomputes_cached_argument_size():
    tx = Transaction(request(target='/?a=1', body=b'{"note":"ordinary"}', content_type='text/plain'))
    assert size(tx) == ['2']
    assert tx.set_body_processor('JSON')
    assert size(tx) == ['19']  # a=1 plus json.note + ordinary.


@pytest.mark.parametrize('total,blocked', [(9, False), (10, False), (11, True)])
def test_explicit_total_limit_respects_strict_boundary(total, blocked):
    engine = build_engine('''
SecAction "id:1,phase:1,pass,nolog,setvar:tx.total_arg_length=10"
SecRule ARGS_COMBINED_SIZE "@gt %{tx.total_arg_length}" "id:2,phase:2,deny"
''')
    verdict = engine.inspect(request(body=b'n=' + b'x' * (total - 1)))
    assert verdict.blocked is blocked and engine.stats['errors'] == 0


def test_test_profile_reads_only_declared_size_limits(tmp_path):
    path = tmp_path / 'tests/docker-compose.yml'
    path.parent.mkdir()
    path.write_text(json.dumps({'x-common-env': {
        'ARG_LENGTH': 400, 'TOTAL_ARG_LENGTH': 6400, 'MAX_FILE_SIZE': '64100',
        'COMBINED_FILE_SIZES': '65535', 'BACKEND': 'ignored', 'ARG_NAME_LENGTH': 1,
    }}))
    limits, digest = load_test_limits(tmp_path)
    assert limits == {'arg_length': 400, 'total_arg_length': 6400,
                      'max_file_size': 64100, 'combined_file_sizes': 65535}
    assert len(digest) == 64


@pytest.mark.parametrize('invalid', [True, '-1', '1,deny', '1.5', 0, 2**31])
def test_test_profile_rejects_invalid_limit_values(tmp_path, invalid):
    path = tmp_path / 'tests/docker-compose.yml'
    path.parent.mkdir()
    path.write_text(json.dumps({'x-common-env': {'ARG_LENGTH': invalid}}))
    with pytest.raises(ValueError, match='Invalid upstream test limit'):
        load_test_limits(tmp_path)
