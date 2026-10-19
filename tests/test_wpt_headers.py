"""Inert public-header parsing regressions; no network or browser execution."""
import json

import pytest

from benchmarks.scripts.bench_wpt_headers import CORP, NOSNIFF, SUPPORT, load_cases
from sentinel.core.models import Severity
from sentinel.scanner.client import HttpResult
from sentinel.scanner.headers import has_nosniff, inspect_security_headers


@pytest.mark.parametrize('value,active', [
    ('nosniff', True), (' \tNoSnIfF\t ', True),
    ('nosniff, other', True), ('other, nosniff', False),
    (',nosniff', False), ('"nosniff, other"', False),
    ('"nosniff"', False), ('nosniff\v', False), ('nosniff\f', False),
    ('nosniff\u00a0', False), ('nosniff\r', False), ('nosniff\n', False),
])
def test_nosniff_first_value_and_http_whitespace(value, active):
    assert has_nosniff(value) is active


def test_noncanonical_but_effective_policy_is_not_reported_as_absent():
    response = HttpResult(url='https://fixture.invalid/', method='GET', status=200,
                          header_items=[('X-Content-Type-Options', 'nosniff'),
                                        ('x-content-type-options', 'other')])
    result = inspect_security_headers(response)
    assert len(result) == 1 and result[0].severity is Severity.INFO
    assert '仍启用 nosniff' in result[0].proof
    assert '缺少或无效' not in result[0].proof
    response.header_items.reverse()
    assert '缺少或无效' in inspect_security_headers(response)[0].proof


@pytest.mark.parametrize('suffix', ['\v', '\f', '\u00a0'])
def test_non_http_whitespace_does_not_hide_missing_protection(suffix):
    response = HttpResult(url='https://fixture.invalid/', method='GET', status=200,
                          headers={'X-Content-Type-Options': 'nosniff' + suffix})
    result = inspect_security_headers(response)
    assert len(result) == 1 and '缺少或无效' in result[0].proof


def fixture_tree(root, raw='X-Content-Type-Options: nosniff\v', table='"ordinary",'):
    for path in (NOSNIFF, CORP, *SUPPORT):
        p = root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('fixture source')
    (root / NOSNIFF).write_text(json.dumps([{'input': raw, 'nosniff': False}]))
    (root / CORP).write_text('[' + table + '''].forEach(incorrectHeaderValue => {
      promise_test(t => {
        return fetch(crossOriginURL + encodeURIComponent(incorrectHeaderValue), { mode: "no-cors" });
      });
    });''')


def test_wpt_adapter_keeps_control_characters_and_expected_values(tmp_path):
    fixture_tree(tmp_path)
    cases, files = load_cases(tmp_path)
    assert len(cases) == 2 and len(files) == 4
    assert cases[0]['header_items'] == [('X-Content-Type-Options', 'nosniff\v')]
    assert cases[0]['expected'] is False and cases[1]['expected'] is True


def test_wpt_adapter_keeps_duplicate_order_and_empty_first_value(tmp_path):
    fixture_tree(tmp_path, raw='X-Content-Type-Options:\r\nx-content-type-options: nosniff')
    cases, _ = load_cases(tmp_path)
    assert cases[0]['header_items'] == [('X-Content-Type-Options', ''), ('x-content-type-options', 'nosniff')]


def test_wpt_adapter_rejects_unrecognized_table_syntax(tmp_path):
    fixture_tree(tmp_path, table='makeValue(),')
    with pytest.raises(ValueError, match='Unadapted WPT CORP table entry'):
        load_cases(tmp_path)


def test_wpt_adapter_requires_upstream_expectation(tmp_path):
    fixture_tree(tmp_path)
    (tmp_path / NOSNIFF).write_text(json.dumps([{'input': 'X: ordinary'}]))
    with pytest.raises(ValueError, match='Unadapted WPT nosniff assertion'):
        load_cases(tmp_path)


def test_wpt_adapter_rejects_absent_sources(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_cases(tmp_path)
