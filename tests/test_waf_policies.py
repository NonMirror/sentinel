"""Defensive body processor overrides and separate CRS observation levels."""
import pytest

from sentinel.core.config import Config
from sentinel.waf.engines.modsecurity import ModSecurityEngine
from sentinel.waf.secrule.syntax import Variable
from sentinel.waf.secrule.variables import Transaction
from tests.test_secrule import build_engine, make_request


@pytest.mark.parametrize("processor,body,variable", [
    ('JSON', b'{"field":"ordinary-marker"}', 'ARGS:json.field'),
    ('XML', b'<root>ordinary-marker</root>', 'XML:/*'),
    ('URLENCODED', b'field=ordinary-marker', 'ARGS:field'),
])
def test_control_actually_changes_body_inspection(processor, body, variable):
    waf = build_engine(f'''SecAction "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor={processor}"
SecRule {variable} "@streq ordinary-marker" "id:2,phase:2,deny"
''')
    req = make_request(method='POST', body=body, ctype='application/octet-stream')
    assert waf.inspect(req).blocked


def test_override_invalidates_cached_fields_preserves_query_and_clears_error():
    tx = Transaction(make_request(target='/?query=kept', body=b'{"field":"first","field":"second"}',
                                 ctype='application/octet-stream'))
    assert tx.resolve(Variable(name='ARGS_POST')) == []
    assert tx.set_body_processor('JSON')
    assert [m.value for m in tx.resolve(Variable(name='ARGS_POST'))] == ['first', 'second']
    assert [m.value for m in tx.resolve(Variable(name='ARGS_GET'))] == ['kept']
    assert tx.set_body_processor('XML')
    assert tx.resolve(Variable(name='REQBODY_ERROR'))[0].value == '1'
    assert tx.resolve(Variable(name='ARGS_POST')) == []
    assert tx.set_body_processor('JSON')
    assert tx.resolve(Variable(name='REQBODY_ERROR'))[0].value == '0'
    assert tx.resolve(Variable(name='XML')) == []
    assert not tx.set_body_processor('UNKNOWN')
    assert tx.resolve(Variable(name='REQBODY_PROCESSOR'))[0].value == 'JSON'


def test_forced_bad_json_still_reports_error_and_exposes_raw_fallback():
    waf = build_engine('''SecAction "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQBODY_ERROR "@eq 1" "id:2,phase:2,deny"
''')
    assert waf.inspect(make_request(body=b'{"field":', ctype='text/plain')).blocked


def test_detection_level_records_strict_rule_without_changing_blocking_level():
    config = Config()
    config.waf.paranoia_level = 1
    config.waf.detection_paranoia_level = 4
    driver = ModSecurityEngine(config)
    req = make_request(target='/?q=ordinary+text')
    result = driver.inspect(req)
    assert not result.blocked and 920273 in result.matched_rules
    assert driver.health()['blocking_paranoia_level'] == 1
    assert driver.health()['detection_paranoia_level'] == 4
    config.waf.paranoia_level = 4
    assert driver.inspect(req).blocked
    config.waf.paranoia_level = 1
    config.waf.detection_paranoia_level = None
    result = driver.inspect(req)
    assert not result.blocked and 920273 not in result.matched_rules


def test_detection_level_never_disables_blocking_level_rules():
    config = Config()
    config.waf.paranoia_level = 4
    config.waf.detection_paranoia_level = 1
    driver = ModSecurityEngine(config)
    assert driver.health()['detection_paranoia_level'] == 4
    assert driver.inspect(make_request(target='/?q=ordinary+text')).blocked


def test_body_limit_hot_update_matches_fresh_driver():
    config = Config()
    driver = ModSecurityEngine(config)
    config.waf.max_body_bytes = 4096
    driver.inspect(make_request())
    fresh = ModSecurityEngine(config)
    assert driver.engine.max_body_bytes == fresh.engine.max_body_bytes == 4096


@pytest.mark.parametrize("value", [0, 5, -1, True, '4', 2.5])
def test_invalid_detection_level_is_reported(value):
    config = Config()
    config.waf.detection_paranoia_level = value
    assert any('detection_paranoia_level' in problem for problem in config.validate())


def test_detection_level_configuration_round_trip(tmp_path):
    config = Config()
    config.waf.detection_paranoia_level = 4
    path = tmp_path / 'config.json'
    config.save(str(path))
    restored = Config.load(str(path))
    assert restored.waf.detection_paranoia_level == 4
    assert restored.waf.paranoia_level == 1 and not restored.validate()


def test_oversized_score_does_not_escape_inspection_or_erase_denial():
    waf = build_engine('SecAction "id:1,phase:1,pass,setvar:tx.blocking_inbound_anomaly_score='
                       + '9' * 5000 + '"\n'
                       + 'SecRule ARGS:field "@streq ordinary-marker" "id:2,phase:2,deny"')
    verdict = waf.inspect(make_request(target='/?field=ordinary-marker'))
    assert verdict.blocked and 2 in verdict.matched_rules
    assert verdict.anomaly_score == 0
