"""Offline syntax boundaries and policy isolation; no commands are executed."""
from urllib.parse import quote

import pytest

from sentinel.core.config import Config
from sentinel.waf.crs_profiles import SYNTAX_RULES, apply_balanced_profile
from sentinel.waf.engines.modsecurity import ModSecurityEngine
from sentinel.waf.secrule import SecRuleEngine
from sentinel.waf.secrule.syntax import load_ruleset, parse_statement
from tests.test_secrule import make_request


@pytest.fixture(scope='module')
def driver():
    return ModSecurityEngine(Config.load('examples/waf-balanced.toml'))


@pytest.mark.parametrize('value,rule_id', [
    ('confirm.call(null, 7)', 10000010),
    ('window.prompt.apply(null, [7])', 10000010),
    ('alert?.(7)', 10000010),
    ('cn:1.2.3:=fixture', 10000011),
    ('*(|(cn=fixture))', 10000011),
    ('note\nMAIL FROM: <fixture@example.invalid>\n', 10000012),
    ('| set /a 2+3', 10000013),
    ('| getent hosts fixture.invalid', 10000013),
    ('--label=`fixture_marker`', 10000014),
])
def test_syntax_indicators_are_observable_and_scored(driver, value, rule_id):
    verdict = driver.inspect(make_request(target='/?note=' + quote(value, safe='')))
    assert verdict.blocked and rule_id in verdict.matched_rules


@pytest.mark.parametrize('value', [
    'confirm policy before submitting', 'prompt.call is a method name',
    'alert.level = info', 'myconfirm.call(null, 7)',
    '(cn:1.2.3:=fixture)', '(cn=fixture)', 'version 1.2.3',
    'MAIL FROM: support@example.invalid', 'Send mail to support@example.invalid',
    'set /a is documented here', 'getent hosts is documented here',
    'pipe | fixture marker', 'inline `fixture_marker` in documentation',
    '--label=fixture', 'query { viewer { name email } }',
    '{ __schema { queryType { name } } }', 'Mozilla/5.0 (compatible; example)',
    'Nuclei is a testing tool',
])
def test_words_punctuation_and_valid_query_structures_still_pass(driver, value):
    verdict = driver.inspect(make_request(target='/?note=' + quote(value, safe='')))
    assert not verdict.blocked, (value, verdict.matched_rules)
    assert not {r[0] for r in SYNTAX_RULES}.intersection(verdict.matched_rules)


@pytest.mark.parametrize('blocking,detection,observed,blocked', [
    (1, 1, False, False), (1, 4, True, False), (4, 4, True, True),
])
def test_syntax_respects_detection_and_blocking_levels(blocking, detection, observed, blocked):
    config = Config.load('examples/waf-balanced.toml')
    config.waf.paranoia_level = blocking
    config.waf.detection_paranoia_level = detection
    engine = ModSecurityEngine(config)
    verdict = engine.inspect(make_request(target='/?q=cn%3A1.2.3%3A%3Dfixture'))
    assert (10000011 in verdict.matched_rules) is observed
    assert verdict.blocked is blocked
    if not blocked:
        assert verdict.anomaly_score == 0


@pytest.mark.parametrize('mode', ['detect', 'off'])
def test_syntax_does_not_force_blocking_modes(mode):
    config = Config.load('examples/waf-balanced.toml')
    config.waf.mode = mode
    verdict = ModSecurityEngine(config).inspect(make_request(target='/?q=cn%3A1.2.3%3A%3Dfixture'))
    assert not verdict.blocked
    assert (10000011 in verdict.matched_rules) is (mode == 'detect')


def test_extension_id_collision_retains_standard_rules():
    driver = ModSecurityEngine(Config())
    rule = parse_statement('SecRule ARGS "@contains ordinary" "id:10000010,phase:2,pass"')
    driver.engine.ruleset.items.append(rule)
    assert apply_balanced_profile(driver.engine.ruleset) == []
    assert any('reserved ID collision' in warning for warning in driver.engine.ruleset.warnings)
    assert not any('sentinel/advisory' in r.tags for r in driver.engine.ruleset.rules)


def test_export_round_trip_preserves_syntax_behavior(driver, tmp_path):
    path = tmp_path / 'balanced.conf'
    driver.export_rules(path)
    restored = SecRuleEngine(load_ruleset([path]), paranoia_level=4)
    for value in ['cn:1.2.3:=fixture', '(cn:1.2.3:=fixture)']:
        request = make_request(target='/?q=' + quote(value, safe=''))
        before, after = driver.inspect(request), restored.inspect(request)
        assert before.blocked == after.blocked
        assert before.anomaly_score == after.anomaly_score


def test_new_acceptance_gate_does_not_reuse_previous_85_percent_target():
    from benchmarks.scripts.bench_waf_acceptance import summarize
    rows = [{'label': 'attack', 'category': 'example', 'blocked': True}] * 94
    rows += [{'label': 'attack', 'category': 'example', 'blocked': False}] * 6
    rows += [{'label': 'benign', 'category': 'normal', 'blocked': False}] * 100
    assert summarize(rows)['meets_macro_gate']
    assert not summarize(rows, .95, .055)['meets_macro_gate']
    with pytest.raises(ValueError):
        summarize(rows, float('nan'), .055)
