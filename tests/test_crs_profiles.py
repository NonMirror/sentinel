"""Balanced scoring preserves detection, hard denials and standard compatibility."""
import pytest

from sentinel.core.config import Config
from sentinel.waf.crs_profiles import ADVISORY_RULES, apply_balanced_profile, rule_fingerprint
from sentinel.waf.engines.modsecurity import ModSecurityEngine
from sentinel.waf.secrule import SecRuleEngine
from sentinel.waf.secrule.syntax import load_ruleset
from tests.test_secrule import build_engine, make_request


def profile_rules(monkeypatch, *, strong=0, explicit=False):
    conf = '''SecDefaultAction "phase:2,pass,log"
SecRule ARGS "@contains ordinary" "id:920273,phase:2,block,tag:OWASP_CRS,setvar:tx.inbound_anomaly_score_pl4=+5,setvar:tx.category_score=+5"
'''
    if strong:
        conf += f'SecRule ARGS "@contains evidence" "id:2,phase:2,pass,tag:OWASP_CRS,setvar:tx.inbound_anomaly_score_pl4=+{strong}"\n'
    if explicit:
        conf += 'SecRule ARGS "@contains explicit" "id:3,phase:2,deny"\n'
    conf += '''SecAction "id:4,phase:2,pass,nolog,setvar:tx.blocking_inbound_anomaly_score=%{tx.inbound_anomaly_score_pl4}"
SecRule TX:blocking_inbound_anomaly_score "@ge 5" "id:949110,phase:2,deny,tag:OWASP_CRS"
SecRule TX:category_score "@ge 5" "id:5,phase:2,pass"
'''
    ruleset = build_engine(conf).ruleset
    rule = ruleset.rules[0]
    monkeypatch.setitem(ADVISORY_RULES, rule.id, ("test", rule_fingerprint(rule)))
    assert apply_balanced_profile(ruleset) == [920273]
    return ruleset


def test_advisory_duplicates_cannot_reach_blocking_threshold(monkeypatch):
    rules = profile_rules(monkeypatch)
    engine = SecRuleEngine(rules, paranoia_level=4)
    verdict = engine.inspect(make_request(target='/?a=ordinary&b=ordinary&c=ordinary'))
    assert not verdict.blocked and verdict.anomaly_score == 0
    assert 920273 in verdict.matched_rules and 5 in verdict.matched_rules
    assert 'sentinel/advisory' in verdict.tags
    assert any('sentinel_advisory_score' in a.argument for a in rules.rules[0].actions)


def test_detection_only_level_cannot_contribute_to_blocking_budget(monkeypatch):
    rules = build_engine('''SecRule ARGS "@contains ordinary" "id:920273,phase:2,block,tag:OWASP_CRS,setvar:tx.inbound_anomaly_score_pl4=+5"
SecRule TX:score "@ge 5" "id:949110,phase:2,deny,tag:OWASP_CRS"''').ruleset
    rule = rules.rules[0]
    monkeypatch.setitem(ADVISORY_RULES, rule.id, ("test", rule_fingerprint(rule)))
    assert apply_balanced_profile(rules, blocking_level=1) == [920273]
    assert rule.setvars == ('tx.sentinel_observed_advisory_score=+5',)


@pytest.mark.parametrize('encoded,valid', [('%E4%B9%A6', True), ('caf%C3%A9', True), ('%FF', False)])
def test_path_variables_keep_utf8_wire_bytes_for_validation(encoded, valid):
    from urllib.parse import unquote_to_bytes
    from sentinel.waf.secrule.syntax import Variable
    from sentinel.waf.secrule.variables import Transaction
    from sentinel.waf.secrule.operators import _validate_utf8
    tx = Transaction(make_request(target='/items/' + encoded))
    path = tx.resolve(Variable(name='REQUEST_FILENAME'))[0].value
    base = tx.resolve(Variable(name='REQUEST_BASENAME'))[0].value
    assert path.encode('latin-1') == b'/items/' + unquote_to_bytes(encoded)
    assert base.encode('latin-1') == unquote_to_bytes(encoded)
    assert _validate_utf8(path) is valid


@pytest.mark.parametrize('score,blocked,total', [(1, False, 3), (2, False, 4), (3, True, 5), (5, True, 7)])
def test_advisory_budget_is_capped_and_needs_separate_evidence(monkeypatch, score, blocked, total):
    engine = SecRuleEngine(profile_rules(monkeypatch, strong=score), paranoia_level=4)
    result = engine.inspect(make_request(target='/?a=ordinary&evidence=evidence&b=ordinary'))
    assert result.blocked is blocked and result.anomaly_score == total


def test_explicit_denial_and_detect_off_modes_are_preserved(monkeypatch):
    rules = profile_rules(monkeypatch, explicit=True)
    req = make_request(target='/?q=ordinary+explicit')
    assert SecRuleEngine(rules).inspect(req).blocked
    assert not SecRuleEngine(rules, mode='detect').inspect(req).blocked
    assert not SecRuleEngine(rules, mode='off').inspect(req).hits


def test_unrecognized_rule_content_keeps_standard_scoring():
    engine = build_engine('''SecRule ARGS "@contains ordinary" "id:920273,phase:2,deny,tag:OWASP_CRS"
SecRule TX:score "@ge 5" "id:949110,phase:2,deny,tag:OWASP_CRS"''')
    assert apply_balanced_profile(engine.ruleset) == []
    assert engine.inspect(make_request(target='/?q=ordinary')).blocked
    assert any('standard scoring retained' in warning for warning in engine.ruleset.warnings)


def test_rule_fingerprint_covers_actions_after_raw_preview_and_chain():
    from sentinel.waf.secrule.syntax import Action
    driver = ModSecurityEngine(Config())
    rule = next(r for r in driver.engine.ruleset.rules if r.id == 920451)
    original, preview = rule_fingerprint(rule), rule.raw
    rule.chain[0].actions += (Action('deny'),)
    assert rule.raw == preview and rule_fingerprint(rule) != original
    assert 920451 not in apply_balanced_profile(driver.engine.ruleset)


def test_legacy_encoding_warning_cannot_borrow_advisory_budget(monkeypatch):
    rules = build_engine('''SecRule ARGS "@contains ordinary" "id:920273,phase:2,pass,tag:OWASP_CRS,setvar:tx.inbound_anomaly_score_pl4=+5"
SecRule ARGS "@contains ordinary" "id:920250,phase:2,pass,tag:OWASP_CRS,setvar:tx.inbound_anomaly_score_pl1=+3"
SecAction "id:4,phase:2,pass,setvar:tx.blocking_inbound_anomaly_score=%{tx.inbound_anomaly_score_pl1}"
SecRule TX:blocking_inbound_anomaly_score "@ge 5" "id:949110,phase:2,deny,tag:OWASP_CRS"''').ruleset
    rule = rules.rules[0]
    monkeypatch.setitem(ADVISORY_RULES, rule.id, ('test', rule_fingerprint(rule)))
    apply_balanced_profile(rules)
    verdict = SecRuleEngine(rules, paranoia_level=4).inspect(make_request(target='/?q=ordinary'))
    assert verdict.anomaly_score == 3 and not verdict.blocked


def test_csic_sample_offset_is_deterministic_disjoint_and_bounded():
    from benchmarks.scripts.bench_csic_benign import select_records
    corpus = [('b', 1, b'b'), ('a', 0, b'a'), ('c', 2, b'c')]
    assert select_records(corpus, 2)[1] == [('a', (0, b'a')), ('b', (1, b'b'))]
    assert select_records(corpus, 1, 2)[1] == [('c', (2, b'c'))]
    with pytest.raises(ValueError):
        select_records(corpus, 2, 2)


@pytest.mark.parametrize('mode', ['detect', 'off'])
def test_real_profile_respects_nonblocking_modes(mode):
    cfg = Config.load('examples/waf-balanced.toml')
    cfg.waf.mode = mode
    result = ModSecurityEngine(cfg).inspect(make_request(target='/?q=ordinary+text'))
    assert not result.blocked


def test_profile_hot_reload_and_round_trip(tmp_path):
    cfg = Config.load('examples/waf-balanced.toml')
    path = tmp_path / 'config.json'
    cfg.save(str(path))
    assert Config.load(str(path)).waf.crs_profile == 'balanced'
    driver = ModSecurityEngine(cfg)
    assert set(driver.health()['advisory_rule_ids']) == set(ADVISORY_RULES)
    req = make_request(target='/?q=ordinary+text')
    result = driver.inspect(req)
    assert not result.blocked and 'sentinel/advisory' in result.tags
    cfg.waf.crs_profile = 'standard'
    assert driver.inspect(req).blocked and not driver.health()['advisory_rule_ids']
    cfg.waf.crs_profile = 'balanced'
    assert not driver.inspect(req).blocked


def test_export_keeps_actual_balanced_scoring(tmp_path):
    driver = ModSecurityEngine(Config.load('examples/waf-balanced.toml'))
    path = tmp_path / 'profile.conf'
    driver.export_rules(path)
    ruleset = load_ruleset([path])
    rule = next(r for r in ruleset.rules if r.id == 920273)
    assert 'sentinel/advisory' in rule.tags
    assert any('sentinel_advisory_score' in v for v in rule.setvars)
    assert not any('inbound_anomaly_score_pl' in v for v in rule.setvars)
    assert len(next(r for r in ruleset.rules if r.id == 10000001).chain) == 2


def test_invalid_profile_cannot_silently_relax_policy():
    cfg = Config()
    cfg.waf.crs_profile = 'typo'
    assert any('crs_profile' in p for p in cfg.validate())
    with pytest.raises(ValueError, match='Unknown CRS profile'):
        ModSecurityEngine(cfg)


def test_acceptance_reports_macro_separately_from_request_weighted_recall():
    from benchmarks.scripts.bench_waf_acceptance import summarize
    rows = [{'label': 'attack', 'category': 'large', 'blocked': True}] * 9
    rows += [{'label': 'attack', 'category': 'small', 'blocked': False},
             {'label': 'benign', 'category': 'benign', 'blocked': False}]
    result = summarize(rows)
    assert result['recall'] == .9 and result['category_macro_recall'] == .5
    assert result['meets_micro_gate'] and not result['meets_macro_gate']


def test_acceptance_ten_percent_false_positives_is_a_failure():
    from benchmarks.scripts.bench_waf_acceptance import summarize
    rows = [{'label': 'attack', 'category': 'sample', 'blocked': True}]
    rows += [{'label': 'benign', 'category': 'benign', 'blocked': False}] * 9
    rows += [{'label': 'benign', 'category': 'benign', 'blocked': True}]
    result = summarize(rows)
    assert result['false_positive_rate'] == .1 and not result['meets_micro_gate']


def test_acceptance_cannot_pass_without_positive_and_benign_denominators():
    from benchmarks.scripts.bench_waf_acceptance import summarize
    with pytest.raises(ValueError, match='both positive and benign'):
        summarize([{'label': 'attack', 'category': 'sample', 'blocked': True}])


def test_csic_records_preserve_body_and_strip_only_record_separators():
    from benchmarks.scripts.bench_csic_benign import records
    first = b'POST http://fixture.invalid/note HTTP/1.1\r\nHost: fixture.invalid\r\nContent-Length: 7\r\n\r\nnote=ok'
    second = b'GET http://fixture.invalid/ HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n'
    rows = records(first + b'\r\n\r\n' + second + b'\r\n')
    assert [r[2] for r in rows] == [first, second]


def test_csic_records_reject_ambiguous_or_incomplete_framing():
    from benchmarks.scripts.bench_csic_benign import records
    with pytest.raises(ValueError, match='Body size'):
        records(b'POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort')


def test_tui_can_load_balanced_profile_without_starting_services(monkeypatch):
    from sentinel.__main__ import main
    import sentinel.tui
    seen = []
    monkeypatch.setattr(sentinel.tui, 'run', lambda config, **kwargs: seen.append((config, kwargs)))
    assert main(['tui', '--config', 'examples/waf-balanced.toml', '--engine', 'modsecurity']) == 0
    assert seen[0][0].waf.crs_profile == 'balanced' and seen[0][0].waf.paranoia_level == 4
    assert seen[0][1]['engine'] == 'modsecurity'


def test_missing_cli_config_cannot_silently_start_standard_profile():
    from sentinel.__main__ import main
    with pytest.raises(SystemExit) as error:
        main(['tui', '--config', '/missing/sentinel-profile.toml'])
    assert error.value.code == 2
