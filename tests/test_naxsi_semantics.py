"""Naxsi rule semantics using inert markers, without network requests."""
import pytest

from sentinel.waf.naxsi.engine import NativeNaxsiEngine
from sentinel.waf.naxsi.syntax import NaxsiRuleSet, parse_main_rule, parse_check_rule
from tests.test_naxsi import request


def engine(rule, check='CheckRule "$TEST >= 8" BLOCK;', **kwargs):
    rules = [parse_main_rule(rule)]
    checks = [parse_check_rule(check)]
    assert all(rules) and all(checks)
    return NativeNaxsiEngine(NaxsiRuleSet(rules=rules, checks=checks), **kwargs)


@pytest.mark.parametrize("pattern,value,count", [
    ('str:aba', 'ababa', 2), ('str:mark', 'MARK mark mark', 3),
    ('rx:mark|note', 'mark note mark', 3),
    ('rx:(mark)', 'mark mark', 4),
    ('rx:(mark)|(note)', 'mark note', 5),
    (r'rx:\d+', '12 34', 2), (r'rx:\.', 'one.two.three', 2),
])
def test_counts_occurrences_and_preserves_regex_escapes(pattern, value, count):
    from urllib.parse import urlencode
    waf = engine(f'MainRule "{pattern}" "mz:ARGS" "s:$TEST:4" id:1;')
    verdict = waf.inspect(request('/?' + urlencode({'q': value})))
    assert verdict.scores == {"TEST": count * 4}
    assert verdict.blocked
    assert len(verdict.hits) == 1 and verdict.hits[0].points == count * 4


@pytest.mark.parametrize("operator,score,blocked", [
    ('>', 8, False), ('>', 9, True), ('>=', 8, True), ('>=', 7, False),
    ('<', 8, False), ('<', 7, True), ('<=', 8, True), ('<=', 9, False),
    ('==', 8, True), ('==', 9, False), ('=', 8, True),
])
def test_comparison_boundaries(operator, score, blocked):
    waf = engine(f'MainRule "str:mark" "mz:ARGS" "s:$TEST:{score}" id:1;',
                 f'CheckRule "$TEST {operator} 8" BLOCK;', paranoia_level=4)
    result = waf.inspect(request('/?q=mark'))
    assert result.blocked is blocked
    assert bool(result.breached) is blocked
    assert result.thresholds == {"TEST": 8}
    # Missing score tags are not implicit zeroes for a < check.
    assert not waf.inspect(request('/?q=ordinary')).blocked


@pytest.mark.parametrize("zone,good,bad", [
    ('$ARGS_VAR:chosen', '/?chosen=mark', '/?other=mark'),
    ('$ARGS_VAR:chosen', '/?CHOSEN=mark', '/?chosen_suffix=mark'),
    ('$ARGS_VAR_X:^chosen[0-9]+$', '/?chosen2=mark', '/?chosenX=mark'),
    (r'$ARGS_VAR_X:^chosen\d+$', '/?chosen2=mark', '/?chosenX=mark'),
    ('$ARGS_VAR:chosen|$URL:/only', '/only?chosen=mark', '/else?chosen=mark'),
    ('$URL_X:^/only/[0-9]+$|$ARGS_VAR:chosen', '/only/2?chosen=mark', '/only/no?chosen=mark'),
])
def test_named_and_url_constrained_fields(zone, good, bad):
    waf = engine(f'MainRule "str:mark" "mz:{zone}" "s:$TEST:8" id:1;')
    assert waf.inspect(request(good)).blocked
    assert not waf.inspect(request(bad)).blocked


def test_query_and_body_selectors_are_separate_and_keep_duplicates():
    waf = engine('MainRule "str:mark" "mz:$BODY_VAR:chosen" "s:$TEST:4" id:1;')
    assert not waf.inspect(request('/?chosen=mark&chosen=mark')).blocked
    result = waf.inspect(request('/', body=b'chosen=mark&chosen=mark',
                                 ctype='application/x-www-form-urlencoded'))
    assert result.scores == {"TEST": 8} and result.blocked


def test_multipart_keeps_field_values_and_upload_names_in_their_zones():
    from tests.test_waf_multipart import multipart
    body = multipart(b'Content-Disposition: form-data; name="chosen"\r\n\r\nmark',
                     b'Content-Disposition: form-data; name="chosen"\r\n\r\nmark',
                     b'Content-Disposition: form-data; name="document"; filename="note.txt"\r\n\r\nfile bytes')
    req = request(body=body, ctype="multipart/form-data; boundary=sample-boundary")
    fields = NativeNaxsiEngine._fields(req)
    assert fields["BODY"] == [("chosen", "mark"), ("chosen", "mark")]
    assert fields["FILE_EXT"] == [("document", "note.txt")]
    waf = engine('MainRule "str:mark" "mz:$BODY_VAR:chosen" "s:$TEST:4" id:1;')
    assert waf.inspect(req).scores == {"TEST": 8}
    waf = engine('MainRule "str:note.txt" "mz:FILE_EXT" "s:$TEST:8" id:1;')
    assert waf.inspect(req).blocked
    waf = engine('MainRule "str:content-disposition" "mz:BODY" "s:$TEST:8" id:1;')
    assert not waf.inspect(req).blocked
    broken = request(body=b'ordinary-marker', ctype="multipart/form-data; boundary=sample-boundary")
    assert NativeNaxsiEngine._fields(broken)["BODY"] == [(None, "ordinary-marker")]


def test_header_selectors_are_case_insensitive_and_not_limited_to_cookie():
    waf = engine('MainRule "str:mark" "mz:$HEADERS_VAR:X-Label" "s:$TEST:8" id:1;')
    assert waf.inspect(request(headers={'x-label': 'mark'})).blocked
    assert not waf.inspect(request(headers={'X-Other': 'mark'})).blocked


def test_name_target_does_not_inspect_values():
    waf = engine('MainRule "str:mark" "mz:ARGS|NAME" "s:$TEST:8" id:1;')
    assert waf.inspect(request('/?mark=ordinary')).blocked
    assert not waf.inspect(request('/?ordinary=mark')).blocked


@pytest.mark.parametrize("pattern", ['str:mark', 'rx:^mark$'])
def test_negative_only_checks_selected_existing_values(pattern):
    waf = engine(f'MainRule negative "{pattern}" "mz:$ARGS_VAR:chosen" "s:$TEST:8" id:1;')
    assert not waf.inspect(request('/?chosen=mark')).blocked
    assert waf.inspect(request('/?chosen=ordinary')).blocked
    assert waf.inspect(request('/?chosen=')).blocked
    assert not waf.inspect(request('/?other=ordinary')).blocked


def test_negative_word_in_message_does_not_change_polarity():
    waf = engine('MainRule "str:mark" "msg:negative example" "mz:ARGS" "s:$TEST:8" id:1;')
    assert waf.inspect(request('/?q=mark')).blocked
    assert not waf.inspect(request('/?q=ordinary')).blocked


@pytest.mark.parametrize("action,blocked", [('BLOCK', True), ('DROP', True), ('ALLOW', False), ('LOG', False)])
def test_direct_actions_without_score(action, blocked):
    rule = f'MainRule "str:mark" "mz:ARGS" "s:{action}" id:1;'
    result = engine(rule).inspect(request('/?q=mark'))
    assert result.blocked is blocked
    assert result.scores == {} and result.hits
    assert not engine(rule, mode='detect').inspect(request('/?q=mark')).blocked
    assert not engine(rule, mode='off').inspect(request('/?q=mark')).hits


@pytest.mark.parametrize("action,blocked", [('BLOCK', True), ('DROP', True), ('ALLOW', False), ('LOG', False)])
def test_check_action_is_not_always_block(action, blocked):
    waf = engine('MainRule "str:mark" "mz:ARGS" "s:$TEST:8" id:1;',
                 f'CheckRule "$TEST >= 8" {action};')
    assert waf.inspect(request('/?q=mark')).blocked is blocked


def test_invalid_regex_selector_never_expands_to_all_arguments():
    waf = engine('MainRule "str:mark" "mz:$ARGS_VAR_X:[" "s:$TEST:8" id:1;')
    assert not waf.inspect(request('/?q=mark')).blocked


@pytest.mark.parametrize("pattern", ['^', '$', '.*'])
def test_zero_width_regex_is_bounded(pattern):
    waf = engine(f'MainRule "rx:{pattern}" "mz:$ARGS_VAR:q" "s:$TEST:4" id:1;')
    result = waf.inspect(request('/?q=ordinary'))
    assert result.scores == {"TEST": 8}  # one name and one value match


def test_upper_bound_check_runs_before_later_fields_increase_score():
    waf = engine('MainRule "str:mark" "mz:ARGS" "s:$TEST:8" id:1;',
                 'CheckRule "$TEST <= 8" BLOCK;')
    result = waf.inspect(request('/?a=mark&b=mark'))
    assert result.blocked and result.breached == {"TEST": 8}


@pytest.mark.parametrize("first,last,blocked", [
    ('BLOCK', 'LOG', False), ('BLOCK', 'ALLOW', False),
    ('ALLOW', 'BLOCK', True), ('DROP', 'ALLOW', True),
])
def test_check_actions_are_applied_in_order_within_update(first, last, blocked):
    waf = engine('MainRule "str:mark" "mz:ARGS" "s:$TEST:8" id:1;',
                 f'CheckRule "$TEST >= 8" {first};')
    waf.ruleset.checks.append(parse_check_rule(f'CheckRule "$TEST >= 8" {last};'))
    assert waf.inspect(request('/?q=mark')).blocked is blocked


@pytest.mark.parametrize("rule", [
    'MainRule id:1 "str:mark" "mz:ARGS" s:BLOCK;',
    "MainRule id:1 'str:mark' 'mz:ARGS' s:BLOCK;",
    'MainRule id:1 str:mark mz:ARGS s:BLOCK;',
])
def test_unquoted_action_and_single_quoted_fields(rule):
    assert engine(rule).inspect(request('/?q=mark')).blocked


@pytest.mark.parametrize("target", ['/?q=%00', '/?q=%zz', '/?q=%2', '/?q=%', '/ordinary%00'])
def test_invalid_transport_encodings_produce_internal_signal(target):
    rule = 'MainRule "str:mark" "mz:ARGS" "s:$TEST:8" id:1;'
    result = engine(rule).inspect(request(target))
    assert result.blocked and result.matched_rules() == [10]
    assert result.scores == {}
    assert not engine(rule, mode='detect').inspect(request(target)).blocked
    assert not engine(rule, mode='off').inspect(request(target)).hits


def test_encoding_validation_respects_body_media_type_and_single_decode():
    waf = engine('MainRule "str:mark" "mz:ARGS" "s:$TEST:8" id:1;')
    assert waf.inspect(request(body=b'q=%zz', ctype='application/x-www-form-urlencoded')).blocked
    assert not waf.inspect(request(body=b'q=%zz', ctype='text/plain')).blocked
    assert not waf.inspect(request(body=b'{"q":"%zz"}', ctype='application/json')).blocked
    assert not waf.inspect(request('/?q=%2500&rate=100%25')).blocked
    assert not waf.inspect(request(headers={'Cookie': 'percent=%zz'})).blocked
    assert waf.inspect(request(headers={'X-Label': 'ordinary\x00'})).blocked


def test_driver_export_preserves_policy_across_two_round_trips(tmp_path):
    from sentinel.core.config import Config
    from sentinel.waf.engines.naxsi import NaxsiEngine

    source = tmp_path / "original.rules"
    source.write_text(r'''MainRule negative "str:plain" "msg:quoted \"note\"" "mz:$ARGS_VAR:chosen|$URL:/only" "s:$TEST:8" id:1;
MainRule "rx:^marker\d+$" "mz:$ARGS_VAR_X:^field\d+$" s:DROP id:2;
CheckRule "$TEST > 8" BLOCK;
CheckRule "$TEST <= 8" LOG;
''' + 'MainRule "str:' + ('ordinary' * 30) + '" "mz:BODY" "s:$TEST:4" id:3;\n')
    config = Config()
    config.waf.paranoia_level = 4
    driver = NaxsiEngine(config, rules_path=source)
    targets = ['/?field2=marker42', '/only?chosen=plain', '/only?chosen=other',
               '/only?chosen=other&chosen=other', '/else?chosen=other']
    expected = [True, False, False, True, False]
    assert [driver.inspect(request(t)).blocked for t in targets] == expected
    for index in range(2):
        destination = tmp_path / f"export-{index}.rules"
        assert driver.export_rules(destination) == 3
        assert '$ARGS_VAR_X:' in destination.read_text()
        driver = NaxsiEngine(config, rules_path=destination)
        assert driver.engine.ruleset.rules[0].message == 'quoted "note"'
        assert driver.engine.ruleset.rules[1].pattern == r'^marker\d+$'
        assert driver.engine.ruleset.rules[2].pattern == 'ordinary' * 30
        assert [(c.operator, c.action) for c in driver.engine.ruleset.checks] == [('>', 'BLOCK'), ('<=', 'LOG')]
        assert [driver.inspect(request(t)).blocked for t in targets] == expected
        assert [r.action for r in driver.rule_index()] == ['score', 'drop', 'score']


def test_driver_preserves_scoreless_internal_rejection():
    from sentinel.core.config import Config
    from sentinel.waf.engines.naxsi import NaxsiEngine

    decision = NaxsiEngine(Config()).inspect(request('/?q=%zz'))
    assert decision.blocked and 10 in decision.matched_rules
    assert decision.anomaly_score == 0


def test_exported_fallback_thresholds_are_not_tightened_twice(tmp_path):
    from sentinel.core.config import Config
    from sentinel.waf.engines.naxsi import NaxsiEngine

    config = Config()
    config.waf.paranoia_level = 4
    driver = NaxsiEngine(config)
    destination = tmp_path / 'core.rules'
    driver.export_rules(destination)
    restored = NaxsiEngine(config, rules_path=destination)
    assert restored.engine.thresholds == driver.engine.thresholds
