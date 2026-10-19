"""Referrer header grammar and public fixture adapter, without active requests."""
import pytest

from benchmarks.scripts.bench_chromium_headers import load_cases
from sentinel.core.models import Severity
from sentinel.scanner.client import HttpResult
from sentinel.scanner.headers import inspect_security_headers, parse_referrer_policy


@pytest.mark.parametrize("value,expected", [
    ("origin", "origin"), ("STRICT-ORIGIN", "strict-origin"),
    ("no-referrer, future-policy", "no-referrer"),
    ("future-policy, no-referrer", "no-referrer"),
    ("no-referrer, unsafe-url", "unsafe-url"),
    ("unsafe-url, no-referrer", "no-referrer"),
    (" ,\t no-referrer ,, ", "no-referrer"),
    ("none", ""), ("", ""), ("future-policy", ""),
])
def test_policy_selection_and_legacy_exclusion(value, expected):
    assert parse_referrer_policy(value) == expected


@pytest.mark.parametrize("invalid", ["origin no-referrer", '"no-referrer"', "future_policy",
                                     "future2", "no-referrer;mode=on", "no-referrer\v",
                                     "no-referrer\f", "no-referrer\u00a0"])
@pytest.mark.parametrize("before", [True, False])
def test_invalid_grammar_invalidates_the_whole_list(invalid, before):
    values = [invalid, "no-referrer"] if before else ["no-referrer", invalid]
    assert parse_referrer_policy(", ".join(values)) == ""
    response = HttpResult(url="https://fixture.invalid/", method="GET", status=200,
                          header_items=[("X-Content-Type-Options", "nosniff"),
                                        ("Referrer-Policy", values[0]), ("referrer-policy", values[1])])
    findings = inspect_security_headers(response)
    assert len(findings) == 1 and findings[0].param == "Referrer-Policy"
    assert findings[0].severity is Severity.INFO and "无效" in findings[0].proof


def fixture(root):
    text = '''TEST(SecurityPolicyTest, ReferrerPolicyFromHeaderValue) {
  TestCase inputs[] = {
    {"origin", true, kDoNotSupportReferrerPolicyLegacyKeywords, network::mojom::ReferrerPolicy::kOrigin},
    {"none", true, kSupportReferrerPolicyLegacyKeywords, network::mojom::ReferrerPolicy::kNever},
    {"origin, foo bar", false, kDoNotSupportReferrerPolicyLegacyKeywords, network::mojom::ReferrerPolicy::kDefault},
  };
  EXPECT_EQ(test.is_valid, SecurityPolicy::ReferrerPolicyFromHeaderValue(test.header, test.keywords, &actual_policy));
  if (test.is_valid) EXPECT_EQ(test.expected_policy, actual_policy);
}
TEST(SecurityPolicyTest, ReferrerPolicyToAndFromString) {
  const char* policies[] = {"no-referrer", "unsafe-url"};
  EXPECT_TRUE(SecurityPolicy::ReferrerPolicyFromString(policy, kDoNotSupportReferrerPolicyLegacyKeywords, &result));
  EXPECT_EQ(string_result, policy);
}
'''
    (root / "security_policy_test.cc").write_text(text)
    return text


def test_adapter_preserves_native_assertions_and_unsupported_legacy_case(tmp_path):
    fixture(tmp_path)
    cases, skipped = load_cases(tmp_path)
    assert len(cases) == 4 and len(skipped) == 1
    assert cases[1]["input"] == "origin, foo bar" and cases[1]["expected_valid"] is False
    assert skipped[0]["input"] == "none" and skipped[0]["expected_valid"] is True
    assert cases[-1]["expected_policy"] == "unsafe-url"


@pytest.mark.parametrize("old,new", [
    ('"origin", true', 'make_policy(), true'),
    ('EXPECT_EQ(test.expected_policy, actual_policy);', 'EXPECT_NE(test.expected_policy, actual_policy);'),
    ('kOrigin}', 'kUnknownEnum}'),
    ('"no-referrer", "unsafe-url"', '"no-referrer", make_policy()'),
])
def test_adapter_fails_on_unadapted_source(tmp_path, old, new):
    text = fixture(tmp_path)
    assert old in text
    (tmp_path / "security_policy_test.cc").write_text(text.replace(old, new))
    with pytest.raises(ValueError, match="Unadapted"):
        load_cases(tmp_path)
