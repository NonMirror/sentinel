"""Check fixture admission, expectations and fail-closed provenance checks."""
import shutil

import pytest

from benchmarks.scripts.bench_naxsi_fixtures import run, sections
from sentinel.vendor import naxsi_core_rules


def test_sections_keep_inline_expectations_and_eval_labels():
    parsed = sections('--- request eval\n"GET /"\n--- error_code: 412\n')
    assert parsed == {"request eval": '"GET /"', "error_code": "412"}


def test_static_adapter_preserves_deny_allow_and_unsupported_cases(tmp_path):
    (tmp_path / "t").mkdir()
    (tmp_path / "naxsi_config").mkdir()
    shutil.copyfile(naxsi_core_rules(), tmp_path / "naxsi_config/naxsi_core.rules")
    template = '''
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:sentinelmarker" "mz:ARGS" "s:$SQL:8" id:499999;
--- config
location / {
 SecRulesEnabled;
 DeniedUrl "/RequestDenied";
 CheckRule "$SQL >= 8" BLOCK;
}
location /RequestDenied {
 return 412;
}
'''
    (tmp_path / "t/sample.t").write_text(
        '=== allow\n' + template + '--- request\nGET /?note=ordinary\n--- error_code: 200\n'
        + '=== deny\n' + template + '--- request\nGET /?note=sentinelmarker\n--- error_code: 412\n'
        + '=== dynamic\n' + template + '--- request eval\ndie "must not execute";\n--- error_code: 412\n')
    # Stub only revision metadata; fixture parsing and WAF evaluation remain real.
    from unittest.mock import patch
    with patch("benchmarks.scripts.bench_naxsi_fixtures.subprocess.check_output", return_value="fixture-revision\n"):
        result = run(tmp_path)
    assert result["totals"]["total"] == 3
    assert result["totals"]["passed"] == 2
    assert result["totals"]["skipped"] == 1
    assert result["skipped"][0]["reason"] == "dynamic-perl-or-raw-request"


def test_rule_revision_mismatch_is_not_silently_compared(tmp_path):
    (tmp_path / "t").mkdir()
    (tmp_path / "t/sample.t").write_text("=== case\n")
    (tmp_path / "naxsi_config").mkdir()
    (tmp_path / "naxsi_config/naxsi_core.rules").write_text("")
    with pytest.raises(ValueError, match="differ"):
        run(tmp_path)
