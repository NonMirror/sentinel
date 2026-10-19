"""Preserve regex results while bounding redundant leading-run retries."""
import itertools
import re
import subprocess
import sys

import pytest

from sentinel.waf.secrule.operators import compile_pattern


@pytest.mark.parametrize("pattern", [r"(?i)[ab]+b", r"[ab]+(?P<label>!?)[ab]*c",
                                    r"[^!]+!(a|b)", r"[ab]+(?:a|!b)",
                                    r"[ab]+(?<!aa)b", r"[ab]+(?=b)b", r"[ab]+?b", r"[ab]++b",
                                    r"(a!|b!)[ab]+!|[ab]+!", r"\|[ab]+!|[ab]+!",
                                    r"[]|]+!|[ab]+!", r"[ab]+!|[^]|]+!",
                                    r"(?x)[ab]+ ! # comment | ordinary", r"(?#ordinary|comment)[ab]+!"])
def test_optimization_preserves_leftmost_span_and_captures(pattern):
    original, optimized = re.compile(pattern), compile_pattern(pattern)
    for size in range(7):
        for letters in itertools.product("ab!", repeat=size):
            value = "".join(letters)
            left, right = original.search(value), optimized.search(value)
            assert (None if left is None else (left.span(), left.groups())) == (
                None if right is None else (right.span(), right.groups()))


def test_long_ordinary_run_finishes_within_bounded_worker_time():
    # A subprocess timeout prevents an accidentally restored quadratic search
    # from hanging the test runner. The input contains only ordinary letters.
    subprocess.run([sys.executable, "-c",
                    'from sentinel.waf.secrule.operators import compile_pattern; '
                    'assert compile_pattern(r"(?i)[a-z]+[!]").search("a" * 100000) is None; '
                    'assert compile_pattern(r"![a-z]+!|[a-z]+[!]").search("a" * 100000) is None'],
                   check=True, timeout=3, capture_output=True)
