"""Byte-range optimization must preserve every byte and existing edge semantics."""
import pytest

from sentinel.waf.secrule.operators import _validate_byte_range, evaluate
from sentinel.waf.secrule.syntax import Operator


@pytest.mark.parametrize("spec,allowed", [
    ("0-255", set(range(256))),
    ("0", {0}), ("255", {255}), ("97-122", set(range(97, 123))),
    ("0, 10, 13, 32, 127-255", {0, 10, 13, 32, *range(127, 256)}),
    ("38,44-46,48-58,61,65-90,95,97-122", {38, *range(44, 47), *range(48, 59), 61,
                                            *range(65, 91), 95, *range(97, 123)}),
    ("65-90,80-110,65", set(range(65, 111))),
    ("0-999999999999999999999999", set(range(256))),
    ("256-999999999999999999999999", set()),
    ("", set()), ("xxx", set()), ("90-65", set()),
    ("bad,97,", {97}), ("-1,97-", {97}),
])
def test_all_bytes_empty_and_combined_values(spec, allowed):
    # Preserve even historical malformed-spec behavior; configuration validation is separate.
    assert _validate_byte_range("", spec)
    for byte in range(256):
        assert _validate_byte_range(chr(byte), spec) == (byte in allowed)
    value = bytes(sorted(allowed)).decode("latin-1")
    assert _validate_byte_range(value, spec)
    for byte in set(range(256)) - allowed:
        assert not _validate_byte_range(value + chr(byte), spec)
        assert not _validate_byte_range(chr(byte) + value, spec)


@pytest.mark.parametrize("value,spec,expected", [("书", "63", True), ("书", "97", False),
                                                ("é", "233", True), ("é", "63", False)])
def test_existing_latin1_replacement_contract_is_preserved(value, spec, expected):
    assert _validate_byte_range(value, spec) is expected


@pytest.mark.parametrize("position", [0, 65536, 131071])
def test_long_ordinary_text_and_one_disallowed_space(position):
    value = "a" * 131072
    assert _validate_byte_range(value, "97-122")
    value = value[:position] + " " + value[position + 1:]
    assert not _validate_byte_range(value, "97-122")


def test_operator_match_polarity_and_negation_are_preserved():
    operator = Operator(name="validatebyterange", argument="97-122")
    assert not evaluate(operator, "ordinary")
    assert evaluate(operator, "ordinary text")
    operator.negated = True
    assert evaluate(operator, "ordinary")
    assert not evaluate(operator, "ordinary text")
