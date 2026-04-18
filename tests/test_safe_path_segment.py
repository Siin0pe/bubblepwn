"""Regression tests for the es-audit dumpone / sqlite path-traversal fix.

Without a hard sanitiser on ``raw_type``, the legacy ``str.replace('/', '_')``
call let ``..`` characters through, so ``run es-audit dumpone ../../../tmp/x``
would write outside ``out/``. These tests lock the sanitiser down.
"""
import pytest

from bubblepwn.modules.es_audit import _safe_path_segment


@pytest.mark.parametrize(
    "value,expected",
    [
        ("user", "user"),
        ("custom.user", "custom.user"),
        ("custom.some_type-v2", "custom.some_type-v2"),
        ("option.my_enum", "option.my_enum"),
    ],
)
def test_accepts_legitimate_type_names(value, expected):
    assert _safe_path_segment(value) == expected


def test_replaces_unsafe_chars_without_escaping_the_directory():
    # Slashes / colons / backslashes are flattened into ``_`` — the resulting
    # string is a plain filename so ``Path(dir) / result`` cannot escape ``dir``.
    assert _safe_path_segment("custom/foo:bar") == "custom_foo_bar"
    assert _safe_path_segment("a\\b:c/d") == "a_b_c_d"
    # Absolute paths are neutralised — leading slash becomes underscore.
    assert _safe_path_segment("/etc/passwd") == "_etc_passwd"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        ".",
        "..",
        ".hidden",
        "./relative",
        "___",
        "../../../etc/passwd",
    ],
)
def test_rejects_traversal_attempts(bad):
    with pytest.raises(ValueError):
        _safe_path_segment(bad)
