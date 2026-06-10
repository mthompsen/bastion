"""Unit tests for every Sigma value modifier (pure predicates)."""

from __future__ import annotations

import re
from collections.abc import Callable

import pytest

from bastion.sigma.modifiers import (
    match_contains,
    match_endswith,
    match_equals,
    match_re,
    match_startswith,
    wildcard_to_regex,
)


class TestEquals:
    def test_case_insensitive(self) -> None:
        assert match_equals("PowerShell.EXE", "powershell.exe")

    def test_no_match(self) -> None:
        assert not match_equals("cmd.exe", "powershell.exe")

    def test_int_vs_string(self) -> None:
        assert match_equals(1, "1")
        assert match_equals("4624", 4624)

    def test_bool_rule_value(self) -> None:
        assert match_equals("true", True)
        assert not match_equals("false", True)

    def test_null_matches_absent_field(self) -> None:
        assert match_equals(None, None)
        assert not match_equals("something", None)
        assert not match_equals(None, "something")

    def test_wildcard_star(self) -> None:
        assert match_equals(r"C:\Windows\System32\cmd.exe", "C:*cmd.exe")
        assert not match_equals(r"C:\Temp\evil.exe", "C:*cmd.exe")
        # Note: per Sigma escaping, a backslash directly before * escapes it —
        # "C:\Windows\*" means a literal asterisk (see the escaped tests below).

    def test_wildcard_question_mark(self) -> None:
        assert match_equals("run1.exe", "run?.exe")
        assert not match_equals("run12.exe", "run?.exe")

    def test_wildcard_is_case_insensitive(self) -> None:
        assert match_equals("POWERSHELL -ENC ABC", "*-enc*")

    def test_escaped_wildcard_is_literal(self) -> None:
        assert match_equals("literal*star", r"literal\*star")
        assert not match_equals("literalXstar", r"literal\*star")

    def test_escaped_backslash_then_wildcard(self) -> None:
        # \\* = a literal backslash followed by a real wildcard.
        assert match_equals(r"share\anything", r"share\\*")

    def test_plain_backslash_is_literal(self) -> None:
        # A backslash not followed by a wildcard or backslash is plain.
        assert match_equals(r"C:\Windows", r"C:\Windows")


class TestSubstringModifiers:
    def test_contains_case_insensitive(self) -> None:
        assert match_contains("powershell -EncodedCommand SQBFAFgA", " -encodedcommand ")
        assert not match_contains("powershell -Command foo", "-enc ")

    def test_startswith(self) -> None:
        assert match_startswith(r"C:\Windows\System32\cmd.exe", "c:\\windows\\")
        assert not match_startswith(r"D:\cmd.exe", "c:\\windows\\")

    def test_endswith(self) -> None:
        assert match_endswith(r"C:\Tools\PsExec.exe", r"\psexec.exe")
        assert not match_endswith(r"C:\Tools\PsExec64.exe", r"\psexec.exe")

    def test_int_field_values_are_stringified(self) -> None:
        assert match_contains(4624, "62")
        assert match_startswith(4624, "46")
        assert match_endswith(4624, "24")

    @pytest.mark.parametrize("predicate", [match_contains, match_startswith, match_endswith])
    def test_none_never_matches(
        self, predicate: Callable[[str | None, str | None], bool]
    ) -> None:
        assert not predicate(None, "x")
        assert not predicate("x", None)


class TestRegex:
    def test_search_semantics(self) -> None:
        assert match_re("powershell -enc SQBFAFgA", r"-enc\s+[A-Za-z0-9+/=]+")

    def test_case_sensitive_per_spec(self) -> None:
        assert match_re("PowerShell", r"PowerShell")
        assert not match_re("powershell", r"PowerShell")

    def test_invalid_pattern_raises(self) -> None:
        with pytest.raises(re.error):
            match_re("value", "(unclosed")

    def test_none_never_matches(self) -> None:
        assert not match_re(None, "x")
        assert not match_re("x", None)


class TestWildcardToRegex:
    @pytest.mark.parametrize(
        ("pattern", "expected_match", "expected_miss"),
        [
            ("a*b", "aXXXb", "aXXXc"),
            ("a?b", "aXb", "aXXb"),
            (r"a\*b", "a*b", "aXb"),
            (r"a\\b", r"a\b", "ab"),
        ],
    )
    def test_translation(self, pattern: str, expected_match: str, expected_miss: str) -> None:
        regex = wildcard_to_regex(pattern)
        assert re.fullmatch(regex, expected_match)
        assert not re.fullmatch(regex, expected_miss)

    def test_regex_metacharacters_are_escaped(self) -> None:
        regex = wildcard_to_regex("a.b+c")
        assert re.fullmatch(regex, "a.b+c")
        assert not re.fullmatch(regex, "aXb+c")
