"""Unit tests for every Sigma value modifier (pure predicates)."""

from __future__ import annotations

import base64
import re
from collections.abc import Callable

import pytest

from bastion.sigma.modifiers import (
    base64offset_candidates,
    encode_base64,
    match_cidr,
    match_compare,
    match_contains,
    match_endswith,
    match_equals,
    match_exists,
    match_re,
    match_startswith,
    wildcard_to_regex,
    windash_variants,
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

    def test_wildcards_inside_contains(self) -> None:
        # SigmaHQ regression case "Recon Command Output Piped To Findstr.EXE".
        assert match_contains("cmd /c tasklist /v | findstr /i lsass", "tasklist*|*find")
        assert not match_contains("cmd /c tasklist /v", "tasklist*|*find")
        # "File And SubFolder Enumeration Via Dir Command": 'dir*-s'
        assert match_contains("cmd.exe /c dir C:\\Users -s", "dir*-s")
        assert match_contains("abc", "a?c") and not match_contains("ac", "a?c")

    def test_wildcards_inside_startswith_and_endswith(self) -> None:
        assert match_startswith("/home/bob/public_html/x.php", "/home/*/public_html/")
        assert not match_startswith("/srv/home/bob/public_html/", "/home/*/public_html/")
        assert match_endswith("0x13", "1?") and not match_endswith("0x131", "1?")

    def test_escapes_inside_substring_modifiers(self) -> None:
        # "Potential NTLM Coercion Via Certutil.EXE": ' \\\\' in YAML is four backslashes in
        # the rule, which Sigma reads as two literal backslashes (a UNC prefix).
        rule_value = " " + "\\" * 4
        assert match_contains("certutil -syncwithWU \\\\192.0.2.1\\share", rule_value)
        assert not match_contains("certutil -syncwithWU \\192.0.2.1", rule_value)
        assert match_startswith("\\\\127.0.0.1\\ADMIN$\\x", "\\\\\\\\127.0.0.1\\\\ADMIN$\\")
        # An escaped wildcard is literal.
        assert match_contains("a*b", "a\\*b") and not match_contains("axb", "a\\*b")

    def test_plain_values_keep_their_literal_meaning(self) -> None:
        # A single backslash before an ordinary character is plain: Windows paths need no doubling.
        assert match_contains(r"C:\Windows\System32\x.exe", r"\system32\x.exe")
        assert match_endswith(r"C:\Tools\PsExec.exe", r"\psexec.exe")

    def test_wildcard_crosses_line_breaks_and_respects_cased(self) -> None:
        assert match_contains("tasklist\n| findstr", "tasklist*find")
        assert match_contains("TaskList | Find", "tasklist*find")
        assert not match_contains("TaskList | Find", "tasklist*find", cased=True)
        assert match_equals("a\nb", "a*b")

    def test_lone_star_in_contains_matches_any_present_value(self) -> None:
        assert match_contains("", "*") and match_contains("x", "*")
        assert not match_contains(None, "*")

    @pytest.mark.parametrize("predicate", [match_contains, match_startswith, match_endswith])
    def test_none_never_matches(self, predicate: Callable[[str | None, str | None], bool]) -> None:
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


class TestCasedVariants:
    def test_equals_cased(self) -> None:
        assert match_equals("PowerShell", "PowerShell", cased=True)
        assert not match_equals("powershell", "PowerShell", cased=True)

    def test_contains_startswith_endswith_cased(self) -> None:
        assert match_contains("abcDEF", "cDE", cased=True)
        assert not match_contains("abcdef", "cDE", cased=True)
        assert match_startswith("Mimikatz", "Mimi", cased=True)
        assert not match_startswith("mimikatz", "Mimi", cased=True)
        assert match_endswith("a.DLL", ".DLL", cased=True)
        assert not match_endswith("a.dll", ".DLL", cased=True)

    def test_wildcard_equals_cased(self) -> None:
        assert match_equals("run-EVIL.exe", "run-*.exe", cased=True)
        assert not match_equals("run-EVIL.EXE", "run-*.exe", cased=True)


class TestCidr:
    def test_v4_inside_and_outside(self) -> None:
        assert match_cidr("192.168.1.77", "192.168.0.0/16")
        assert not match_cidr("10.0.0.1", "192.168.0.0/16")

    def test_v6(self) -> None:
        assert match_cidr("fe80::1", "fe80::/10")

    def test_garbage_never_matches(self) -> None:
        assert not match_cidr("not-an-ip", "10.0.0.0/8")
        assert not match_cidr("10.0.0.1", "not-a-range")
        assert not match_cidr(None, "10.0.0.0/8")


class TestExistsAndCompare:
    def test_exists(self) -> None:
        assert match_exists("anything", True)
        assert match_exists(None, False)
        assert not match_exists(None, True)
        assert not match_exists("anything", False)

    def test_compare_ops(self) -> None:
        assert match_compare(4624, 4000, "gt")
        assert match_compare(4624, 4624, "gte")
        assert match_compare("80", 443, "lt")
        assert match_compare(443, 443, "lte")
        assert not match_compare(443, 443, "gt")

    def test_compare_non_numeric_never_matches(self) -> None:
        assert not match_compare("abc", 1, "gt")
        assert not match_compare(None, 1, "lt")


class TestTransforms:
    def test_windash_variants(self) -> None:
        assert " /enc " in windash_variants(" -enc ")
        assert " -enc " in windash_variants(" /enc ")

    def test_encode_base64(self) -> None:
        assert encode_base64(b"http://") == base64.b64encode(b"http://").decode()

    @pytest.mark.parametrize("prefix", [b"", b"a", b"ab"])
    def test_base64offset_covers_every_alignment(self, prefix: bytes) -> None:
        value = b"IEX (New-Object"
        stream = base64.b64encode(prefix + value + b"suffix").decode()
        assert any(candidate in stream for candidate in base64offset_candidates(value))


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
