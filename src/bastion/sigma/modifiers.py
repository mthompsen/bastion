"""Sigma value modifiers as pure predicate functions.

Each function answers "does this event field value satisfy this rule
value?" for one modifier. Per the Sigma specification:

* base equality is case-insensitive and honours wildcards in the rule
  value (``*`` matches any run of characters, ``?`` any single character;
  ``\\*`` / ``\\?`` escape a literal wildcard and ``\\\\`` a literal
  backslash, while any other backslash is plain, so Windows paths need no
  doubling);
* ``contains`` / ``startswith`` / ``endswith`` are case-insensitive and mean
  ``*value*``, ``value*`` and ``*value``: wildcards and escapes inside the
  value apply exactly as for equality (before B2 they were read literally,
  so ``'tasklist*|*find'`` and the UNC prefix ``'\\\\\\\\'`` could not match);
* ``*`` matches across line breaks, since a field such as a command line can
  hold one;
* ``re`` is a case-sensitive regular-expression search;
* ``cased`` switches the string predicates to case-sensitive matching;
* ``cidr``, ``exists`` and ``gt``/``gte``/``lt``/``lte`` cover network
  ranges, field presence and numeric comparison.

Value transforms (``windash``, ``base64``, ``base64offset``, with optional
``utf16le``/``wide``/``utf16be`` encodings) expand a rule value into the
candidate strings the matcher then tests with the predicate.

The ``all`` modifier is not a predicate; it switches list semantics from
OR to AND and is handled by the matcher.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from functools import cache

from bastion.models import FieldValue

#: Rule values as they come out of YAML.
RuleValue = str | int | float | bool | None

IGNORECASE = re.IGNORECASE


def _to_text(value: FieldValue | RuleValue) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


@cache
def compiled(pattern: str, flags: int = 0) -> re.Pattern[str]:
    """Compile a regex once per process.

    ``re``'s own cache holds 512 entries and a ruleset carries thousands of
    patterns, so it thrashes; this cache is unbounded. An invalid pattern
    raises ``re.error`` from here, as it did from ``re.search`` before.
    """
    return re.compile(pattern, flags)


@cache
def wildcard_to_regex(pattern: str) -> str:
    """Translate a Sigma wildcard pattern into an anchored regex.

    Implements Sigma's escaping rules: ``\\*``/``\\?`` mean a literal
    wildcard, ``\\\\`` a literal backslash, and a backslash before anything
    else is a plain backslash.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern) and pattern[i + 1] in ("*", "?", "\\"):
            out.append(re.escape(pattern[i + 1]))
            i += 2
        elif char == "*":
            out.append(".*")
            i += 1
        elif char == "?":
            out.append(".")
            i += 1
        else:
            out.append(re.escape(char))
            i += 1
    return "".join(out)


def is_pattern(rule_value: RuleValue) -> bool:
    """True when Sigma's wildcard or escape rules give the value a non-literal meaning.

    That is a ``*`` or ``?`` (wildcards, or escaped literals), or a doubled backslash (an
    escaped backslash). Any other value means exactly its text, and the fast literal
    comparisons below apply unchanged.
    """
    return isinstance(rule_value, str) and (
        "*" in rule_value or "?" in rule_value or "\\\\" in rule_value
    )


def _pattern(rule_value: str, anchor: str, cased: bool) -> re.Pattern[str]:
    """The compiled pattern for a string predicate. ``*`` crosses line breaks (DOTALL):
    a command line can hold a newline, and the wildcard means any run of characters."""
    flags = re.DOTALL if cased else re.IGNORECASE | re.DOTALL
    regex = wildcard_to_regex(rule_value)
    return compiled(regex + r"\Z" if anchor == "end" else regex, flags)


def match_equals(field_value: FieldValue, rule_value: RuleValue, cased: bool = False) -> bool:
    """Sigma base equality: case-insensitive (unless ``cased``), wildcard- and null-aware."""
    if rule_value is None:
        return field_value is None
    if field_value is None:
        return False
    if isinstance(rule_value, str) and is_pattern(rule_value):
        return _pattern(rule_value, "full", cased).fullmatch(_to_text(field_value)) is not None
    if cased:
        return _to_text(field_value) == _to_text(rule_value)
    return _to_text(field_value).casefold() == _to_text(rule_value).casefold()


def match_contains(field_value: FieldValue, rule_value: RuleValue, cased: bool = False) -> bool:
    """Sigma ``contains``: the value as ``*value*``, so its wildcards and escapes apply."""
    if field_value is None or rule_value is None:
        return False
    if isinstance(rule_value, str) and is_pattern(rule_value):
        return _pattern(rule_value, "any", cased).search(_to_text(field_value)) is not None
    if cased:
        return _to_text(rule_value) in _to_text(field_value)
    return _to_text(rule_value).casefold() in _to_text(field_value).casefold()


def match_startswith(field_value: FieldValue, rule_value: RuleValue, cased: bool = False) -> bool:
    """Sigma ``startswith``: the value as ``value*``."""
    if field_value is None or rule_value is None:
        return False
    if isinstance(rule_value, str) and is_pattern(rule_value):
        return _pattern(rule_value, "start", cased).match(_to_text(field_value)) is not None
    if cased:
        return _to_text(field_value).startswith(_to_text(rule_value))
    return _to_text(field_value).casefold().startswith(_to_text(rule_value).casefold())


def match_endswith(field_value: FieldValue, rule_value: RuleValue, cased: bool = False) -> bool:
    """Sigma ``endswith``: the value as ``*value``."""
    if field_value is None or rule_value is None:
        return False
    if isinstance(rule_value, str) and is_pattern(rule_value):
        return _pattern(rule_value, "end", cased).search(_to_text(field_value)) is not None
    if cased:
        return _to_text(field_value).endswith(_to_text(rule_value))
    return _to_text(field_value).casefold().endswith(_to_text(rule_value).casefold())


def match_cidr(field_value: FieldValue, rule_value: RuleValue) -> bool:
    """True when the field value is an IP address inside the rule's CIDR range."""
    if field_value is None or rule_value is None:
        return False
    try:
        address = ipaddress.ip_address(_to_text(field_value).strip())
        network = ipaddress.ip_network(_to_text(rule_value).strip(), strict=False)
    except ValueError:
        return False
    return address.version == network.version and address in network


def match_exists(field_value: FieldValue, rule_value: RuleValue) -> bool:
    """``Field|exists: true`` matches when the field is present (and vice versa)."""
    if isinstance(rule_value, bool):
        expected = rule_value
    else:
        expected = _to_text(rule_value).lower() == "true"
    return (field_value is not None) == expected


def match_compare(field_value: FieldValue, rule_value: RuleValue, op: str) -> bool:
    """Numeric comparison for the ``gt``/``gte``/``lt``/``lte`` modifiers."""
    if field_value is None or rule_value is None or isinstance(rule_value, bool):
        return False
    try:
        field_num = float(_to_text(field_value))
        rule_num = float(_to_text(rule_value))
    except ValueError:
        return False
    if op == "gt":
        return field_num > rule_num
    if op == "gte":
        return field_num >= rule_num
    if op == "lt":
        return field_num < rule_num
    return field_num <= rule_num


def windash_variants(value: str) -> list[str]:
    """Dash/slash flag-prefix variants for the ``windash`` modifier.

    Generates the value with all ``-`` swapped to ``/`` and the reverse, so
    ``-nop`` also matches ``/nop``. Per-character permutations are not
    generated; mixed-prefix command lines are rare enough that the uniform
    swap covers the rules in the wild.
    """
    variants = {value, value.replace("-", "/"), value.replace("/", "-")}
    return sorted(variants)


def encode_base64(data: bytes) -> str:
    """Plain base64 of the rule value for the ``base64`` modifier."""
    return base64.b64encode(data).decode()


def base64offset_candidates(data: bytes) -> list[str]:
    """The three alignment-shifted base64 encodings for ``base64offset``.

    Base64 encodes in 3-byte groups, so a value can appear in an encoded
    stream in one of three alignments. For each shift the leading characters
    influenced by the padding and the trailing characters influenced by what
    follows are trimmed, leaving the stable middle that a ``contains`` match
    can rely on.
    """
    starts = (0, 2, 3)
    ends = (None, -3, -2)
    candidates = []
    for shift in range(3):
        encoded = base64.b64encode(b" " * shift + data).decode()
        candidates.append(encoded[starts[shift] : ends[(len(data) + shift) % 3]])
    return candidates


def match_re(field_value: FieldValue, rule_value: RuleValue) -> bool:
    """Case-sensitive regex search. An invalid pattern raises ``re.error``,
    which the engine records as a rule-evaluation error rather than a miss."""
    if field_value is None or rule_value is None:
        return False
    return compiled(_to_text(rule_value)).search(_to_text(field_value)) is not None
