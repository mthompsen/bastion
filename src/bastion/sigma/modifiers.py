"""Sigma value modifiers as pure predicate functions.

Each function answers "does this event field value satisfy this rule
value?" for one modifier. Per the Sigma specification:

* base equality is case-insensitive and honours wildcards in the rule
  value (``*`` matches any run of characters, ``?`` any single character;
  ``\\*`` / ``\\?`` escape a literal wildcard and ``\\\\`` a literal
  backslash, while any other backslash is plain, so Windows paths need no
  doubling);
* ``contains`` / ``startswith`` / ``endswith`` are case-insensitive; rule
  values used with these modifiers are treated literally (wildcards inside
  them are not interpreted, a documented subset limitation);
* ``re`` is a case-sensitive regular-expression search.

The ``all`` modifier is not a predicate; it switches list semantics from
OR to AND and is handled by the matcher.
"""

from __future__ import annotations

import re

from bastion.models import FieldValue

#: Rule values as they come out of YAML.
RuleValue = str | int | float | bool | None


def _to_text(value: FieldValue | RuleValue) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


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


def match_equals(field_value: FieldValue, rule_value: RuleValue) -> bool:
    """Sigma base equality: case-insensitive, wildcard-aware, null-aware."""
    if rule_value is None:
        return field_value is None
    if field_value is None:
        return False
    if isinstance(rule_value, str) and ("*" in rule_value or "?" in rule_value):
        regex = wildcard_to_regex(rule_value)
        return re.fullmatch(regex, _to_text(field_value), re.IGNORECASE) is not None
    return _to_text(field_value).casefold() == _to_text(rule_value).casefold()


def match_contains(field_value: FieldValue, rule_value: RuleValue) -> bool:
    if field_value is None or rule_value is None:
        return False
    return _to_text(rule_value).casefold() in _to_text(field_value).casefold()


def match_startswith(field_value: FieldValue, rule_value: RuleValue) -> bool:
    if field_value is None or rule_value is None:
        return False
    return _to_text(field_value).casefold().startswith(_to_text(rule_value).casefold())


def match_endswith(field_value: FieldValue, rule_value: RuleValue) -> bool:
    if field_value is None or rule_value is None:
        return False
    return _to_text(field_value).casefold().endswith(_to_text(rule_value).casefold())


def match_re(field_value: FieldValue, rule_value: RuleValue) -> bool:
    """Case-sensitive regex search. An invalid pattern raises ``re.error``,
    which the engine records as a rule-evaluation error rather than a miss."""
    if field_value is None or rule_value is None:
        return False
    return re.search(_to_text(rule_value), _to_text(field_value)) is not None
