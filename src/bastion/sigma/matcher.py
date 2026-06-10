"""Evaluate a Sigma rule's detection block against one normalized Event.

Supported Sigma grammar subset. Anything outside it raises
:class:`UnsupportedRuleError`, so the engine records the rule as not
evaluated instead of mis-judging it:

Detection identifiers
    * a map of field specs: all entries must match (AND). A field spec is
      ``FieldName`` or ``FieldName|modifier`` (optionally ``|all``); a
      list of values matches if any value matches (OR), or every value
      when the ``all`` modifier is present; a ``null`` value matches a
      missing/null field.
    * a list of maps: any map may match (OR).
    * a list of scalars: keywords, matched case-insensitively (with
      wildcards) as substrings of the raw record and every field value.

Value modifiers
    ``contains``, ``startswith``, ``endswith``, ``re``, ``all``; see
    :mod:`bastion.sigma.modifiers`. Anything else (``base64``, ``windash``,
    ``cidr``, chained transforms, ...) is unsupported.

Condition expressions
    identifiers, ``and`` / ``or`` / ``not``, parentheses,
    ``<N> of <pattern|them>`` and ``all of <pattern|them>`` (``pattern``
    may use ``*`` wildcards); a list-valued ``condition`` is OR-linked.
    Aggregations (``| count() ...``), ``near`` and ``timeframe`` are
    unsupported.

A successful match reports the field/value pairs of every identifier that
evaluated to true, tying the alert back to the log content behind it.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import cast

from bastion.models import Event, SigmaRule
from bastion.sigma import modifiers as mods
from bastion.sigma.modifiers import RuleValue

_PREDICATES: dict[str, Callable[..., bool]] = {
    "": mods.match_equals,
    "contains": mods.match_contains,
    "startswith": mods.match_startswith,
    "endswith": mods.match_endswith,
    "re": mods.match_re,
}

_RESERVED_KEYS = {"condition", "timeframe"}
_KEYWORDS = {"and", "or", "not", "of", "(", ")"}


class UnsupportedRuleError(Exception):
    """The rule uses Sigma grammar outside the supported subset."""


@dataclass
class MatchResult:
    """Outcome of evaluating one rule against one event."""

    matched: bool
    matched_fields: dict[str, str] = field(default_factory=dict)


def evaluate(rule: SigmaRule, event: Event) -> bool:
    """True when ``rule`` fires on ``event`` (see :func:`match` for evidence)."""
    return match(rule, event).matched


def match(rule: SigmaRule, event: Event) -> MatchResult:
    """Evaluate ``rule`` against ``event``, capturing matched-field evidence."""
    detection = rule.detection
    if "timeframe" in detection:
        raise UnsupportedRuleError("timeframe/aggregation rules are not supported")
    raw_condition = detection.get("condition")
    if raw_condition is None:
        raise UnsupportedRuleError("detection block has no condition")
    conditions = raw_condition if isinstance(raw_condition, list) else [raw_condition]

    identifiers = {key: value for key, value in detection.items() if key not in _RESERVED_KEYS}
    if not identifiers:
        raise UnsupportedRuleError("detection block has no search identifiers")

    cache: dict[str, MatchResult] = {}

    def resolve(name: str) -> bool:
        if name not in cache:
            cache[name] = _eval_identifier(identifiers[name], event)
        return cache[name].matched

    matched = any(
        _eval_condition(str(condition), list(identifiers), resolve) for condition in conditions
    )
    if not matched:
        return MatchResult(matched=False)

    evidence: dict[str, str] = {}
    for result in cache.values():
        if result.matched:
            evidence.update(result.matched_fields)
    return MatchResult(matched=True, matched_fields=evidence)


# --- identifier evaluation -------------------------------------------------


def _eval_identifier(value: object, event: Event) -> MatchResult:
    if isinstance(value, dict):
        return _eval_map(value, event)
    if isinstance(value, list):
        if value and all(isinstance(item, dict) for item in value):
            evidence: dict[str, str] = {}
            matched = False
            for item in value:
                result = _eval_map(item, event)
                if result.matched:
                    matched = True
                    evidence.update(result.matched_fields)
            return MatchResult(matched=matched, matched_fields=evidence)
        if any(isinstance(item, dict | list) for item in value):
            raise UnsupportedRuleError("identifier mixes maps and scalars")
        return _eval_keywords(value, event)
    if isinstance(value, str | int | float):
        return _eval_keywords([value], event)
    raise UnsupportedRuleError(f"unsupported identifier shape: {type(value).__name__}")


def _eval_map(spec: dict[object, object], event: Event) -> MatchResult:
    evidence: dict[str, str] = {}
    for field_spec, rule_value in spec.items():
        field_name, predicate, match_all = _parse_field_spec(str(field_spec))
        if isinstance(rule_value, list):
            values = cast("list[RuleValue]", rule_value)
        else:
            values = [cast("RuleValue", rule_value)]
        field_value = event.fields.get(field_name)
        combine = all if match_all else any
        if not values:
            return MatchResult(matched=False)
        if not combine(predicate(field_value, value) for value in values):
            return MatchResult(matched=False)
        evidence[field_name] = "(absent)" if field_value is None else str(field_value)
    return MatchResult(matched=True, matched_fields=evidence)


def _parse_field_spec(field_spec: str) -> tuple[str, Callable[..., bool], bool]:
    """Split ``Field|modifier|all`` into (field name, predicate, all-flag)."""
    parts = field_spec.split("|")
    field_name, modifier_chain = parts[0], parts[1:]
    match_all = "all" in modifier_chain
    modifier_chain = [modifier for modifier in modifier_chain if modifier != "all"]
    if len(modifier_chain) > 1:
        raise UnsupportedRuleError(f"chained modifiers are not supported: {field_spec!r}")
    modifier = modifier_chain[0] if modifier_chain else ""
    if modifier not in _PREDICATES:
        raise UnsupportedRuleError(f"unsupported modifier {modifier!r} in {field_spec!r}")
    return field_name, _PREDICATES[modifier], match_all


def _eval_keywords(keywords: list[object], event: Event) -> MatchResult:
    haystack = "\n".join(
        [event.raw, *(str(value) for value in event.fields.values() if value is not None)]
    )
    for keyword in keywords:
        regex = mods.wildcard_to_regex(str(keyword))
        if re.search(regex, haystack, re.IGNORECASE):
            return MatchResult(matched=True, matched_fields={"keyword": str(keyword)})
    return MatchResult(matched=False)


# --- condition expression parsing -------------------------------------------


def _eval_condition(condition: str, names: list[str], resolve: Callable[[str], bool]) -> bool:
    if "|" in condition:
        raise UnsupportedRuleError(f"aggregation conditions are not supported: {condition!r}")
    tokens = condition.replace("(", " ( ").replace(")", " ) ").split()
    if not tokens:
        raise UnsupportedRuleError("empty condition")
    parser = _ConditionParser(tokens, names, resolve)
    result = parser.parse_or()
    if parser.peek() is not None:
        raise UnsupportedRuleError(f"trailing tokens in condition: {condition!r}")
    return result


class _ConditionParser:
    """Recursive-descent parser for the supported condition grammar."""

    def __init__(self, tokens: list[str], names: list[str], resolve: Callable[[str], bool]):
        self._tokens = tokens
        self._pos = 0
        self._names = names
        self._resolve = resolve

    def peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _next(self) -> str:
        token = self.peek()
        if token is None:
            raise UnsupportedRuleError("unexpected end of condition")
        self._pos += 1
        return token

    def parse_or(self) -> bool:
        result = self.parse_and()
        while (token := self.peek()) is not None and token.lower() == "or":
            self._next()
            # No short-circuiting: every referenced identifier should land in
            # the evidence cache, and "near" semantics never apply here.
            right = self.parse_and()
            result = result or right
        return result

    def parse_and(self) -> bool:
        result = self.parse_not()
        while (token := self.peek()) is not None and token.lower() == "and":
            self._next()
            right = self.parse_not()
            result = result and right
        return result

    def parse_not(self) -> bool:
        token = self.peek()
        if token is not None and token.lower() == "not":
            self._next()
            return not self.parse_not()
        return self.parse_primary()

    def parse_primary(self) -> bool:
        token = self._next()
        lowered = token.lower()
        if token == "(":
            result = self.parse_or()
            if self._next() != ")":
                raise UnsupportedRuleError("unbalanced parentheses in condition")
            return result
        if lowered == "all" or token.isdigit():
            return self._parse_quantifier(token)
        if lowered in _KEYWORDS or token == ")":
            raise UnsupportedRuleError(f"unexpected token {token!r} in condition")
        return self._resolve_name(token)

    def _parse_quantifier(self, count_token: str) -> bool:
        if self._next().lower() != "of":
            raise UnsupportedRuleError(f"expected 'of' after {count_token!r}")
        target = self._next()
        if target.lower() == "them":
            selected = list(self._names)
        elif "*" in target:
            selected = [name for name in self._names if fnmatch.fnmatchcase(name, target)]
        else:
            selected = [name for name in self._names if name == target]
        if not selected:
            raise UnsupportedRuleError(f"condition references unknown identifier(s): {target!r}")
        hits = sum(1 for name in selected if self._resolve(name))
        if count_token.lower() == "all":
            return hits == len(selected)
        return hits >= int(count_token)

    def _resolve_name(self, name: str) -> bool:
        if name not in self._names:
            raise UnsupportedRuleError(f"condition references unknown identifier: {name!r}")
        return self._resolve(name)
