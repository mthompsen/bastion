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
    Match predicates: ``contains``, ``startswith``, ``endswith``, ``re``,
    ``cidr``, ``exists``, ``gt``/``gte``/``lt``/``lte``, plus ``cased`` for
    case-sensitive string matching and ``all`` for AND-list semantics.
    Value transforms, applied before a string predicate: ``windash``,
    ``base64``, ``base64offset``, optionally preceded by ``utf16le`` /
    ``wide`` / ``utf16be``. See :mod:`bastion.sigma.modifiers`. Anything
    else (``fieldref``, ``expand``, ``minute``, ...) is unsupported.

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
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cache
from typing import cast

from bastion.models import Event, FieldValue, SigmaRule
from bastion.sigma import modifiers as mods
from bastion.sigma.modifiers import RuleValue

#: Predicates that accept the ``cased`` flag.
_STRING_PREDICATES = {"", "contains", "startswith", "endswith"}
_PREDICATE_NAMES = _STRING_PREDICATES | {"re", "cidr", "exists", "gt", "gte", "lt", "lte"}
#: Encodings applied before a base64 transform.
_ENCODINGS = {"utf16le": "utf-16-le", "wide": "utf-16-le", "utf16be": "utf-16-be"}
_B64_TRANSFORMS = {"base64", "base64offset"}

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

    names = tuple(identifiers)
    matched = any(_compile_condition(str(condition), names)(resolve) for condition in conditions)
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


@dataclass(frozen=True)
class _FieldSpec:
    """A parsed ``Field|modifier|...`` chain. Immutable, so parses are shared across events."""

    field: str
    predicate: str = ""
    match_all: bool = False
    cased: bool = False
    windash: bool = False
    encoding: str | None = None
    b64: str | None = None

    @property
    def has_transforms(self) -> bool:
        return self.windash or self.b64 is not None


def _eval_map(spec: dict[object, object], event: Event) -> MatchResult:
    evidence: dict[str, str] = {}
    for raw_spec, rule_value in spec.items():
        field_spec = _parse_field_spec(str(raw_spec))
        if isinstance(rule_value, list):
            values = cast("list[RuleValue]", rule_value)
        else:
            values = [cast("RuleValue", rule_value)]
        field_value = event.fields.get(field_spec.field)
        combine = all if field_spec.match_all else any
        if not values:
            return MatchResult(matched=False)
        if not combine(_value_matches(field_spec, field_value, value) for value in values):
            return MatchResult(matched=False)
        evidence[field_spec.field] = "(absent)" if field_value is None else str(field_value)
    return MatchResult(matched=True, matched_fields=evidence)


@cache
def _parse_field_spec(raw: str) -> _FieldSpec:
    """Parse a field spec with its modifier chain, validating combinations.

    Cached: the same spec string is parsed once per process and the frozen
    result is shared. Errors are not cached, so an invalid spec raises on
    every call exactly as before.
    """
    parts = raw.split("|")
    predicate = ""
    match_all = cased = windash = False
    encoding: str | None = None
    b64: str | None = None
    for modifier in parts[1:]:
        name = modifier.lower()
        if name == "all":
            match_all = True
        elif name == "cased":
            cased = True
        elif name == "windash":
            windash = True
        elif name in _ENCODINGS:
            if encoding is not None:
                raise UnsupportedRuleError(f"multiple encodings in {raw!r}")
            encoding = _ENCODINGS[name]
        elif name in _B64_TRANSFORMS:
            if b64 is not None:
                raise UnsupportedRuleError(f"multiple base64 transforms in {raw!r}")
            b64 = name
        elif name in _PREDICATE_NAMES:
            if predicate:
                raise UnsupportedRuleError(f"multiple match modifiers in {raw!r}")
            predicate = name
        else:
            raise UnsupportedRuleError(f"unsupported modifier {modifier!r} in {raw!r}")
    spec = _FieldSpec(parts[0], predicate, match_all, cased, windash, encoding, b64)
    if spec.encoding is not None and spec.b64 is None:
        raise UnsupportedRuleError(f"{raw!r}: utf16 encodings require a base64 transform")
    if spec.cased and spec.predicate not in _STRING_PREDICATES:
        raise UnsupportedRuleError(f"{raw!r}: 'cased' only applies to string matches")
    if spec.has_transforms and spec.predicate not in _STRING_PREDICATES:
        raise UnsupportedRuleError(f"{raw!r}: value transforms require a string match")
    return spec


def _value_matches(spec: _FieldSpec, field_value: FieldValue, rule_value: RuleValue) -> bool:
    """Does one rule value (after transforms) satisfy the predicate?"""
    if rule_value is None and not spec.has_transforms and spec.predicate == "":
        return field_value is None
    if spec.has_transforms:
        # The type is part of the key: ``1``, ``1.0`` and ``True`` hash alike but stringify apart.
        candidates = _cached_candidates(spec, type(rule_value).__name__, rule_value)
    else:
        candidates = (rule_value,)
    return any(_apply_predicate(spec, field_value, candidate) for candidate in candidates)


@cache
def _cached_candidates(
    spec: _FieldSpec, _type_name: str, rule_value: RuleValue
) -> tuple[RuleValue, ...]:
    return tuple(_candidate_values(spec, rule_value))


def _candidate_values(spec: _FieldSpec, rule_value: RuleValue) -> list[RuleValue]:
    """Expand a rule value through windash/encoding/base64 transforms."""
    if not spec.has_transforms:
        return [rule_value]
    if rule_value is None:
        raise UnsupportedRuleError("null values cannot be combined with value transforms")
    texts = [str(rule_value)]
    if spec.windash:
        texts = [variant for text in texts for variant in mods.windash_variants(text)]
    if spec.b64 is None:
        return list(texts)
    encoding = spec.encoding or "utf-8"
    candidates: list[RuleValue] = []
    for text in texts:
        data = text.encode(encoding)
        if spec.b64 == "base64":
            candidates.append(mods.encode_base64(data))
        else:
            candidates.extend(mods.base64offset_candidates(data))
    return candidates


def _apply_predicate(spec: _FieldSpec, field_value: FieldValue, candidate: RuleValue) -> bool:
    predicate = spec.predicate
    if predicate == "":
        return mods.match_equals(field_value, candidate, cased=spec.cased)
    if predicate == "contains":
        return mods.match_contains(field_value, candidate, cased=spec.cased)
    if predicate == "startswith":
        return mods.match_startswith(field_value, candidate, cased=spec.cased)
    if predicate == "endswith":
        return mods.match_endswith(field_value, candidate, cased=spec.cased)
    if predicate == "re":
        return mods.match_re(field_value, candidate)
    if predicate == "cidr":
        return mods.match_cidr(field_value, candidate)
    if predicate == "exists":
        return mods.match_exists(field_value, candidate)
    return mods.match_compare(field_value, candidate, predicate)


def _eval_keywords(keywords: list[object], event: Event) -> MatchResult:
    haystack = "\n".join(
        [event.raw, *(str(value) for value in event.fields.values() if value is not None)]
    )
    for keyword in keywords:
        regex = mods.wildcard_to_regex(str(keyword))
        if mods.compiled(regex, mods.IGNORECASE).search(haystack):
            return MatchResult(matched=True, matched_fields={"keyword": str(keyword)})
    return MatchResult(matched=False)


# --- condition expression compilation ----------------------------------------

Resolve = Callable[[str], bool]
Node = Callable[[Resolve], bool]
"""A compiled condition: given an identifier resolver, the condition's truth."""


@cache
def _compile_condition(condition: str, names: tuple[str, ...]) -> Node:
    """Compile a condition string into a callable, once per (condition, identifier names).

    Evaluation order and short-circuit behaviour are those of the original
    interpreting parser: both operands of ``and`` and ``or`` are always
    evaluated, left first, so every referenced identifier lands in the
    evidence cache. Grammar errors are raised here, on the first ``match``
    call for the rule, with the same messages as before; errors are not
    cached, so later calls raise again.
    """
    if "|" in condition:
        raise UnsupportedRuleError(f"aggregation conditions are not supported: {condition!r}")
    tokens = condition.replace("(", " ( ").replace(")", " ) ").split()
    if not tokens:
        raise UnsupportedRuleError("empty condition")
    parser = _ConditionParser(tokens, names)
    node = parser.parse_or()
    if parser.peek() is not None:
        raise UnsupportedRuleError(f"trailing tokens in condition: {condition!r}")
    return node


def _eval_condition(condition: str, names: list[str], resolve: Resolve) -> bool:
    """Evaluate a condition against a resolver (compiles and caches on first use)."""
    return _compile_condition(condition, tuple(names))(resolve)


def _or(left: Node, right: Node) -> Node:
    def node(resolve: Resolve) -> bool:
        first = left(resolve)
        second = right(resolve)
        return first or second

    return node


def _and(left: Node, right: Node) -> Node:
    def node(resolve: Resolve) -> bool:
        first = left(resolve)
        second = right(resolve)
        return first and second

    return node


def _not(child: Node) -> Node:
    return lambda resolve: not child(resolve)


def _name(name: str) -> Node:
    return lambda resolve: resolve(name)


def _quantifier(selected: tuple[str, ...], count: int | None) -> Node:
    """``all of`` when ``count`` is None, else ``count of``. Every selected identifier is
    evaluated, never short-circuited."""

    def node(resolve: Resolve) -> bool:
        hits = sum(1 for name in selected if resolve(name))
        if count is None:
            return hits == len(selected)
        return hits >= count

    return node


class _ConditionParser:
    """Recursive-descent parser for the supported condition grammar, producing Nodes."""

    def __init__(self, tokens: list[str], names: tuple[str, ...]):
        self._tokens = tokens
        self._pos = 0
        self._names = names

    def peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _next(self) -> str:
        token = self.peek()
        if token is None:
            raise UnsupportedRuleError("unexpected end of condition")
        self._pos += 1
        return token

    def parse_or(self) -> Node:
        result = self.parse_and()
        while (token := self.peek()) is not None and token.lower() == "or":
            self._next()
            # No short-circuiting: every referenced identifier should land in
            # the evidence cache, and "near" semantics never apply here.
            result = _or(result, self.parse_and())
        return result

    def parse_and(self) -> Node:
        result = self.parse_not()
        while (token := self.peek()) is not None and token.lower() == "and":
            self._next()
            result = _and(result, self.parse_not())
        return result

    def parse_not(self) -> Node:
        token = self.peek()
        if token is not None and token.lower() == "not":
            self._next()
            return _not(self.parse_not())
        return self.parse_primary()

    def parse_primary(self) -> Node:
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

    def _parse_quantifier(self, count_token: str) -> Node:
        if self._next().lower() != "of":
            raise UnsupportedRuleError(f"expected 'of' after {count_token!r}")
        target = self._next()
        if target.lower() == "them":
            selected = tuple(self._names)
        elif "*" in target:
            selected = tuple(name for name in self._names if fnmatch.fnmatchcase(name, target))
        else:
            selected = tuple(name for name in self._names if name == target)
        if not selected:
            raise UnsupportedRuleError(f"condition references unknown identifier(s): {target!r}")
        count = None if count_token.lower() == "all" else int(count_token)
        return _quantifier(selected, count)

    def _resolve_name(self, name: str) -> Node:
        if name not in self._names:
            raise UnsupportedRuleError(f"condition references unknown identifier: {name!r}")
        return _name(name)
