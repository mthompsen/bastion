"""Static evaluability check: which loaded rules the matcher can evaluate at all.

The engine only discovers unsupported grammar when a rule is evaluated
against an event its category pre-filter admits, and ``_eval_map`` returns
on the first non-matching field, so a later unsupported modifier is never
seen at run time. This walks every identifier and every field-modifier
chain up front, so the count is reproducible and independent of the log
being scanned. It is the ``not_evaluable`` of contract rule 3 for the
grammar cause; the missing-field cause needs the tri-state matcher (B2).
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from bastion.models import SigmaRule
from bastion.sigma import matcher
from bastion.sigma.matcher import UnsupportedRuleError

# This module reaches into the matcher's private surface on purpose: ``_parse_field_spec``
# (cached, returns a frozen ``_FieldSpec``), ``_eval_condition`` (compiles and evaluates a
# condition against a resolver) and ``_RESERVED_KEYS``. Grammar work in B2 that renames or
# reshapes any of them must update this check in the same change, or the bench will report
# a stale evaluability picture.


@dataclass(frozen=True)
class Unsupported:
    rule_id: str
    file_path: str
    reason: str
    detail: str


def _check_map(mapping: dict[object, object]) -> None:
    for key, value in mapping.items():
        spec = matcher._parse_field_spec(str(key))
        values = value if isinstance(value, list) else [value]
        if spec.has_transforms and any(v is None for v in values):
            raise UnsupportedRuleError("null values cannot be combined with value transforms")
        if spec.predicate == "re":
            for candidate in values:
                try:
                    re.compile(str(candidate))
                except re.error as exc:
                    raise UnsupportedRuleError(f"regex does not compile: {exc}") from exc


def _check_identifier(value: object) -> None:
    if isinstance(value, dict):
        _check_map(value)
    elif isinstance(value, list):
        if value and all(isinstance(item, dict) for item in value):
            for item in value:
                _check_map(item)
        elif any(isinstance(item, dict | list) for item in value):
            raise UnsupportedRuleError("identifier mixes maps and scalars")
    elif not isinstance(value, str | int | float):
        raise UnsupportedRuleError(f"unsupported identifier shape: {type(value).__name__}")


def classify(message: str) -> str:
    """A short reason key for a matcher error message."""
    found = re.search(r"unsupported modifier '([^']+)'", message)
    if found:
        return f"modifier:{found.group(1).lower()}"
    for key in (
        "multiple encodings",
        "multiple base64",
        "multiple match modifiers",
        "utf16 encodings require",
        "cased' only applies",
        "value transforms require",
        "identifier mixes",
        "unsupported identifier shape",
        "null values cannot",
        "keyword lists take only",
        "regex does not compile",
        "unknown identifier",
        "unbalanced",
        "unexpected token",
        "trailing tokens",
        "expected 'of'",
        "no condition",
        "no search identifiers",
    ):
        if key in message:
            return "structure:" + key.replace("'", "").replace(" ", "-")
    return "other:" + message[:40]


def check_rule(rule: SigmaRule) -> Unsupported | None:
    """None when the matcher can evaluate the rule, else the first reason it cannot."""
    detection = rule.detection
    if "timeframe" in detection:
        return Unsupported(rule.id, rule.file_path, "aggregation:timeframe", "timeframe key")
    condition = detection.get("condition")
    if condition is None:
        return Unsupported(rule.id, rule.file_path, "structure:no-condition", "")
    conditions = condition if isinstance(condition, list) else [condition]
    identifiers = {k: v for k, v in detection.items() if k not in matcher._RESERVED_KEYS}
    if not identifiers:
        return Unsupported(rule.id, rule.file_path, "structure:no-identifiers", "")
    for text in conditions:
        text = str(text)
        if "|" in text:
            aggregate = text.split("|", 1)[1].strip()
            head = re.split(r"[ (]", aggregate, maxsplit=1)[0]
            return Unsupported(rule.id, rule.file_path, f"aggregation:{head}", text)
        try:
            matcher._eval_condition(text, list(identifiers), lambda _name: True)
        except UnsupportedRuleError as exc:
            return Unsupported(rule.id, rule.file_path, classify(str(exc)), str(exc))
    for value in identifiers.values():
        try:
            _check_identifier(value)
        except UnsupportedRuleError as exc:
            return Unsupported(rule.id, rule.file_path, classify(str(exc)), str(exc))
    return None


@dataclass
class EvaluabilityReport:
    unsupported: list[Unsupported]
    by_reason: dict[str, int]

    def evaluable(self, rule: SigmaRule) -> bool:
        return not any(
            u.rule_id == rule.id and u.file_path == rule.file_path for u in self.unsupported
        )

    def evaluable_map(self, rules: Sequence[SigmaRule]) -> dict[str, bool]:
        bad = {(u.rule_id, u.file_path) for u in self.unsupported}
        return {r.id + r.file_path: (r.id, r.file_path) not in bad for r in rules}


def check_rules(rules: Sequence[SigmaRule]) -> EvaluabilityReport:
    unsupported = [found for rule in rules if (found := check_rule(rule)) is not None]
    by_reason = Counter(u.reason for u in unsupported)
    return EvaluabilityReport(unsupported, dict(by_reason.most_common()))
