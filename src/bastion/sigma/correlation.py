"""Sigma correlation rules: a pass over what single-event rules match (B4 lever c).

Ported from Citadel M2 (`citadel/core/sigma/correlation.py`, Citadel commit `12a0fed`, read at
`ff50c75`; MIT, same author), following Citadel ADR 0008: the matcher keeps its one rule, one
event contract, and this module holds everything that needs state across events (grouping,
the time bound, the counting). Bastion's version is streaming: :class:`Correlator` sees each
event once, inside :func:`bastion.engine.scan`, and keeps only the events a correlation's
inputs matched, so memory grows with matches, not with the log.

The format is Sigma's correlation specification 2.1.0. A correlation file is a multi-document
YAML stream: the correlation first, then its **building blocks**, the single-event rules it
correlates, each carrying the `name` the correlation refers to. A building block is parsed into
its correlation and nowhere else (the rule loader skips correlation files), so it can never
alert on its own. `generate: true` is refused, because it exists to make referenced rules
alert. A correlation may also name rules by id that live in files of their own; those alert on
their own already.

Supported types: `event_count`, `value_count`, `temporal`, `temporal_ordered`. The other three
the specification defines (`value_sum`, `value_avg`, `value_percentile`) are recorded as
unsupported, never dropped.

**Techniques.** START_PROMPT section 6 lever 5: a correlation alert is tagged with the
techniques of its constituent rules only. A correlation's own tags count when its constituents
are building blocks written in the same file (they are one rule); tags it adds beyond its
externally referenced rules' tags are dropped and recorded.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from bastion.models import Event, SigmaRule
from bastion.sigma.loader import is_correlation, read_documents, rule_from_document
from bastion.sigma.matcher import UnsupportedRuleError, match

CorrelationType = Literal["event_count", "value_count", "temporal", "temporal_ordered"]

SUPPORTED_TYPES: frozenset[str] = frozenset(
    {"event_count", "value_count", "temporal", "temporal_ordered"}
)
_SPECIFIED_TYPES = SUPPORTED_TYPES | {"value_sum", "value_avg", "value_percentile"}
_COMPARISONS = frozenset({"gt", "gte", "lt", "lte", "eq", "neq"})
_TIMESPAN = re.compile(r"^(\d+)([smhd])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class CorrelationError(ValueError):
    """A correlation file that cannot be used, with the reason."""


class UnsupportedCorrelation(CorrelationError):
    """A correlation the specification allows and this module does not evaluate."""


@dataclass(frozen=True)
class CorrelationRule:
    """One correlation and everything it correlates.

    ``header`` carries the correlation's own metadata as a rule with no detection. ``blocks``
    are the building blocks, keyed by the `name` the correlation refers to them by;
    ``external`` are rule ids the correlation names that live in files of their own.
    """

    header: SigmaRule
    type: CorrelationType
    group_by: tuple[str, ...]
    timespan: timedelta
    condition: Mapping[str, int]
    blocks: Mapping[str, SigmaRule]
    external: tuple[str, ...] = ()
    #: the rules in the order the correlation names them, which `temporal_ordered` reads
    order: tuple[str, ...] = ()
    #: `value_count`'s counted field, named inside the condition by the specification
    value_field: str | None = None
    #: alias -> rule name -> the field that rule's events carry the alias under
    aliases: Mapping[str, Mapping[str, str]] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.header.id


def parse_timespan(text: object) -> timedelta:
    """`10s`, `5m`, `1h` or `1d`: one number, one lower case unit, as the specification says."""
    found = _TIMESPAN.match(str(text).strip())
    if found is None:
        raise CorrelationError(f"timespan {text!r} is not a number and one of s, m, h, d")
    return timedelta(seconds=int(found.group(1)) * _UNIT_SECONDS[found.group(2)])


def parse_correlation(documents: Sequence[Any], path: Path) -> CorrelationRule:
    """A correlation file's documents as one rule, or raise saying why it cannot be used."""
    head = documents[0]
    block = head.get("correlation")
    if not isinstance(block, dict):
        raise CorrelationError(f"{path}: `correlation` is not a mapping")
    if head.get("generate") is True:
        raise CorrelationError(
            f"{path}: `generate: true` makes the correlated rules alert on their own, which a "
            "building block must never do"
        )
    kind = str(block.get("type", ""))
    if kind not in _SPECIFIED_TYPES:
        raise CorrelationError(f"{path}: correlation type {kind!r} is not in the specification")
    if kind not in SUPPORTED_TYPES:
        raise UnsupportedCorrelation(f"{path}: correlation type {kind!r} is not evaluated here")

    header = rule_from_document({**head, "detection": {}}, path)
    if header is None:
        raise CorrelationError(f"{path}: the correlation header is not a valid rule")

    blocks: dict[str, SigmaRule] = {}
    for index, doc in enumerate(documents[1:], start=2):
        name = doc.get("name") if isinstance(doc, dict) else None
        if not name:
            raise CorrelationError(f"{path}: document {index} is a building block with no name")
        if not isinstance(doc.get("detection"), dict):
            raise CorrelationError(f"{path}: building block {name!r} has no detection")
        rule = rule_from_document(
            {"title": f"{header.title}: {name}", **doc}, path, rule_id=f"{header.id}:{name}"
        )
        if rule is None:
            raise CorrelationError(f"{path}: building block {name!r} is not a valid rule")
        blocks[str(name)] = rule

    order = tuple(str(ref) for ref in block.get("rules") or [])
    if not order:
        raise CorrelationError(f"{path}: the correlation names no rules")
    orphans = sorted(set(blocks) - set(order))
    if orphans:
        # A block the correlation does not name would still count as one of its inputs,
        # changing what the correlation counts without the correlation saying so.
        raise CorrelationError(f"{path}: building block(s) {orphans} are not in `rules`")
    group_by = tuple(str(name) for name in block.get("group-by") or [])
    if not group_by:
        raise CorrelationError(f"{path}: `group-by` is required")

    condition: dict[str, int] = {}
    value_field: str | None = None
    raw_condition = block.get("condition") or {}
    if not isinstance(raw_condition, dict):
        raise CorrelationError(f"{path}: `condition` is not a mapping")
    for key, value in raw_condition.items():
        if key == "field" and isinstance(value, list):
            raise UnsupportedCorrelation(
                f"{path}: value_count over several fields at once is not evaluated here"
            )
        if key == "field":
            value_field = str(value)
        elif key in _COMPARISONS and isinstance(value, int) and not isinstance(value, bool):
            condition[str(key)] = value
        else:
            raise CorrelationError(f"{path}: condition {key}: {value!r} is not a comparison")
    if kind in ("event_count", "value_count") and not condition:
        raise CorrelationError(f"{path}: {kind} needs a condition")
    if kind == "value_count" and value_field is None:
        raise CorrelationError(f"{path}: value_count needs a `field` in its condition")

    aliases = {
        str(alias): {str(rule): str(name) for rule, name in (mapping or {}).items()}
        for alias, mapping in (block.get("aliases") or {}).items()
    }
    return CorrelationRule(
        header=header,
        type=kind,  # type: ignore[arg-type]  # checked against SUPPORTED_TYPES above
        group_by=group_by,
        timespan=parse_timespan(block.get("timespan")),
        condition=condition,
        blocks=blocks,
        external=tuple(ref for ref in order if ref not in blocks),
        order=order,
        value_field=value_field,
        aliases=aliases,
    )


@dataclass
class LoadedCorrelations:
    """What a rules tree holds by way of correlations, including what could not be used."""

    rules: list[CorrelationRule] = field(default_factory=list)
    #: path -> reason, for files the specification allows and this module does not evaluate
    unsupported: dict[str, str] = field(default_factory=dict)
    #: path -> reason, for files that are not usable correlations at all
    errors: dict[str, str] = field(default_factory=dict)

    def extend(self, other: LoadedCorrelations) -> None:
        self.rules += other.rules
        self.unsupported.update(other.unsupported)
        self.errors.update(other.errors)


def load_correlations(rules_dir: Path) -> LoadedCorrelations:
    """Every correlation file under ``rules_dir``, and every one that could not be used.

    A file whose text never says `correlation:` is not parsed again: over the SigmaHQ trees
    that is every file today.
    """
    loaded = LoadedCorrelations()
    if not rules_dir.is_dir():
        return loaded
    for path in sorted(p for p in rules_dir.rglob("*") if p.suffix.lower() in (".yml", ".yaml")):
        if "correlation:" not in path.read_text(encoding="utf-8", errors="replace"):
            continue
        documents = read_documents(path)
        if documents is None or not is_correlation(documents):
            continue
        try:
            loaded.rules.append(parse_correlation(documents, path))
        except UnsupportedCorrelation as exc:
            loaded.unsupported[str(path)] = str(exc)
        except CorrelationError as exc:
            loaded.errors[str(path)] = str(exc)
    return loaded


def correlation_techniques(
    rule: CorrelationRule, rules_by_id: Mapping[str, SigmaRule]
) -> tuple[list[str], list[str]]:
    """``(kept, dropped)``: the correlation's technique ids, restricted to its constituents'.

    Building blocks are part of the correlation's own file, so the correlation's tags speak
    for them. Rules named by id speak for themselves: a tag the correlation adds beyond the
    union of their tags is dropped (START_PROMPT section 6 lever 5).
    """
    own = rule.header.technique_ids()
    if rule.blocks:
        return list(own), []
    allowed: set[str] = set()
    for ref in rule.external:
        if ref in rules_by_id:
            allowed.update(t.upper() for t in rules_by_id[ref].technique_ids())
    if not own:
        return sorted(allowed), []
    kept = [t for t in own if t.upper() in allowed]
    return kept, [t for t in own if t.upper() not in allowed]


@dataclass
class CorrelatedFinding:
    """One group of events that satisfied a correlation."""

    rule_id: str
    rule_title: str
    level: str
    group: dict[str, str]
    events: list[Event]
    matched_by: list[str]
    techniques: list[str]


@dataclass
class CorrelationOutcome:
    findings: list[CorrelatedFinding] = field(default_factory=list)
    #: correlation id -> groups keyed on `pid` whose events carried more than one `Image`,
    #: reported rather than merged, because a merged chain reports a sequence nobody ran
    collisions: dict[str, int] = field(default_factory=dict)
    #: correlation id -> matched events that could not be grouped (a group-by field absent,
    #: or no timestamp)
    ungrouped: dict[str, int] = field(default_factory=dict)
    #: rule id -> reason, for a building block or rule the matcher cannot evaluate
    unsupported_rules: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class _Hit:
    event: Event
    timestamp: datetime
    rule: str


class Correlator:
    """Evaluates correlations over a stream of events, one :meth:`observe` per event."""

    def __init__(
        self,
        correlations: Sequence[CorrelationRule],
        rules_by_id: Mapping[str, SigmaRule] | None = None,
        applies: Any = None,
    ) -> None:
        self.correlations = list(correlations)
        self.rules_by_id = dict(rules_by_id or {})
        # The engine's logsource pre-filter, so a building block meets exactly the events it
        # would meet as a rule. Injected to keep this module free of the engine import.
        self.applies = applies or (lambda rule, event: True)
        self.inputs: list[dict[str, SigmaRule]] = []
        for rule in self.correlations:
            inputs = dict(rule.blocks)
            for ref in rule.external:
                if ref in self.rules_by_id:
                    inputs[ref] = self.rules_by_id[ref]
            self.inputs.append(inputs)
        self.groups: list[dict[tuple[str, ...], list[_Hit]]] = [{} for _ in self.correlations]
        self.outcome = CorrelationOutcome()

    def observe(self, event: Event) -> None:
        unsupported = self.outcome.unsupported_rules
        for index, rule in enumerate(self.correlations):
            for name, input_rule in self.inputs[index].items():
                if input_rule.id in unsupported or not self.applies(input_rule, event):
                    continue
                try:
                    matched = match(input_rule, event).matched
                except UnsupportedRuleError as exc:
                    unsupported[input_rule.id] = str(exc)
                    continue
                if not matched:
                    continue
                values = [_group_value(rule, name, alias, event) for alias in rule.group_by]
                if event.timestamp is None or any(value is None for value in values):
                    self.outcome.ungrouped[rule.id] = self.outcome.ungrouped.get(rule.id, 0) + 1
                    continue
                key = tuple(value or "" for value in values)
                # Text logs carry no zone: read a naive timestamp as UTC, as the bench does, so
                # one group can hold events from sources with and without a zone.
                when = event.timestamp
                when = when if when.tzinfo is not None else when.replace(tzinfo=UTC)
                self.groups[index].setdefault(key, []).append(_Hit(event, when, name))

    def finish(self) -> CorrelationOutcome:
        """Findings over everything observed. Call once, after the last event."""
        for index, rule in enumerate(self.correlations):
            techniques, _ = correlation_techniques(rule, self.rules_by_id)
            for key, hits in self.groups[index].items():
                hits.sort(key=lambda hit: hit.timestamp)
                group = dict(zip(rule.group_by, key, strict=True))
                # Sliding for "at least", tumbling for everything else (Citadel): any window
                # holding enough is a finding for gt, gte and the temporal types, so the window
                # slides one event at a time. For an upper bound, sliding manufactures
                # findings, so those windows tumble from the first event.
                sliding = rule.type.startswith("temporal") or set(rule.condition) <= {"gt", "gte"}
                start = 0
                while start < len(hits):
                    horizon = hits[start].timestamp + rule.timespan
                    span = [hit for hit in hits[start:] if hit.timestamp <= horizon]
                    if not _satisfied(rule, span):
                        start += 1 if sliding else len(span)
                        continue
                    if (
                        "pid" in rule.group_by
                        and len({hit.event.fields.get("Image") for hit in span}) > 1
                    ):
                        self.outcome.collisions[rule.id] = (
                            self.outcome.collisions.get(rule.id, 0) + 1
                        )
                    else:
                        self.outcome.findings.append(
                            CorrelatedFinding(
                                rule_id=rule.id,
                                rule_title=rule.header.title,
                                level=rule.header.level,
                                group=group,
                                events=[hit.event for hit in span],
                                matched_by=[hit.rule for hit in span],
                                techniques=techniques,
                            )
                        )
                    start += len(span)
        return self.outcome


def _group_value(rule: CorrelationRule, name: str, alias: str, event: Event) -> str | None:
    field_name = rule.aliases.get(alias, {}).get(name, alias)
    value = event.fields.get(field_name)
    return None if value is None else str(value)


def _satisfied(rule: CorrelationRule, hits: Sequence[_Hit]) -> bool:
    if rule.type == "temporal":
        return set(rule.order) <= {hit.rule for hit in hits}
    if rule.type == "temporal_ordered":
        remaining = iter(hit.rule for hit in hits)
        return all(any(seen == wanted for seen in remaining) for wanted in rule.order)
    if rule.type == "value_count":
        field_name = rule.value_field or ""
        measure = len({hit.event.fields.get(field_name) for hit in hits} - {None})
    else:
        # One event matching two of the correlation's inputs happened once, and counts once.
        measure = len({id(hit.event) for hit in hits})
    checks = {
        "gt": lambda bound: measure > bound,
        "gte": lambda bound: measure >= bound,
        "lt": lambda bound: measure < bound,
        "lte": lambda bound: measure <= bound,
        "eq": lambda bound: measure == bound,
        "neq": lambda bound: measure != bound,
    }
    return all(checks[op](bound) for op, bound in rule.condition.items())
