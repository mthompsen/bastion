"""The scan engine: run Sigma rules over normalized events.

For every event, each applicable rule is evaluated; a match becomes a
:class:`~bastion.models.Detection` carrying the matched-field evidence and
the rule's ATT&CK techniques enriched via the loaded lookup.

Robustness rules: a rule that raises is recorded with its reason and
retired for the rest of the scan, which keeps a single bad rule from
aborting the run. Rules using unsupported Sigma grammar are recorded
separately so the report can state how much of the ruleset was actually
evaluable, and technique tags that don't resolve against ATT&CK are
collected for the report instead of being dropped.

Rules are pre-filtered by ``logsource``: platform first, then on Windows the
routes of the declarative pipeline (``bastion/data/pipelines/windows.yml``): a
listed ``service`` needs the event's ``Channel``, a listed ``category`` one of
its (channel, EventID) routes, so a ``registry_set`` rule is never evaluated
against a process-creation event and a ``service: system`` rule never against a
Sysmon event. A category or service the pipeline does not list is not
restricted; the B1 goodware replay showed what a negation-only rule does then
(raw_access_thread was misspelled, so its one rule fired 63,482 times).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from bastion.attack import resolve_techniques
from bastion.models import Detection, Event, SigmaRule, TechniqueRef
from bastion.pipelines import event_channel, linux_pipeline, windows_pipeline
from bastion.process_tree import ProcessTree
from bastion.sigma.correlation import CorrelationOutcome, CorrelationRule, Correlator
from bastion.sigma.filters import SigmaFilter
from bastion.sigma.matcher import UnsupportedRuleError, match

logger = logging.getLogger(__name__)


@dataclass
class ScanOutcome:
    """Everything a scan produced, including what could not be evaluated."""

    detections: list[Detection] = field(default_factory=list)
    events_scanned: int = 0
    #: process starts that gained a parent field from an earlier start in the same scan
    lineage_enriched: int = 0
    #: correlation findings and what the correlation pass could not place (B4 lever c)
    correlation: CorrelationOutcome = field(default_factory=CorrelationOutcome)
    rules_evaluated: int = 0
    unsupported_rules: dict[str, str] = field(default_factory=dict)
    rule_errors: dict[str, str] = field(default_factory=dict)
    unresolved_techniques: list[str] = field(default_factory=list)
    #: rule id -> detections suppressed by filter documents
    filtered: dict[str, int] = field(default_factory=dict)
    #: filter id -> suppressions it caused
    filter_hits: dict[str, int] = field(default_factory=dict)
    #: filter id -> why it could not be evaluated (it then fails open: detections are kept)
    filter_errors: dict[str, str] = field(default_factory=dict)
    #: rule id -> events on which the rule was not_evaluable: it did not match, and its
    #: answer depended on fields the event's source does not carry (never a no_match)
    not_evaluable: dict[str, int] = field(default_factory=dict)
    #: missing field -> rule-event pairs it left undecided (the reason, by field)
    not_evaluable_fields: dict[str, int] = field(default_factory=dict)
    #: rule id -> events that carry none of the fields the rule reads: the rule is about
    #: another source whose logsource Bastion does not route yet (also never a no_match)
    outside_source: dict[str, int] = field(default_factory=dict)


def _suppressed(
    rule: SigmaRule,
    event: Event,
    candidates: Sequence[tuple[SigmaFilter, SigmaRule]],
    outcome: ScanOutcome,
) -> bool:
    """Does a filter document naming this rule match the event? Errors fail open."""
    for sigma_filter, pseudo in candidates:
        if sigma_filter.id in outcome.filter_errors:
            continue
        if not sigma_filter.applies_to_source(event, rule):
            continue
        try:
            hit = match(pseudo, event).matched
        except Exception as exc:  # a broken filter must never hide a detection
            logger.warning("filter %s (%s) failed: %s", sigma_filter.id, sigma_filter.title, exc)
            outcome.filter_errors[sigma_filter.id] = str(exc)
            continue
        if hit:
            outcome.filtered[rule.id] = outcome.filtered.get(rule.id, 0) + 1
            outcome.filter_hits[sigma_filter.id] = outcome.filter_hits.get(sigma_filter.id, 0) + 1
            return True
    return False


def rule_applies(rule: SigmaRule, event: Event) -> bool:
    """logsource pre-filter: platform match, then the Windows pipeline's routes."""
    product = rule.logsource.get("product", "").lower()
    if product and product != event.platform:
        return False
    if event.platform == "linux":
        return linux_pipeline().admits(rule, event)
    return windows_pipeline().admits(rule, event)


def scan(
    events: Iterable[Event],
    rules: Sequence[SigmaRule],
    attack_lookup: dict[str, TechniqueRef],
    filters: Sequence[SigmaFilter] = (),
    correlations: Sequence[CorrelationRule] = (),
) -> ScanOutcome:
    """Evaluate every applicable rule against every event.

    ``filters`` are Sigma filter documents: a detection whose rule a filter names is
    suppressed when the filter's selection matches the same event, and every suppression
    is counted on the outcome. A filter the matcher cannot evaluate fails open.

    ``correlations`` are Sigma correlation rules, evaluated in the same pass over what their
    building blocks (and any rules they name by id) match; findings are on
    ``outcome.correlation``.
    """
    outcome = ScanOutcome(rules_evaluated=len(rules))
    retired: set[str] = set()
    technique_cache: dict[str, list[TechniqueRef]] = {}
    unresolved_seen: set[str] = set()
    filters_by_rule: dict[str, list[tuple[SigmaFilter, SigmaRule]]] = {}
    for sigma_filter in filters:
        pseudo = sigma_filter.as_rule()
        for rule_id in sigma_filter.rule_ids:
            filters_by_rule.setdefault(rule_id, []).append((sigma_filter, pseudo))
    # The logsource pre-filter's inputs are per rule, so read them once rather than per event.
    pipeline = windows_pipeline()
    linux = linux_pipeline()
    prepared = [
        (
            rule,
            rule.logsource.get("product", "").lower(),
            *pipeline.routes_for(rule),
            *linux.routes_for(rule),
        )
        for rule in rules
    ]

    tree = ProcessTree()
    correlator = (
        Correlator(correlations, {r.id: r for r in rules}, rule_applies) if correlations else None
    )
    for event in events:
        outcome.events_scanned += 1
        # Process lineage (B4 lever c): a process start gains its parent's details from an
        # earlier start in this scan, only where it lacks them, before any rule reads it.
        tree.observe(event)
        if correlator is not None:
            correlator.observe(event)
        is_windows = event.platform == "windows"
        event_id = event.fields.get("EventID")
        channel = event_channel(event) if is_windows else None
        kind = linux.kind(event) if event.platform == "linux" else ""
        for rule, product, channels, routes, kinds, kind_routes in prepared:
            if rule.id in retired or (product and product != event.platform):
                continue
            if is_windows:
                if (channels is not None or routes is not None) and not pipeline.admits_with(
                    channels, routes, channel, event_id
                ):
                    continue
            elif (kinds is not None or kind_routes is not None) and not linux.admits_with(
                kinds, kind_routes, kind, event_id
            ):
                continue
            try:
                result = match(rule, event)
            except UnsupportedRuleError as exc:
                outcome.unsupported_rules[rule.id] = str(exc)
                retired.add(rule.id)
                continue
            except Exception as exc:  # record the failure and keep scanning
                logger.warning("rule %s (%s) failed: %s", rule.id, rule.title, exc)
                outcome.rule_errors[rule.id] = str(exc)
                retired.add(rule.id)
                continue
            if not result.matched:
                if result.outside_source:
                    outcome.outside_source[rule.id] = outcome.outside_source.get(rule.id, 0) + 1
                elif result.missing_fields:
                    outcome.not_evaluable[rule.id] = outcome.not_evaluable.get(rule.id, 0) + 1
                    for name in result.missing_fields:
                        fields_seen = outcome.not_evaluable_fields
                        fields_seen[name] = fields_seen.get(name, 0) + 1
                continue
            if rule.id in filters_by_rule and _suppressed(
                rule, event, filters_by_rule[rule.id], outcome
            ):
                continue
            if rule.id not in technique_cache:
                resolved, unresolved = resolve_techniques(rule.technique_ids(), attack_lookup)
                technique_cache[rule.id] = resolved
                for technique_id in unresolved:
                    if technique_id not in unresolved_seen:
                        unresolved_seen.add(technique_id)
                        outcome.unresolved_techniques.append(technique_id)
            outcome.detections.append(
                Detection(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    level=rule.level,
                    event=event,
                    matched_fields=result.matched_fields,
                    techniques=technique_cache[rule.id],
                )
            )
    outcome.lineage_enriched = tree.enriched
    if correlator is not None:
        outcome.correlation = correlator.finish()
    return outcome
