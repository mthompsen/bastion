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

For performance, rules are pre-filtered by ``logsource``: platform first,
then (for Windows events with an ``EventID``) the Sigma event category,
so a ``registry_set`` rule is never evaluated against a process-creation
event.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from bastion.attack import resolve_techniques
from bastion.models import Detection, Event, SigmaRule, TechniqueRef
from bastion.sigma.matcher import UnsupportedRuleError, match

logger = logging.getLogger(__name__)

#: Sigma logsource categories → the Windows event ids that carry them
#: (Sysmon ids, plus the classic Security-log equivalents where common).
_CATEGORY_EVENT_IDS: dict[str, frozenset[int]] = {
    "process_creation": frozenset({1, 4688}),
    "network_connection": frozenset({3, 5156}),
    "sysmon_status": frozenset({4, 16}),
    "process_termination": frozenset({5}),
    "driver_load": frozenset({6}),
    "image_load": frozenset({7}),
    "create_remote_thread": frozenset({8}),
    "raw_access_read": frozenset({9}),
    "process_access": frozenset({10}),
    "file_event": frozenset({11}),
    "registry_add": frozenset({12}),
    "registry_delete": frozenset({12}),
    "registry_set": frozenset({13}),
    "registry_rename": frozenset({14}),
    "registry_event": frozenset({12, 13, 14}),
    "create_stream_hash": frozenset({15}),
    "pipe_created": frozenset({17, 18}),
    "wmi_event": frozenset({19, 20, 21}),
    "dns_query": frozenset({22}),
    "file_delete": frozenset({23, 26}),
    "clipboard_change": frozenset({24}),
    "process_tampering": frozenset({25}),
}


@dataclass
class ScanOutcome:
    """Everything a scan produced, including what could not be evaluated."""

    detections: list[Detection] = field(default_factory=list)
    events_scanned: int = 0
    rules_evaluated: int = 0
    unsupported_rules: dict[str, str] = field(default_factory=dict)
    rule_errors: dict[str, str] = field(default_factory=dict)
    unresolved_techniques: list[str] = field(default_factory=list)


def rule_applies(rule: SigmaRule, event: Event) -> bool:
    """logsource pre-filter: platform match, then Windows event-category match."""
    product = rule.logsource.get("product", "").lower()
    if product and product != event.platform:
        return False
    category = rule.logsource.get("category", "").lower()
    allowed_ids = _CATEGORY_EVENT_IDS.get(category)
    if allowed_ids is not None and event.platform == "windows":
        event_id = event.fields.get("EventID")
        if isinstance(event_id, int) and event_id not in allowed_ids:
            return False
    return True


def scan(
    events: Iterable[Event],
    rules: Sequence[SigmaRule],
    attack_lookup: dict[str, TechniqueRef],
) -> ScanOutcome:
    """Evaluate every applicable rule against every event."""
    outcome = ScanOutcome(rules_evaluated=len(rules))
    retired: set[str] = set()
    technique_cache: dict[str, list[TechniqueRef]] = {}
    unresolved_seen: set[str] = set()
    # The logsource pre-filter's inputs are per rule, so read them once rather than per event.
    prepared = [
        (
            rule,
            rule.logsource.get("product", "").lower(),
            _CATEGORY_EVENT_IDS.get(rule.logsource.get("category", "").lower()),
        )
        for rule in rules
    ]

    for event in events:
        outcome.events_scanned += 1
        is_windows = event.platform == "windows"
        event_id = event.fields.get("EventID")
        for rule, product, allowed_ids in prepared:
            if rule.id in retired or (product and product != event.platform):
                continue
            if (
                allowed_ids is not None
                and is_windows
                and isinstance(event_id, int)
                and event_id not in allowed_ids
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
                continue
            if rule.id not in technique_cache:
                resolved, unresolved = resolve_techniques(rule.attack_techniques, attack_lookup)
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
    return outcome
