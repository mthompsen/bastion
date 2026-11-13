"""Metric definitions (START_PROMPT section 4). Only these names appear in outputs.

Every rate is a :class:`Rate`: numerator, denominator, basis name, corpus,
split, pins, and a Wilson 95% interval. A percentage is never emitted on
its own. Per-technique rates with fewer than :data:`MIN_CAPTURES` captures
carry ``suppressed=True`` so renderers print counts, not a percentage.

Inputs are :class:`CaptureOutcome` records produced by the runner: what a
capture was labelled, what fired on it, and how much was scanned. Nothing
here touches the matcher; these are pure aggregations over outcomes.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from bastion.attack import AttackData
from bastion.coverage import host_relevant, telemetry_readable
from bastion.models import SigmaRule, TechniqueRef

MIN_CAPTURES = 5
"""Below this many captures a per-technique percentage is suppressed."""

HUNTING_STATUSES = frozenset({"experimental", "unsupported", "deprecated"})
"""Rule statuses that place a rule in the hunting class (contract rule 6)."""

Z95 = 1.959963984540054


def wilson(successes: int, trials: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion; ``(0, 0)`` when trials is 0."""
    if trials <= 0:
        return (0.0, 0.0)
    p = successes / trials
    denominator = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    return (max(0.0, centre - half), min(1.0, centre + half))


@dataclass
class Rate:
    """A proportion that always carries its basis."""

    name: str
    numerator: int
    denominator: int
    basis: str
    corpus: str = ""
    split: str = ""
    low: float = 0.0
    high: float = 0.0
    suppressed: bool = False
    notes: list[str] = field(default_factory=list)

    @classmethod
    def of(
        cls,
        name: str,
        numerator: int,
        denominator: int,
        basis: str,
        corpus: str = "",
        split: str = "",
        min_n: int = 0,
        notes: Sequence[str] = (),
    ) -> Rate:
        low, high = wilson(numerator, denominator)
        return cls(
            name,
            numerator,
            denominator,
            basis,
            corpus,
            split,
            low,
            high,
            suppressed=denominator < min_n,
            notes=list(notes),
        )

    @property
    def ratio(self) -> float | None:
        return self.numerator / self.denominator if self.denominator else None

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["ratio"] = self.ratio
        return data

    def text(self) -> str:
        """``k of n (p%, 95% CI a to b) [basis]``, or counts only when suppressed."""
        head = f"{self.numerator} of {self.denominator}"
        if self.denominator == 0:
            return f"{head} (no captures) [{self.basis}]"
        if self.suppressed:
            return (
                f"{head} (percentage suppressed, fewer than {MIN_CAPTURES} captures) [{self.basis}]"
            )
        ratio = self.ratio or 0.0
        return f"{head} ({ratio:.1%}, 95% CI {self.low:.1%} to {self.high:.1%}) [{self.basis}]"


@dataclass
class Fired:
    """One rule that fired on a capture, with how many events it matched."""

    rule_id: str
    title: str
    level: str
    hunting: bool
    techniques: list[str]
    count: int
    #: the rule is in the SigmaHQ emerging-threats tree: its own reported class, outside the
    #: headline (B4 lever d, Mason's decision); defaults False for runs that predate it
    emerging: bool = False


@dataclass
class CaptureOutcome:
    """What the engine produced on one capture; the runner writes one per capture."""

    capture_id: str
    corpus: str
    kind: str
    split: str
    platform: str
    techniques: list[str]
    raw_labels: list[str]
    host: str
    events_scanned: int
    fired: list[Fired]
    first_ts: str | None = None
    last_ts: str | None = None
    unsupported_rules: int = 0
    rule_errors: int = 0
    expected_matches: dict[str, int | None] = field(default_factory=dict)
    notes: dict[str, str] = field(default_factory=dict)
    skipped: str | None = None
    #: rule id -> detections suppressed by filter documents on this capture
    filtered: dict[str, int] = field(default_factory=dict)
    #: rule id -> events on which the rule was not_evaluable (tri-state, B2 lever d)
    not_evaluable: dict[str, int] = field(default_factory=dict)
    #: missing field -> rule-event pairs it left undecided on this capture
    not_evaluable_fields: dict[str, int] = field(default_factory=dict)
    #: rule id -> events carrying none of the rule's fields (logsource not routed)
    outside_source: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> CaptureOutcome:
        data = dict(raw)
        data["fired"] = [Fired(**f) for f in data.get("fired", [])]
        return cls(**data)


def is_hunting(rule: SigmaRule) -> bool:
    """Contract rule 6: experimental, unsupported, deprecated, or the threat-hunting tree."""
    return rule.status in HUNTING_STATUSES or "rules-threat-hunting" in rule.file_path.replace(
        "\\", "/"
    )


def is_emerging(rule: SigmaRule) -> bool:
    """The SigmaHQ emerging-threats tree: a class of its own, reported outside the headline."""
    return "rules-emerging-threats" in rule.file_path.replace("\\", "/")


def is_alerting(rule: SigmaRule) -> bool:
    """The headline class: neither hunting nor emerging threats."""
    return not is_hunting(rule) and not is_emerging(rule)


# --- technique matching -------------------------------------------------------------------


def _parent(technique_id: str) -> str:
    return technique_id.split(".", 1)[0]


def tagged_to(rule_techniques: Iterable[str], label: str) -> bool:
    """Does a rule's tag set claim ``label``? Exact, or parent and sub-technique of each other.

    A capture labelled with a parent technique is detected by a rule tagged
    with one of its sub-techniques, and a capture labelled with a
    sub-technique is detected by a rule tagged at the parent level. Both
    directions are counted and the hierarchical hits are reported
    separately by :func:`detection_rates`.
    """
    label = label.upper()
    for tag in rule_techniques:
        tag = tag.upper()
        if tag == label or _parent(tag) == label or _parent(label) == tag:
            return True
    return False


def _alerting(outcome: CaptureOutcome, include_emerging: bool = False) -> list[Fired]:
    """Fired rules of the headline class; with ``include_emerging``, emerging threats too."""
    return [f for f in outcome.fired if not f.hunting and (include_emerging or not f.emerging)]


def _hit(outcome: CaptureOutcome, include_emerging: bool = False) -> tuple[bool, bool]:
    """``(parent_aware, strict)``: detected under the headline definition, and under exact tags.

    Parent-aware (the headline, Mason's decision B1-2) counts a rule tagged to the label or to
    its parent or sub-technique in either direction; sibling sub-techniques do not count.
    Strict counts exact tag matches only and is reported beside the headline everywhere.
    """
    exact = False
    hierarchical = False
    for fired in _alerting(outcome, include_emerging):
        tags = {t.upper() for t in fired.techniques}
        for label in outcome.techniques:
            if label.upper() in tags:
                exact = True
            elif tagged_to(tags, label):
                hierarchical = True
    return (exact or hierarchical, exact)


# --- section 4 metrics --------------------------------------------------------------------


def labelled_positives(outcomes: Iterable[CaptureOutcome], split: str) -> list[CaptureOutcome]:
    return [
        o
        for o in outcomes
        if o.kind == "positive" and o.techniques and o.skipped is None and o.split == split
    ]


@dataclass
class DetectionRates:
    overall: Rate
    strict: Rate
    any_alert: Rate
    per_technique: dict[str, Rate]
    per_tactic: dict[str, Rate]
    hierarchical_hits: int
    captures: int


def detection_rates(
    outcomes: Iterable[CaptureOutcome],
    attack: AttackData,
    split: str,
    pins_label: str,
    include_emerging: bool = False,
) -> DetectionRates:
    """Detection rate (technique recall) and any-alert rate over labelled positives.

    The headline counts the alerting class only. ``include_emerging`` adds the emerging-threats
    class, for the separately reported rate that is never the headline.
    """
    positives = labelled_positives(outcomes, split)
    basis = f"labelled positive captures, {split} split, {pins_label}"
    hits = 0
    strict_hits = 0
    any_alert = 0
    hierarchical = 0
    per_technique_hits: Counter[str] = Counter()
    per_technique_total: Counter[str] = Counter()
    per_tactic_hits: Counter[str] = Counter()
    per_tactic_total: Counter[str] = Counter()
    for outcome in positives:
        detected, strict = _hit(outcome, include_emerging)
        hits += int(detected)
        strict_hits += int(strict)
        hierarchical += int(detected and not strict)
        any_alert += int(bool(_alerting(outcome, include_emerging)))
        tactics: set[str] = set()
        for technique in outcome.techniques:
            per_technique_total[technique] += 1
            per_technique_hits[technique] += int(detected)
            ref = attack.techniques.get(technique)
            tactics.update(ref.tactics if ref else ["unknown"])
        for tactic in tactics:
            per_tactic_total[tactic] += 1
            per_tactic_hits[tactic] += int(detected)
    per_technique = {
        t: Rate.of(
            "detection_rate",
            per_technique_hits[t],
            n,
            f"captures labelled {t}, {split} split",
            split=split,
            min_n=MIN_CAPTURES,
        )
        for t, n in sorted(per_technique_total.items())
    }
    per_tactic = {
        t: Rate.of(
            "detection_rate",
            per_tactic_hits[t],
            n,
            f"captures whose technique is in {t}, {split} split",
            split=split,
            min_n=MIN_CAPTURES,
        )
        for t, n in sorted(per_tactic_total.items())
    }
    return DetectionRates(
        overall=Rate.of("detection_rate", hits, len(positives), basis, split=split),
        strict=Rate.of(
            "detection_rate_strict",
            strict_hits,
            len(positives),
            basis + ", exact tag match only",
            split=split,
        ),
        any_alert=Rate.of("any_alert_rate", any_alert, len(positives), basis, split=split),
        per_technique=per_technique,
        per_tactic=per_tactic,
        hierarchical_hits=hierarchical,
        captures=len(positives),
    )


@dataclass
class ValidatedCoverage:
    over_labelled: Rate
    over_matrix: Rate
    strict_over_labelled: Rate
    validated: set[str]
    validated_strict: set[str]


def validated_coverage(
    outcomes: Iterable[CaptureOutcome], attack: AttackData, split: str, pins_label: str
) -> ValidatedCoverage:
    """Techniques with a detected labelled capture, over techniques with any labelled capture.

    The headline uses parent-aware detection; the strict variant (exact tags) is beside it.
    """
    labelled: set[str] = set()
    validated: set[str] = set()
    validated_strict: set[str] = set()
    for outcome in labelled_positives(outcomes, split):
        detected, strict = _hit(outcome)
        for technique in outcome.techniques:
            labelled.add(technique)
            if detected:
                validated.add(technique)
            if strict:
                validated_strict.add(technique)
    basis = f"techniques with at least one labelled positive capture, {split} split, {pins_label}"
    return ValidatedCoverage(
        over_labelled=Rate.of(
            "validated_coverage", len(validated), len(labelled), basis, split=split
        ),
        over_matrix=Rate.of(
            "validated_coverage",
            len(validated),
            len(attack.techniques),
            f"full enterprise matrix, ATT&CK {attack.version}",
            split=split,
        ),
        strict_over_labelled=Rate.of(
            "validated_coverage_strict",
            len(validated_strict),
            len(labelled),
            basis + ", exact tag match only",
            split=split,
        ),
        validated=validated,
        validated_strict=validated_strict,
    )


def claimed_coverage(
    rules: Sequence[SigmaRule], attack: AttackData, evaluable: Mapping[str, bool]
) -> dict[str, Rate]:
    """Claimed and telemetry-feasible coverage per section 4 (full matrix, Windows, Linux)."""
    alerting = [r for r in rules if evaluable.get(r.id + r.file_path, True) and is_alerting(r)]
    feasible = [r for r in alerting if _feasible(r)]
    out: dict[str, Rate] = {}
    for label, subset in (
        ("claimed_coverage", alerting),
        ("telemetry_feasible_coverage", feasible),
    ):
        out[f"{label}:enterprise"] = _coverage_rate(label, subset, attack, None)
        out[f"{label}:windows"] = _coverage_rate(label, subset, attack, "windows")
        out[f"{label}:linux"] = _coverage_rate(label, subset, attack, "linux")
    hunting = [r for r in rules if is_hunting(r)]
    out["hunting_class:enterprise"] = _coverage_rate("hunting_class", hunting, attack, None)
    emerging = [r for r in rules if is_emerging(r) and not is_hunting(r)]
    out["emerging_class:enterprise"] = _coverage_rate("emerging_class", emerging, attack, None)
    return out


_LINUX_TEXT_SERVICES = frozenset(
    {
        "auth",
        "sshd",
        "sudo",
        "syslog",
        "cron",
        "pam",
        "su",
        "vsftpd",
        "guacamole",
        "modsecurity",
        "clamav",
    }
)
_LINUX_AUDIT_CATEGORIES = frozenset(
    {
        "process_creation",
        "network_connection",
        "file_event",
        "file_delete",
        "file_rename",
        "file_change",
        "file_access",
    }
)


def _feasible(rule: SigmaRule) -> bool:
    """Can a source Bastion reads satisfy the rule's logsource? Logsource-level estimate."""
    logsource = {k.lower(): str(v).lower() for k, v in rule.logsource.items()}
    product = logsource.get("product", "")
    category = logsource.get("category", "")
    service = logsource.get("service", "")
    if product == "windows":
        return True
    if product == "linux":
        if category in _LINUX_AUDIT_CATEGORIES or service == "auditd":
            return True  # auditd ingestion exists since 7f83020
        return service in _LINUX_TEXT_SERVICES or (category == "" and service == "")
    return False


def _coverage_rate(
    name: str, rules: Sequence[SigmaRule], attack: AttackData, platform: str | None
) -> Rate:
    techniques: dict[str, TechniqueRef] = {
        tid: ref
        for tid, ref in attack.techniques.items()
        if platform is None or platform in {p.lower() for p in ref.platforms}
    }
    subset = (
        rules
        if platform is None
        else [r for r in rules if r.logsource.get("product", "").lower() in {platform, ""}]
    )
    tagged = {t.upper() for r in subset for t in r.technique_ids()}
    covered = len(tagged & set(techniques))
    scope = "full enterprise matrix" if platform is None else f"techniques listing {platform}"
    return Rate.of(
        name,
        covered,
        len(techniques),
        f"{scope}, ATT&CK {attack.version}, {len(subset)} rules",
        notes=[f"{len(subset)} rules in scope"],
    )


def blind_spot_split(rules: Sequence[SigmaRule], attack: AttackData) -> dict[str, int]:
    """The three-way uncovered split for the alerting class, reusing coverage.py's classifiers."""
    tagged = {t.upper() for r in rules if is_alerting(r) for t in r.technique_ids()}
    uncovered = [ref for tid, ref in attack.techniques.items() if tid not in tagged]
    on_host = [ref for ref in uncovered if host_relevant(ref)]
    writable = [ref for ref in on_host if telemetry_readable(ref)]
    return {
        "uncovered": len(uncovered),
        "beyond_host": len(uncovered) - len(on_host),
        "beyond_telemetry": len(on_host) - len(writable),
        "writable_gaps": len(writable),
    }


@dataclass
class RegressionSummary:
    #: headline: SigmaHQ's own runner criterion, at least the expected number of matches
    passed: Rate
    #: Bastion's strict criterion, exactly the expected number, reported beside the headline
    passed_strict: Rate
    #: cases that passed the headline with more matches than expected (SigmaHQ warns on these)
    more_than_expected: int
    failed: int
    skipped_by_reason: dict[str, int]
    failures: list[dict[str, Any]]
    over_count: list[dict[str, Any]]
    by_logsource: dict[str, dict[str, int]]


def regression_pass_rate(
    outcomes: Iterable[CaptureOutcome],
    skipped: Mapping[str, int],
    rules_by_id: Mapping[str, SigmaRule],
    pins_label: str,
) -> RegressionSummary:
    """Regression pass rates under SigmaHQ's criterion (headline) and Bastion's strict one.

    SigmaHQ's runner passes a case when at least ``match_count`` matches are produced (at
    least one when the count is omitted) and warns when there are more; that is the headline
    (Mason's decision B1-1). The strict rate requires the exact count and is reported beside it.
    """
    passed = 0
    passed_strict = 0
    failures: list[dict[str, Any]] = []
    over_count: list[dict[str, Any]] = []
    by_logsource: dict[str, dict[str, int]] = defaultdict(lambda: {"passed": 0, "failed": 0})
    evaluable = [o for o in outcomes if o.kind == "regression" and o.skipped is None]
    for outcome in evaluable:
        for rule_id, expected in outcome.expected_matches.items():
            actual = sum(f.count for f in outcome.fired if f.rule_id == rule_id)
            ok = actual >= 1 if expected is None else actual >= expected
            strict = actual >= 1 if expected is None else actual == expected
            passed_strict += int(strict)
            rule = rules_by_id.get(rule_id)
            key = (
                "/".join(
                    v
                    for v in (
                        rule.logsource.get("product", "") if rule else "",
                        rule.logsource.get("category", "") if rule else "",
                        rule.logsource.get("service", "") if rule else "",
                    )
                    if v
                )
                or "unknown"
            )
            by_logsource[key]["passed" if ok else "failed"] += 1
            record = {
                "capture": outcome.capture_id,
                "rule_id": rule_id,
                "rule_title": rule.title if rule else outcome.notes.get("rule_title", ""),
                "logsource": key,
                "expected": expected,
                "actual": actual,
                "events": outcome.events_scanned,
            }
            if ok:
                passed += 1
                if not strict:
                    over_count.append(record)
            else:
                failures.append(record)
    total = len(evaluable)
    skipped_total = sum(skipped.values())
    basis = f"evaluable SigmaHQ regression_data EVTX cases ({skipped_total} skipped), {pins_label}"
    return RegressionSummary(
        passed=Rate.of(
            "regression_pass_rate",
            passed,
            total,
            basis + ", SigmaHQ criterion: at least the expected matches",
            corpus="regression_data",
        ),
        passed_strict=Rate.of(
            "regression_pass_rate_strict",
            passed_strict,
            total,
            basis + ", strict: exactly the expected matches",
            corpus="regression_data",
        ),
        more_than_expected=len(over_count),
        failed=total - passed,
        skipped_by_reason=dict(sorted(skipped.items())),
        failures=failures,
        over_count=over_count,
        by_logsource=dict(sorted(by_logsource.items())),
    )


@dataclass
class BenignVolume:
    host_days: float
    hosts: int
    events: int
    alerts: int
    alerts_medium_plus: int
    per_host_day: float | None
    per_host_day_medium_plus: float | None
    per_rule: list[dict[str, Any]]
    budget: float
    within_budget: bool | None
    notes: list[str]
    evaluated_rule_ids: list[str]
    #: the emerging-threats class, outside the budget figure and reported beside it
    alerts_emerging: int = 0
    alerts_emerging_medium_plus: int = 0
    per_host_day_emerging: float | None = None
    per_host_day_emerging_medium_plus: float | None = None


def benign_volume(
    outcomes: Iterable[CaptureOutcome],
    known_fps: Mapping[str, Sequence[str]],
    budget: float,
    evaluated_rule_ids: Iterable[str],
    corpus: str | None = None,
) -> BenignVolume:
    """Alerts per host per day on goodware, overall and per rule, medium-and-above separated.

    Host-days come from the min and max event timestamps actually scanned per
    host. A host whose scanned span is under one hour is floored to one hour
    and noted, since a rate over a few seconds would be meaningless.
    """
    benign = [
        o
        for o in outcomes
        if o.kind == "benign" and o.skipped is None and (corpus is None or o.corpus == corpus)
    ]
    spans: dict[str, tuple[datetime, datetime]] = {}
    for outcome in benign:
        if outcome.first_ts and outcome.last_ts:
            first, last = (
                datetime.fromisoformat(outcome.first_ts),
                datetime.fromisoformat(outcome.last_ts),
            )
            if outcome.host in spans:
                lo, hi = spans[outcome.host]
                spans[outcome.host] = (min(lo, first), max(hi, last))
            else:
                spans[outcome.host] = (first, last)
    notes: list[str] = []
    host_days = 0.0
    for host, (lo, hi) in spans.items():
        days = (hi - lo).total_seconds() / 86400
        if days < 1 / 24:
            notes.append(f"{host}: scanned span under one hour, floored to one hour")
            days = 1 / 24
        host_days += days
    per_rule_counter: dict[str, dict[str, Any]] = {}
    alerts = 0
    medium_plus = 0
    emerging = 0
    emerging_medium_plus = 0
    for outcome in benign:
        for fired in outcome.fired:
            if fired.hunting:
                continue
            is_medium_plus = fired.level in {"medium", "high", "critical"}
            if fired.emerging:
                emerging += fired.count
                emerging_medium_plus += fired.count if is_medium_plus else 0
                continue
            alerts += fired.count
            medium_plus += fired.count if is_medium_plus else 0
            entry = per_rule_counter.setdefault(
                fired.rule_id,
                {
                    "rule_id": fired.rule_id,
                    "title": fired.title,
                    "level": fired.level,
                    "alerts": 0,
                    "hosts": set(),
                    "known_fp": fired.rule_id in known_fps,
                },
            )
            entry["alerts"] += fired.count
            entry["hosts"].add(outcome.host)
    per_rule = []
    for entry in sorted(per_rule_counter.values(), key=lambda e: (-e["alerts"], e["rule_id"])):
        entry["hosts"] = sorted(entry["hosts"])
        entry["per_host_day"] = entry["alerts"] / host_days if host_days else None
        per_rule.append(entry)
    rate = alerts / host_days if host_days else None
    rate_medium = medium_plus / host_days if host_days else None
    return BenignVolume(
        host_days=host_days,
        hosts=len(spans),
        events=sum(o.events_scanned for o in benign),
        alerts=alerts,
        alerts_medium_plus=medium_plus,
        per_host_day=rate,
        per_host_day_medium_plus=rate_medium,
        per_rule=per_rule,
        budget=budget,
        within_budget=None if rate is None else rate <= budget,
        notes=notes,
        evaluated_rule_ids=sorted(set(evaluated_rule_ids)),
        alerts_emerging=emerging,
        alerts_emerging_medium_plus=emerging_medium_plus,
        per_host_day_emerging=emerging / host_days if host_days else None,
        per_host_day_emerging_medium_plus=emerging_medium_plus / host_days if host_days else None,
    )


def cross_firing(outcomes: Iterable[CaptureOutcome], split: str) -> dict[str, Any]:
    """Rules that fired on labelled captures but are tagged to a different technique."""
    offenders: Counter[str] = Counter()
    titles: dict[str, str] = {}
    captures_with_cross = 0
    total_cross = 0
    for outcome in labelled_positives(outcomes, split):
        crossed = False
        for fired in _alerting(outcome):
            if fired.techniques and not any(
                tagged_to(fired.techniques, t) for t in outcome.techniques
            ):
                offenders[fired.rule_id] += fired.count
                titles[fired.rule_id] = fired.title
                total_cross += fired.count
                crossed = True
        captures_with_cross += int(crossed)
    return {
        "captures_with_cross_firing": captures_with_cross,
        "cross_fired_alerts": total_cross,
        "top_offenders": [
            {"rule_id": rid, "title": titles[rid], "alerts": n}
            for rid, n in offenders.most_common(15)
        ],
    }


def not_evaluable_summary(
    outcomes: Sequence[CaptureOutcome], rules_by_id: Mapping[str, SigmaRule]
) -> dict[str, Any]:
    """Tri-state disclosure: rule-event pairs that were not_evaluable, by reason and corpus.

    Contract rule 3: a pair whose answer depends on a field the event's source lacks is
    never counted as a no_match, and never as coverage. The per-split figure says how many
    labelled captures the headline missed while an alerting rule tagged to the label could
    not be evaluated on at least one of their events; those misses are not rule misses.
    """
    by_kind: Counter[str] = Counter()
    by_field: Counter[str] = Counter()
    by_rule: Counter[str] = Counter()
    outside: Counter[str] = Counter()
    for outcome in outcomes:
        outside.update(outcome.outside_source)
        pairs = sum(outcome.not_evaluable.values())
        by_kind[outcome.kind] += pairs
        by_field.update(outcome.not_evaluable_fields)
        by_rule.update(outcome.not_evaluable)
    alerting_rules = {
        rid for rid in by_rule if rid in rules_by_id and is_alerting(rules_by_id[rid])
    }
    per_split: dict[str, Any] = {}
    for split in ("test", "dev"):
        missed_undecided = 0
        examples: list[str] = []
        for outcome in labelled_positives(outcomes, split):
            if _hit(outcome)[0]:
                continue
            undecided = [
                rid
                for rid in outcome.not_evaluable
                if rid in alerting_rules
                and any(tagged_to(rules_by_id[rid].technique_ids(), t) for t in outcome.techniques)
            ]
            if undecided:
                missed_undecided += 1
                if len(examples) < 10:
                    examples.append(outcome.capture_id)
        per_split[split] = {
            "undetected_with_tagged_rule_not_evaluable": missed_undecided,
            "examples": examples,
        }
    return {
        "rule_event_pairs": sum(by_kind.values()),
        "rule_event_pairs_by_capture_kind": dict(sorted(by_kind.items())),
        "rules_not_evaluable_at_least_once": len(by_rule),
        "alerting_rules_not_evaluable_at_least_once": len(alerting_rules),
        "by_missing_field": dict(by_field.most_common(25)),
        "top_rules": [
            {
                "rule_id": rid,
                "title": rules_by_id[rid].title if rid in rules_by_id else "",
                "pairs": n,
            }
            for rid, n in by_rule.most_common(15)
        ],
        "labelled": per_split,
        "outside_source_pairs": sum(outside.values()),
        "outside_source_rules": len(outside),
        "outside_source_by_logsource": _by_logsource(outside, rules_by_id),
    }


def _by_logsource(
    counts: Mapping[str, int], rules_by_id: Mapping[str, SigmaRule]
) -> dict[str, int]:
    grouped: Counter[str] = Counter()
    for rule_id, pairs in counts.items():
        rule = rules_by_id.get(rule_id)
        source = rule.logsource if rule is not None else {}
        key = "/".join(source.get(k, "") for k in ("product", "category", "service"))
        grouped[key] += pairs
    return dict(grouped.most_common(15))


LADDER = ("held-out-proven", "sample-proven", "fixture-proven", "rule-only", "none")


def evidence_ladder(
    outcomes: Iterable[CaptureOutcome], rules: Sequence[SigmaRule], attack: AttackData
) -> dict[str, str]:
    """Strongest evidence any alerting rule has per technique, for every enterprise technique."""
    ladder: dict[str, str] = {}
    rule_only = {t.upper() for r in rules if is_alerting(r) for t in r.technique_ids()}
    for technique in attack.techniques:
        ladder[technique] = "rule-only" if technique in rule_only else "none"
    strength = {name: index for index, name in enumerate(LADDER)}

    def raise_to(technique: str, level: str) -> None:
        if technique in ladder and strength[level] < strength[ladder[technique]]:
            ladder[technique] = level

    for outcome in outcomes:
        if outcome.skipped is not None or not outcome.techniques:
            continue
        detected, _ = _hit(outcome)
        if not detected:
            continue
        if outcome.kind == "fixture":
            level = "fixture-proven"
        elif outcome.kind == "positive" and outcome.split == "test":
            level = "held-out-proven"
        elif outcome.kind == "positive":
            level = "sample-proven"
        else:
            continue
        for technique in outcome.techniques:
            raise_to(technique, level)
    return ladder


def ladder_distribution(ladder: Mapping[str, str]) -> dict[str, int]:
    counts = Counter(ladder.values())
    return {level: counts.get(level, 0) for level in LADDER}


def robustness(rules: Sequence[SigmaRule], scores: Mapping[str, str]) -> dict[str, Any]:
    """STP level distribution; every rule without a score is counted as unscored."""
    distribution: Counter[str] = Counter()
    for rule in rules:
        distribution[scores.get(rule.id, "unscored")] += 1
    unscored = distribution.get("unscored", 0)
    return {
        "levels": dict(sorted(distribution.items())),
        "scored": len(rules) - unscored,
        "unscored": unscored,
        "rules": len(rules),
    }
