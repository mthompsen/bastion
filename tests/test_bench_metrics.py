"""Known-answer tests for every section 4 metric."""

from __future__ import annotations

from pathlib import Path

import pytest

from bastion.attack import load_attack_data
from bastion.bench.metrics import (
    LADDER,
    MIN_CAPTURES,
    CaptureOutcome,
    Fired,
    Rate,
    benign_volume,
    blind_spot_split,
    claimed_coverage,
    cross_firing,
    detection_rates,
    evidence_ladder,
    is_hunting,
    ladder_distribution,
    regression_pass_rate,
    robustness,
    tagged_to,
    validated_coverage,
    wilson,
)
from bastion.models import SigmaRule
from bastion.sigma.loader import load_rules

FIXTURES = Path(__file__).parent / "fixtures"
ATTACK = load_attack_data(FIXTURES / "mini_attack.json")
RULES = load_rules(FIXTURES / "rules")


def test_wilson_known_values() -> None:
    assert wilson(0, 0) == (0.0, 0.0)
    low, high = wilson(5, 10)
    assert round(low, 3) == 0.237 and round(high, 3) == 0.763
    low, high = wilson(10, 10)
    assert round(low, 3) == 0.722 and round(high, 3) == 1.0
    low, high = wilson(0, 10)
    assert low == 0.0 and round(high, 3) == 0.278


def test_rate_text_and_dict() -> None:
    rate = Rate.of("r", 3, 4, "basis", min_n=MIN_CAPTURES)
    assert rate.suppressed and "suppressed" in rate.text()
    full = Rate.of("r", 3, 4, "basis")
    assert full.text().startswith("3 of 4 (75.0%, 95% CI ")
    assert full.as_dict()["ratio"] == 0.75
    empty = Rate.of("r", 0, 0, "basis")
    assert "no captures" in empty.text() and empty.ratio is None


def test_tagged_to_exact_and_hierarchical() -> None:
    assert tagged_to(["T1059.001"], "T1059.001")
    assert tagged_to(["T1059.001"], "T1059")  # sub-technique rule, parent label
    assert tagged_to(["T1059"], "T1059.001")  # parent rule, sub-technique label
    assert not tagged_to(["T1110"], "T1059")
    assert not tagged_to([], "T1059")


def _fired(
    rule_id: str, techniques: list[str], hunting: bool = False, count: int = 1, level: str = "high"
) -> Fired:
    return Fired(rule_id, f"title {rule_id}", level, hunting, techniques, count)


def _outcome(
    cid: str,
    techniques: list[str],
    fired: list[Fired],
    split: str = "test",
    kind: str = "positive",
    events: int = 10,
    corpus: str = "c",
    host: str = "h",
    first: str | None = None,
    last: str | None = None,
    expected: dict[str, int | None] | None = None,
    skipped: str | None = None,
) -> CaptureOutcome:
    return CaptureOutcome(
        cid,
        corpus,
        kind,
        split,
        "windows",
        techniques,
        list(techniques),
        host,
        events,
        fired,
        first_ts=first,
        last_ts=last,
        expected_matches=expected or {},
        skipped=skipped,
    )


OUTCOMES = [
    _outcome("exact", ["T1059.001"], [_fired("a", ["T1059.001"])]),
    _outcome("hier", ["T1059"], [_fired("b", ["T1059.001"])]),
    _outcome("cross", ["T1110"], [_fired("c", ["T1059"]), _fired("h", ["T1110"], hunting=True)]),
    _outcome("silent", ["T1110"], []),
    _outcome("dev-hit", ["T1110"], [_fired("d", ["T1110"])], split="dev"),
    _outcome("unlab", [], [_fired("e", ["T1059"])], split="unlabelled"),
    _outcome("skip", ["T1110"], [], skipped="boom"),
]


def test_detection_rates_strict_hierarchy_and_any_alert() -> None:
    rates = detection_rates(OUTCOMES, ATTACK, "test", "pins")
    assert rates.captures == 4
    assert (rates.overall.numerator, rates.overall.denominator) == (2, 4)
    assert rates.hierarchical_hits == 1
    assert (rates.any_alert.numerator, rates.any_alert.denominator) == (3, 4)
    assert rates.per_technique["T1110"].numerator == 0
    assert rates.per_technique["T1110"].denominator == 2
    assert rates.per_technique["T1110"].suppressed  # under MIN_CAPTURES
    assert rates.per_tactic["execution"].numerator == 2
    assert rates.per_tactic["credential-access"].denominator == 2
    dev = detection_rates(OUTCOMES, ATTACK, "dev", "pins")
    assert (dev.overall.numerator, dev.overall.denominator) == (1, 1)


def test_validated_coverage_denominators() -> None:
    over_labelled, over_matrix, validated = validated_coverage(OUTCOMES, ATTACK, "test", "pins")
    assert validated == {"T1059.001", "T1059"}
    assert (over_labelled.numerator, over_labelled.denominator) == (2, 3)
    assert over_matrix.denominator == len(ATTACK.techniques)


def test_claimed_and_feasible_coverage_and_blind_spots() -> None:
    evaluable = {r.id + r.file_path: True for r in RULES}
    rates = claimed_coverage(RULES, ATTACK, evaluable)
    enterprise = rates["claimed_coverage:enterprise"]
    assert (enterprise.numerator, enterprise.denominator) == (2, 3)  # T1059.001 and T1110 of 3
    assert rates["claimed_coverage:windows"].denominator == 3
    assert rates["claimed_coverage:linux"].numerator == 1  # only the linux rule counts on linux
    assert rates["telemetry_feasible_coverage:enterprise"].numerator == 2
    assert rates["hunting_class:enterprise"].numerator == 0
    # Marking the windows rule non-evaluable removes its technique from the claim.
    windows_rule = next(r for r in RULES if r.logsource.get("product") == "windows")
    evaluable[windows_rule.id + windows_rule.file_path] = False
    assert claimed_coverage(RULES, ATTACK, evaluable)["claimed_coverage:enterprise"].numerator == 1
    gaps = blind_spot_split(RULES, ATTACK)
    assert (
        gaps["uncovered"] == 1
        and gaps["writable_gaps"] + gaps["beyond_telemetry"] + gaps["beyond_host"] == 1
    )


def test_feasibility_estimate_by_logsource() -> None:
    def rule(**logsource: str) -> SigmaRule:
        return SigmaRule(id="x", title="x", logsource=logsource, attack_techniques=["T1110"])

    def claimed(r: SigmaRule) -> int:
        return claimed_coverage([r], ATTACK, {"x": True})[
            "telemetry_feasible_coverage:enterprise"
        ].numerator

    assert claimed(rule(product="windows", service="powershell")) == 1
    assert claimed(rule(product="linux", category="process_creation")) == 1
    assert claimed(rule(product="linux", service="sshd")) == 1
    assert claimed(rule(product="linux")) == 1
    assert claimed(rule(product="linux", service="unknown-daemon")) == 0
    assert claimed(rule(product="aws", service="cloudtrail")) == 0


def test_is_hunting_by_status_and_tree() -> None:
    assert is_hunting(SigmaRule(id="a", title="a", status="experimental"))
    assert is_hunting(SigmaRule(id="b", title="b", file_path="x/rules-threat-hunting/y.yml"))
    assert not is_hunting(SigmaRule(id="c", title="c", status="test", file_path="rules/y.yml"))


def test_regression_pass_rate_counts_exact_and_at_least_one() -> None:
    by_id = {r.id: r for r in RULES}
    win = next(r for r in RULES if r.logsource.get("product") == "windows")
    outcomes = [
        _outcome("r1", [], [_fired(win.id, [])], kind="regression", expected={win.id: 1}),
        _outcome("r2", [], [_fired(win.id, [], count=3)], kind="regression", expected={win.id: 1}),
        _outcome(
            "r3", [], [_fired(win.id, [], count=2)], kind="regression", expected={win.id: None}
        ),
        _outcome("r4", [], [], kind="regression", expected={"unknown-rule": None}),
        _outcome("r5", [], [], kind="regression", expected={win.id: 1}, skipped="broken"),
    ]
    summary = regression_pass_rate(outcomes, {"json": 2}, by_id, "pins")
    assert (summary.passed.numerator, summary.passed.denominator) == (2, 4)
    assert summary.failed == 2
    assert summary.skipped_by_reason == {"json": 2}
    assert summary.by_logsource["windows/process_creation"] == {"passed": 2, "failed": 1}
    assert summary.by_logsource["unknown"] == {"passed": 0, "failed": 1}
    assert {f["rule_id"] for f in summary.failures} == {win.id, "unknown-rule"}
    assert "2 skipped" in summary.passed.basis


def test_benign_volume_host_days_budget_and_known_fps() -> None:
    outcomes = [
        _outcome(
            "b1",
            [],
            [_fired("noisy", [], level="medium", count=30), _fired("h", [], hunting=True, count=5)],
            kind="benign",
            host="host-a",
            first="2026-01-01T00:00:00+00:00",
            last="2026-01-03T00:00:00+00:00",
            corpus="evtx_baseline",
        ),
        _outcome(
            "b2",
            [],
            [_fired("quiet", [], level="low", count=2)],
            kind="benign",
            host="host-a",
            first="2026-01-02T00:00:00+00:00",
            last="2026-01-04T00:00:00+00:00",
            corpus="evtx_baseline",
        ),
        _outcome(
            "b3",
            [],
            [_fired("quiet", [], level="low", count=1)],
            kind="benign",
            host="host-b",
            first="2026-02-01T00:00:00+00:00",
            last="2026-02-01T00:00:30+00:00",
            corpus="evtx_baseline",
        ),
        _outcome(
            "other",
            [],
            [_fired("x", [], count=99)],
            kind="benign",
            host="lab",
            corpus="citadel_captures",
        ),
    ]
    volume = benign_volume(
        outcomes,
        {"noisy": [".*"]},
        budget=20.0,
        evaluated_rule_ids=["quiet", "noisy", "silent"],
        corpus="evtx_baseline",
    )
    assert volume.hosts == 2
    assert volume.host_days == pytest.approx(3 + 1 / 24)
    assert volume.alerts == 33 and volume.alerts_medium_plus == 30
    assert volume.per_host_day == pytest.approx(33 / (3 + 1 / 24))
    assert volume.within_budget is True
    assert volume.notes == ["host-b: scanned span under one hour, floored to one hour"]
    assert volume.per_rule[0]["rule_id"] == "noisy" and volume.per_rule[0]["known_fp"] is True
    assert volume.per_rule[1]["hosts"] == ["host-a", "host-b"]
    assert volume.evaluated_rule_ids == ["noisy", "quiet", "silent"]
    strict = benign_volume(outcomes, {}, budget=1.0, evaluated_rule_ids=[], corpus="evtx_baseline")
    assert strict.within_budget is False
    empty = benign_volume([], {}, 20.0, [], corpus="evtx_baseline")
    assert empty.per_host_day is None and empty.within_budget is None


def test_cross_firing_top_offenders() -> None:
    result = cross_firing(OUTCOMES, "test")
    assert result["captures_with_cross_firing"] == 1
    assert result["cross_fired_alerts"] == 1
    assert result["top_offenders"] == [{"rule_id": "c", "title": "title c", "alerts": 1}]


def test_evidence_ladder_and_distribution() -> None:
    outcomes = [
        *OUTCOMES,
        _outcome("fx", ["T1110"], [_fired("f", ["T1110"])], kind="fixture", split=""),
    ]
    ladder = evidence_ladder(outcomes, RULES, ATTACK)
    assert ladder["T1059.001"] == "held-out-proven"
    assert ladder["T1059"] == "held-out-proven"  # hierarchical hit in the test split
    assert ladder["T1110"] == "sample-proven"  # dev hit outranks the fixture hit
    dist = ladder_distribution(ladder)
    assert list(dist) == list(LADDER) and sum(dist.values()) == len(ATTACK.techniques)
    only_fixture = evidence_ladder([outcomes[-1]], RULES, ATTACK)
    # No fixture rule tags the parent T1059, so it is "none"; the sub-technique is rule-only.
    assert only_fixture["T1110"] == "fixture-proven" and only_fixture["T1059"] == "none"
    assert only_fixture["T1059.001"] == "rule-only"


def test_robustness_is_all_unscored_until_scores_exist() -> None:
    result = robustness(RULES, {})
    assert result == {"levels": {"unscored": 2}, "scored": 0, "unscored": 2, "rules": 2}
    scored = robustness(RULES, {RULES[0].id: "level-3"})
    assert scored["levels"] == {"level-3": 1, "unscored": 1}


def test_capture_outcome_round_trip() -> None:
    outcome = OUTCOMES[2]
    restored = CaptureOutcome.from_dict(outcome.as_dict())
    assert restored == outcome
