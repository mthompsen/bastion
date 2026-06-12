"""Tests for the coverage computation — covered techniques AND blind spots."""

from __future__ import annotations

from pathlib import Path

from bastion.attack import load_attack
from bastion.coverage import compute_coverage, host_relevant, summarize_coverage
from bastion.models import SigmaRule, TechniqueRef
from bastion.sigma.loader import load_rules

FIXTURES = Path(__file__).parent / "fixtures"
ATTACK = load_attack(FIXTURES / "mini_attack.json")
RULES = load_rules(FIXTURES / "rules")


def make_rule(rule_id: str, techniques: list[str]) -> SigmaRule:
    return SigmaRule(
        id=rule_id,
        title=rule_id,
        detection={"s": {"EventID": 1}, "condition": "s"},
        attack_techniques=techniques,
    )


def test_every_attack_technique_gets_an_entry() -> None:
    entries = compute_coverage(RULES, ATTACK)
    assert [entry.technique.id for entry in entries] == ["T1059", "T1059.001", "T1110"]


def test_covered_and_uncovered_are_both_reported() -> None:
    entries = {entry.technique.id: entry for entry in compute_coverage(RULES, ATTACK)}
    assert entries["T1059.001"].covered
    assert entries["T1059.001"].rule_count == 1
    assert entries["T1110"].covered
    # The blind spot is present in the output, not omitted.
    assert not entries["T1059"].covered
    assert entries["T1059"].rule_count == 0


def test_rule_counts_accumulate_across_rules() -> None:
    rules = [make_rule("a", ["T1110"]), make_rule("b", ["t1110"]), make_rule("c", ["T1059"])]
    entries = {entry.technique.id: entry for entry in compute_coverage(rules, ATTACK)}
    assert entries["T1110"].rule_count == 2  # case-insensitive accumulation
    assert entries["T1059"].rule_count == 1
    assert entries["T1059.001"].rule_count == 0


def test_summary_counts_and_tactics() -> None:
    summary = summarize_coverage(RULES, ATTACK)
    assert summary.covered_count == 2
    assert summary.total_count == 3
    # execution: T1059 (uncovered) + T1059.001 (covered) -> 1 of 2.
    assert summary.tactic_totals["execution"] == (1, 2)
    assert summary.tactic_totals["credential-access"] == (1, 1)
    assert summary.unknown_technique_ids == []


def test_unknown_technique_tags_are_listed_not_counted() -> None:
    rules = [*RULES, make_rule("stale", ["T9999", "T9002"])]
    summary = summarize_coverage(rules, ATTACK)
    assert summary.unknown_technique_ids == ["T9002", "T9999"]
    # Unknown tags must not inflate the covered count.
    assert summary.covered_count == 2


def test_empty_ruleset_covers_nothing() -> None:
    summary = summarize_coverage([], ATTACK)
    assert summary.covered_count == 0
    assert summary.total_count == 3
    assert all(not entry.covered for entry in summary.entries)


class TestHostRelevance:
    def test_host_platforms_are_relevant(self) -> None:
        assert host_relevant(TechniqueRef(id="T1", name="a", platforms=["Windows"]))
        assert host_relevant(TechniqueRef(id="T2", name="b", platforms=["IaaS", "Linux"]))

    def test_non_host_platforms_are_not(self) -> None:
        assert not host_relevant(TechniqueRef(id="T3", name="c", platforms=["IaaS", "SaaS"]))
        assert not host_relevant(TechniqueRef(id="T4", name="d", platforms=["PRE"]))
        assert not host_relevant(
            TechniqueRef(id="T5", name="e", platforms=["Network Devices", "ESXi"])
        )

    def test_missing_platform_metadata_counts_as_relevant(self) -> None:
        # The gap count must never understate the remaining work.
        assert host_relevant(TechniqueRef(id="T6", name="f", platforms=[]))

    def test_summary_splits_uncovered_by_host_relevance(self) -> None:
        lookup = {
            "T1059.001": TechniqueRef(
                id="T1059.001", name="PowerShell", tactics=["execution"], platforms=["Windows"]
            ),
            "T9100": TechniqueRef(
                id="T9100", name="Cloud Only", tactics=["impact"], platforms=["IaaS"]
            ),
            "T9200": TechniqueRef(
                id="T9200", name="Host Gap", tactics=["impact"], platforms=["Linux"]
            ),
        }
        summary = summarize_coverage([make_rule("a", ["T1059.001"])], lookup)
        assert summary.covered_count == 1
        assert summary.uncovered_beyond_host_count == 1  # T9100
        assert summary.uncovered_host_gap_count == 1  # T9200

    def test_fixture_summary_gap_counts(self) -> None:
        # The fixture's only uncovered technique (T1059) is host-relevant.
        summary = summarize_coverage(RULES, ATTACK)
        assert summary.uncovered_host_gap_count == 1
        assert summary.uncovered_beyond_host_count == 0
