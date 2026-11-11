"""Tests for ATT&CK STIX parsing and technique resolution."""

from __future__ import annotations

from pathlib import Path

from bastion.attack import load_attack, load_attack_data, resolve_rule_tags, resolve_techniques
from bastion.coverage import summarize_coverage
from bastion.engine import scan
from bastion.models import Event, SigmaRule

MINI_STIX = Path(__file__).parent / "fixtures" / "mini_attack.json"


def test_load_attack_indexes_techniques_and_subtechniques() -> None:
    lookup = load_attack(MINI_STIX)
    assert set(lookup) == {"T1059", "T1059.001", "T1110"}
    assert lookup["T1059"].name == "Command and Scripting Interpreter"
    assert lookup["T1059.001"].name == "PowerShell"
    assert lookup["T1110"].tactics == ["credential-access"]


def test_platforms_are_parsed() -> None:
    lookup = load_attack(MINI_STIX)
    assert lookup["T1059.001"].platforms == ["Windows"]
    assert lookup["T1110"].platforms == ["Windows", "Linux", "IaaS"]


def test_detection_strategy_log_sources_are_attached() -> None:
    lookup = load_attack(MINI_STIX)
    # T1059 has a detection strategy whose analytic names two log sources.
    assert lookup["T1059"].log_sources == ["WinEventLog:Sysmon", "auditd:SYSCALL"]
    # Techniques without strategies keep an empty list.
    assert lookup["T1059.001"].log_sources == []


def test_tactics_only_include_mitre_attack_kill_chain() -> None:
    lookup = load_attack(MINI_STIX)
    # The fixture's T1059 also carries a lockheed-martin kill-chain phase.
    assert lookup["T1059"].tactics == ["execution"]


def test_revoked_and_deprecated_techniques_are_excluded() -> None:
    lookup = load_attack(MINI_STIX)
    assert "T9001" not in lookup
    assert "T9002" not in lookup


def test_revoked_by_links_and_deprecations_are_recorded() -> None:
    data = load_attack_data(MINI_STIX)
    # T9001 is revoked and ATT&CK names T1059.001 as its replacement.
    assert data.revoked_by == {"T9001": "T1059.001"}
    assert data.deprecated == frozenset({"T9002"})
    assert data.resolve_retired("t9001") == ("T1059.001", "revoked")
    assert data.resolve_retired("T9002") == (None, "deprecated")
    assert data.resolve_retired("T1110") == ("T1110", "live")
    assert data.resolve_retired("T9999") == (None, "unknown")


def test_bundle_version_is_read_from_collection_object() -> None:
    data = load_attack_data(MINI_STIX)
    assert data.version == "99.0"
    assert data.techniques == load_attack(MINI_STIX)


def test_resolve_techniques_is_case_insensitive_and_records_unresolved() -> None:
    lookup = load_attack(MINI_STIX)
    resolved, unresolved = resolve_techniques(["t1059.001", "T1110", "t9002", "T9999"], lookup)
    assert [ref.id for ref in resolved] == ["T1059.001", "T1110"]
    # The deprecated id and the unknown id are surfaced, not dropped.
    assert unresolved == ["T9002", "T9999"]


def test_resolve_techniques_empty_input() -> None:
    resolved, unresolved = resolve_techniques([], load_attack(MINI_STIX))
    assert resolved == []
    assert unresolved == []


def _rule(rule_id: str, *tags: str) -> SigmaRule:
    return SigmaRule(id=rule_id, title=rule_id, attack_techniques=list(tags))


def test_rule_tags_resolve_through_revoked_by() -> None:
    data = load_attack_data(MINI_STIX)
    rules = [
        _rule("a", "T9001", "T1110"),  # revoked tag plus a live tag
        _rule("b", "t9001", "T1059.001"),  # revoked tag whose successor is already present
        _rule("c", "T9002"),  # deprecated, no successor
        _rule("d", "T9999", "T1059"),  # unknown tag beside a live one
        _rule("e"),  # untagged
    ]
    report = resolve_rule_tags(rules, data)
    assert [r.technique_ids() for r in rules] == [
        ["T1059.001", "T1110"],
        ["T1059.001"],
        [],
        ["T1059"],
        [],
    ]
    # Upstream tags are never edited.
    assert rules[0].attack_techniques == ["T9001", "T1110"]
    assert report.remapped == {"T9001": ("T1059.001", 2)}
    assert report.deprecated == {"T9002": 1}
    assert report.unknown == {"T9999": 1}
    assert report.rules_remapped == 2
    assert report.rules_without_live_tag == 1  # rule c; the untagged rule does not count
    assert report.as_dict()["remapped"] == {"T9001": {"to": "T1059.001", "rules": 2}}


def test_unresolved_rule_uses_its_raw_tags() -> None:
    assert _rule("x", "t1059").technique_ids() == ["T1059"]


def test_resolved_tags_drive_detections_and_coverage() -> None:
    data = load_attack_data(MINI_STIX)
    rule = SigmaRule(
        id="r",
        title="r",
        logsource={"product": "windows"},
        detection={"s": {"Image|endswith": "/x.exe"}, "condition": "s"},
        attack_techniques=["T9001", "T9002"],
    )
    resolve_rule_tags([rule], data)
    event = Event(platform="windows", source="t", fields={"Image": "C:/x.exe"}, raw="")
    outcome = scan([event], [rule], data.techniques)
    assert [ref.id for ref in outcome.detections[0].techniques] == ["T1059.001"]
    assert outcome.unresolved_techniques == []
    entries = summarize_coverage([rule], data.techniques).entries
    covered = {e.technique.id for e in entries if e.covered}
    assert covered == {"T1059.001"}
