"""Tests for ATT&CK STIX parsing and technique resolution."""

from __future__ import annotations

from pathlib import Path

from bastion.attack import load_attack, load_attack_data, resolve_techniques

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
