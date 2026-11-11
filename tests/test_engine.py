"""Tests for the scan engine: detections, evidence, pre-filtering, robustness."""

from __future__ import annotations

from pathlib import Path

import pytest

from bastion.attack import load_attack
from bastion.engine import rule_applies, scan
from bastion.models import Event, FieldValue, SigmaRule, TechniqueRef
from bastion.sigma.loader import load_rules

FIXTURES = Path(__file__).parent / "fixtures"
ATTACK = load_attack(FIXTURES / "mini_attack.json")


def windows_event(**fields: FieldValue) -> Event:
    base: dict[str, FieldValue] = {"EventID": 1}
    base.update(fields)
    return Event(platform="windows", source="sample.evtx", fields=base, raw="<Event/>")


PS_EVENT = windows_event(
    Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgA",
    ParentImage=r"C:\Windows\System32\cmd.exe",
)

SSH_EVENT = Event(
    platform="linux",
    source="auth.log",
    fields={"process": "sshd", "message": "Failed password for invalid user admin"},
    raw="Jun 10 06:13:44 web01 sshd[498]: Failed password for invalid user admin",
)

BENIGN_EVENT = windows_event(Image=r"C:\Windows\explorer.exe", CommandLine="explorer.exe")


def fixture_rules(platform: str | None = None) -> list[SigmaRule]:
    return load_rules(FIXTURES / "rules", platform=platform)  # type: ignore[arg-type]


class TestScan:
    def test_detection_with_evidence_and_enrichment(self) -> None:
        outcome = scan([PS_EVENT, BENIGN_EVENT], fixture_rules("windows"), ATTACK)
        assert outcome.events_scanned == 2
        assert len(outcome.detections) == 1
        detection = outcome.detections[0]
        assert detection.rule_title == "Suspicious Encoded PowerShell Command"
        assert detection.level == "high"
        assert detection.matched_fields["CommandLine"] == PS_EVENT.fields["CommandLine"]
        assert detection.techniques == [
            TechniqueRef(
                id="T1059.001", name="PowerShell", tactics=["execution"], platforms=["Windows"]
            )
        ]
        assert detection.event is PS_EVENT

    def test_linux_keyword_rule_fires(self) -> None:
        outcome = scan([SSH_EVENT], fixture_rules("linux"), ATTACK)
        assert [d.rule_title for d in outcome.detections] == ["SSH Failed Login For Invalid User"]
        assert outcome.detections[0].techniques[0].id == "T1110"

    def test_platform_prefilter_blocks_cross_platform_rules(self) -> None:
        # A Linux event whose fields would satisfy the Windows PowerShell rule.
        sneaky = Event(
            platform="linux",
            source="auth.log",
            fields=dict(PS_EVENT.fields),
            raw="powershell -enc on linux?!",
        )
        outcome = scan([sneaky], fixture_rules(), ATTACK)
        titles = [d.rule_title for d in outcome.detections]
        assert "Suspicious Encoded PowerShell Command" not in titles

    def test_category_prefilter_blocks_wrong_event_id(self) -> None:
        network_event = windows_event(EventID=3)
        network_event.fields.update(
            {
                "Image": PS_EVENT.fields["Image"],
                "CommandLine": PS_EVENT.fields["CommandLine"],
            }
        )
        outcome = scan([network_event], fixture_rules("windows"), ATTACK)
        assert outcome.detections == []

    def test_erroring_rule_is_recorded_and_scan_continues(self) -> None:
        bad = SigmaRule(
            id="bad-re",
            title="Bad Regex Rule",
            level="low",
            detection={"s": {"CommandLine|re": "(unclosed"}, "condition": "s"},
        )
        rules = [bad, *fixture_rules("windows")]
        outcome = scan([PS_EVENT], rules, ATTACK)
        assert "bad-re" in outcome.rule_errors
        # The good rule still fired despite the broken one.
        assert [d.rule_title for d in outcome.detections] == [
            "Suspicious Encoded PowerShell Command"
        ]

    def test_unsupported_rule_is_recorded_separately(self) -> None:
        unsupported = SigmaRule(
            id="agg-rule",
            title="Aggregation Rule",
            level="low",
            detection={"s": {"EventID": 1}, "condition": "s | count() > 5"},
        )
        outcome = scan([PS_EVENT, PS_EVENT], [unsupported], ATTACK)
        assert outcome.unsupported_rules == {"agg-rule": outcome.unsupported_rules["agg-rule"]}
        assert "aggregation" in outcome.unsupported_rules["agg-rule"]
        assert outcome.detections == []

    def test_unresolved_technique_tags_are_surfaced(self) -> None:
        rule = SigmaRule(
            id="stale-tag",
            title="Rule With Stale Tag",
            level="low",
            detection={"s": {"EventID": 1}, "condition": "s"},
            attack_techniques=["T1059.001", "T9999"],
        )
        outcome = scan([PS_EVENT], [rule], ATTACK)
        assert outcome.unresolved_techniques == ["T9999"]
        assert [ref.id for ref in outcome.detections[0].techniques] == ["T1059.001"]

    def test_multiple_events_can_fire_same_rule(self) -> None:
        outcome = scan([PS_EVENT, PS_EVENT], fixture_rules("windows"), ATTACK)
        assert len(outcome.detections) == 2


class TestRuleApplies:
    @pytest.fixture()
    def process_rule(self) -> SigmaRule:
        return SigmaRule(
            id="r",
            title="r",
            logsource={"product": "windows", "category": "process_creation"},
            detection={"s": {"EventID": 1}, "condition": "s"},
        )

    def test_product_mismatch(self, process_rule: SigmaRule) -> None:
        assert not rule_applies(process_rule, SSH_EVENT)

    def test_category_event_id_match(self, process_rule: SigmaRule) -> None:
        assert rule_applies(process_rule, windows_event(EventID=1))
        assert rule_applies(process_rule, windows_event(EventID=4688))
        assert not rule_applies(process_rule, windows_event(EventID=3))

    def test_event_without_event_id_is_not_blocked(self, process_rule: SigmaRule) -> None:
        event = Event(platform="windows", source="x.evtx", fields={}, raw="")
        assert rule_applies(process_rule, event)

    def test_unknown_category_is_not_blocked(self) -> None:
        rule = SigmaRule(
            id="r2",
            title="r2",
            logsource={"product": "windows", "category": "file_access"},  # ETW, no event id
            detection={"s": {"a": 1}, "condition": "s"},
        )
        assert rule_applies(rule, windows_event(EventID=4104))
        assert rule_applies(rule, windows_event(EventID=1))

    @pytest.mark.parametrize(
        ("category", "admitted", "blocked"),
        [
            (
                "raw_access_thread",
                9,
                1,
            ),  # spelled raw_access_read before B2; see docs/milestones/B2.md
            ("clipboard_capture", 24, 1),
            ("file_change", 2, 11),
            ("file_executable_detected", 29, 11),
            ("sysmon_error", 255, 1),
            ("ps_script", 4104, 1),
            ("ps_module", 4103, 4104),
            ("ps_classic_start", 400, 4104),
            ("file_delete", 26, 11),
        ],
    )
    def test_taxonomy_categories_route_to_their_event_ids(
        self, category: str, admitted: int, blocked: int
    ) -> None:
        rule = SigmaRule(
            id="r3",
            title="r3",
            logsource={"product": "windows", "category": category},
            detection={"s": {"a": 1}, "condition": "s"},
        )
        assert rule_applies(rule, windows_event(EventID=admitted))
        assert not rule_applies(rule, windows_event(EventID=blocked))

    def test_negation_only_rule_is_confined_to_its_category(self) -> None:
        """The B1 goodware finding: a rule whose condition is only exclusions must not run
        against events its category never produces."""
        rule = SigmaRule(
            id="raw",
            title="raw",
            logsource={"product": "windows", "category": "raw_access_thread"},
            detection={"filter": {"Image|startswith": "C:\\Windows\\"}, "condition": "not filter"},
        )
        outcome = scan(
            [
                windows_event(EventID=1, Image="C:\\Tools\\x.exe"),
                windows_event(EventID=9, Image="C:\\Tools\\x.exe"),
            ],
            [rule],
            ATTACK,
        )
        assert [d.event.fields["EventID"] for d in outcome.detections] == [9]
