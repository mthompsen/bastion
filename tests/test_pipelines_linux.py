"""Tests for Linux routing and Sysmon for Linux ingestion (B3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bastion.attack import load_attack_data
from bastion.bench.corpora import attack_data
from bastion.engine import rule_applies, scan
from bastion.ingest import SysmonLinuxSource
from bastion.models import Event, FieldValue, SigmaRule
from bastion.pipelines import linux_pipeline

ATTACK = load_attack_data(Path(__file__).parent / "fixtures" / "mini_attack.json")

SYSMON_LINUX = (
    "<Event><System><Provider Name='Linux-Sysmon'/><EventID>1</EventID>"
    "<Channel>Linux-Sysmon/Operational</Channel><Computer>lab</Computer></System>"
    "<EventData><Data Name='Image'>/usr/bin/whoami</Data>"
    "<Data Name='CommandLine'>whoami</Data></EventData></Event>"
)


def _rule(**logsource: str) -> SigmaRule:
    return SigmaRule(
        id="r",
        title="r",
        logsource={"product": "linux", **logsource},
        detection={"s": {"Image|endswith": "/whoami"}, "condition": "s"},
    )


def _sysmon(event_id: int) -> Event:
    return Event(
        platform="linux",
        source="s.log",
        fields={"EventID": event_id, "Channel": "Linux-Sysmon/Operational"},
        raw="",
    )


def _auditd() -> Event:
    record = Event(platform="linux", source="a.log", fields={"type": "SYSCALL"}, raw="")
    return Event(
        platform="linux", source="a.log", fields={"type": "SYSCALL"}, raw="", records=[record]
    )


TEXT = Event(platform="linux", source="auth.log", fields={"program": "sshd"}, raw="sshd[1]: x")


class TestLinuxRouting:
    def test_event_kinds(self) -> None:
        pipeline = linux_pipeline()
        assert [pipeline.kind(e) for e in (_auditd(), _sysmon(1), TEXT)] == [
            "auditd",
            "sysmon",
            "text",
        ]

    def test_process_creation_runs_on_sysmon_1_and_auditd_only(self) -> None:
        rule = _rule(category="process_creation")
        assert rule_applies(rule, _sysmon(1))
        assert rule_applies(rule, _auditd())
        assert not rule_applies(rule, _sysmon(3))
        assert not rule_applies(rule, TEXT)

    def test_services_route_to_their_kinds(self) -> None:
        assert rule_applies(_rule(service="auditd"), _auditd())
        assert not rule_applies(_rule(service="auditd"), TEXT)
        assert rule_applies(_rule(service="sshd"), TEXT)
        assert not rule_applies(_rule(service="sshd"), _sysmon(1))

    @pytest.mark.parametrize(
        ("category", "event_id"), [("network_connection", 3), ("file_event", 11)]
    )
    def test_sysmon_categories(self, category: str, event_id: int) -> None:
        assert rule_applies(_rule(category=category), _sysmon(event_id))
        assert not rule_applies(_rule(category=category), _sysmon(1))
        assert not rule_applies(_rule(category=category), _auditd())

    def test_unlisted_logsource_is_not_restricted(self) -> None:
        assert rule_applies(_rule(), TEXT)
        assert rule_applies(_rule(service="unknown"), _sysmon(1))

    def test_scan_applies_the_routes(self) -> None:
        rule = _rule(category="process_creation")
        hit = Event(
            platform="linux",
            source="s.log",
            fields={
                "EventID": 1,
                "Channel": "Linux-Sysmon/Operational",
                "Image": "/usr/bin/whoami",
            },
            raw="",
        )
        miss: dict[str, FieldValue] = {**hit.fields, "EventID": 3}
        events = [hit, Event(platform="linux", source="s.log", fields=miss, raw="")]
        outcome = scan(events, [rule], {})
        assert len(outcome.detections) == 1 and outcome.events_scanned == 2


def test_sysmon_linux_source_reads_linux_events(tmp_path: Path) -> None:
    path = tmp_path / "sysmon.log"
    path.write_text("Jan  1 00:00:00 lab sysmon: " + SYSMON_LINUX + "\n" + SYSMON_LINUX, "utf-8")
    events = list(SysmonLinuxSource().parse(path))
    assert [e.platform for e in events] == ["linux", "linux"]
    assert events[0].fields["Image"] == "/usr/bin/whoami"
    assert "User" not in events[0].fields  # no Windows field mapping on Linux events


def test_attack_data_sysmon_linux_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = attack_data.corpus_dir(tmp_path)
    manifest = "datasets/attack_techniques/T1110/lin_demo/lin_demo.yml"
    lists = {"sysmon_linux_datasets_list": [manifest]}
    monkeypatch.setattr(
        attack_data, "dataset_manifests", lambda key="datasets_list": lists.get(key, [])
    )
    folder = root / "datasets/attack_techniques/T1110/lin_demo"
    folder.mkdir(parents=True)
    (folder / "sysmon_linux.log").write_text(SYSMON_LINUX, encoding="utf-8")
    entries = [
        {
            "path": "/datasets/attack_techniques/T1110/lin_demo/sysmon_linux.log",
            "sourcetype": "sysmon:linux",
            "source": "Syslog:Linux-Sysmon/Operational",
        },
        {"path": "/datasets/attack_techniques/T1110/lin_demo/a.log", "sourcetype": "auditd"},
    ]
    (root / manifest).write_text(
        json.dumps({"mitre_technique": ["T1110"], "datasets": entries}), encoding="utf-8"
    )
    (capture,) = attack_data.attack_data_captures(root, ATTACK)
    assert capture.id == "attack_data/T1110/lin_demo/sysmon_linux"
    assert (capture.platform, capture.source_kind) == ("linux", "sysmon_linux")
    assert capture.notes["sourcetype"] == "sysmon:linux"
    assert [e.fields["EventID"] for e in capture.events()] == [1]
