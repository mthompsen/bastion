"""Tests for the declarative Windows pipeline: log source routing and field mapping (B3)."""

from __future__ import annotations

import pytest

from bastion.engine import rule_applies, scan
from bastion.ingest.evtx import xml_to_event
from bastion.models import Event, FieldValue, SigmaRule
from bastion.pipelines import parse_windows_pipeline, windows_pipeline

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def _event(channel: str | None, event_id: int, **fields: FieldValue) -> Event:
    data: dict[str, FieldValue] = {"EventID": event_id, **fields}
    if channel is not None:
        data["Channel"] = channel
    return Event(platform="windows", source="t.evtx", fields=data, raw="")


def _rule(**logsource: str) -> SigmaRule:
    return SigmaRule(
        id="r",
        title="r",
        logsource={"product": "windows", **logsource},
        detection={"s": {"Image|endswith": "\\whoami.exe"}, "condition": "s"},
    )


class TestRouting:
    def test_service_needs_its_channel(self) -> None:
        rule = _rule(service="security")
        assert rule_applies(rule, _event("Security", 4625))
        assert not rule_applies(rule, _event("System", 4625))
        assert rule_applies(rule, _event(None, 4625))  # no Channel: routed by nothing else

    def test_channels_compare_case_insensitively(self) -> None:
        assert rule_applies(_rule(service="sysmon"), _event(SYSMON.upper(), 1))

    def test_category_needs_channel_and_event_id(self) -> None:
        rule = _rule(category="process_creation")
        assert rule_applies(rule, _event(SYSMON, 1))
        assert rule_applies(rule, _event("Security", 4688))
        assert not rule_applies(rule, _event("System", 1))  # EventID 1 of another channel
        assert not rule_applies(rule, _event(SYSMON, 3))
        assert not rule_applies(rule, _event("Security", 1))

    def test_unlisted_service_and_category_are_not_restricted(self) -> None:
        assert rule_applies(_rule(service="not-a-service"), _event("Anything", 7))
        assert rule_applies(_rule(category="file_access"), _event("Anything", 7))

    def test_classic_powershell_routes_to_windows_powershell(self) -> None:
        rule = _rule(category="ps_classic_start")
        assert rule_applies(rule, _event("Windows PowerShell", 400))
        assert not rule_applies(rule, _event("Microsoft-Windows-PowerShell/Operational", 400))

    def test_linux_events_are_not_routed(self) -> None:
        event = Event(platform="linux", source="a", fields={"EventID": 1}, raw="")
        assert windows_pipeline().admits(_rule(category="process_creation"), event)


SECURITY_4688: dict[str, FieldValue] = {
    "Channel": "Security",
    "EventID": 4688,
    "NewProcessName": "C:\\Windows\\System32\\whoami.exe",
    "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
    "CommandLine": "whoami /all",
    "SubjectUserName": "alice",
    "SubjectDomainName": "CORP",
    "TargetUserName": "-",
    "TargetDomainName": "-",
    "MandatoryLabel": "S-1-16-12288",
}


class TestFieldMapping:
    def test_security_4688_gains_process_creation_names(self) -> None:
        fields: dict[str, FieldValue] = dict(SECURITY_4688)
        assert windows_pipeline().apply(fields) == ["security-4688-process-creation"]
        assert fields["Image"] == "C:\\Windows\\System32\\whoami.exe"
        assert fields["ParentImage"] == "C:\\Windows\\System32\\cmd.exe"
        assert fields["User"] == "CORP\\alice"  # Target is "-", so the Subject template wins
        assert fields["IntegrityLevel"] == "High"
        assert fields["NewProcessName"] == SECURITY_4688["NewProcessName"]  # kept

    def test_target_user_preferred_and_nothing_overwritten(self) -> None:
        fields: dict[str, FieldValue] = {
            **SECURITY_4688,
            "TargetUserName": "bob",
            "TargetDomainName": "CORP",
            "Image": "kept",
            "MandatoryLabel": "S-1-16-99999",
        }
        windows_pipeline().apply(fields)
        assert fields["User"] == "CORP\\bob"
        assert fields["Image"] == "kept"
        assert "IntegrityLevel" not in fields  # an unknown label is left unmapped

    def test_other_events_are_untouched(self) -> None:
        fields: dict[str, FieldValue] = {**SECURITY_4688, "EventID": 4689}
        assert windows_pipeline().apply(fields) == []
        assert "Image" not in fields
        sysmon: dict[str, FieldValue] = {"Channel": SYSMON, "EventID": 1, "Image": "x"}
        assert windows_pipeline().apply(sysmon) == [] and sysmon == {
            "Channel": SYSMON,
            "EventID": 1,
            "Image": "x",
        }

    def test_security_5156_gains_network_connection_names(self) -> None:
        fields: dict[str, FieldValue] = {
            "Channel": "Security",
            "EventID": 5156,
            "Application": "\\device\\harddiskvolume2\\windows\\system32\\svchost.exe",
            "DestAddress": "192.0.2.10",
            "DestPort": "443",
            "SourceAddress": "10.0.0.5",
            "Direction": "%%14593",
        }
        windows_pipeline().apply(fields)
        assert (fields["DestinationIp"], fields["DestinationPort"], fields["SourceIp"]) == (
            "192.0.2.10",
            "443",
            "10.0.0.5",
        )
        assert fields["Image"].endswith("svchost.exe")  # type: ignore[union-attr]
        assert fields["Initiated"] == "true"

    def test_rule_on_4688_detects_and_lacking_fields_are_not_evaluable(self) -> None:
        event = xml_to_event(_xml_4688(), "sec.evtx")
        assert event is not None
        hit = _rule(category="process_creation")
        needs_hashes = SigmaRule(
            id="h",
            title="h",
            logsource={"product": "windows", "category": "process_creation"},
            detection={
                "s": {"Image|endswith": "whoami.exe", "OriginalFileName": "whoami.exe"},
                "condition": "s",
            },
        )
        outcome = scan([event], [hit, needs_hashes], {})
        assert [d.rule_id for d in outcome.detections] == ["r"]
        assert outcome.not_evaluable == {"h": 1}

    def test_bad_field_spec_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="unsupported field mapping"):
            parse_windows_pipeline(
                {
                    "mappings": [
                        {"name": "x", "channels": ["a"], "event_ids": [1], "fields": {"A": 3}}
                    ]
                }
            )


def _xml_4688() -> str:
    data = "".join(
        f"<Data Name='{k}'>{v}</Data>"
        for k, v in SECURITY_4688.items()
        if k not in {"Channel", "EventID"}
    )
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        "<EventID>4688</EventID><Channel>Security</Channel></System>"
        f"<EventData>{data}</EventData></Event>"
    )


class TestXmlShapes:
    def test_unnamed_data_becomes_data(self) -> None:
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            "<EventID>400</EventID><Channel>Windows PowerShell</Channel></System><EventData>"
            "<Data>Available</Data><Data>None</Data>"
            "<Data>HostApplication=powershell.exe -enc AAAA</Data></EventData></Event>"
        )
        event = xml_to_event(xml, "ps.evtx")
        assert event is not None
        assert event.fields["Data"] == "Available\nNone\nHostApplication=powershell.exe -enc AAAA"

    def test_user_data_leaves_become_fields(self) -> None:
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            "<EventID>5858</EventID><Channel>Microsoft-Windows-WMI-Activity/Operational</Channel>"
            "</System><UserData><Operation_ClientFailure xmlns='http://manifests/wmi'>"
            "<Id>{1}</Id><Operation>Start IWbemServices::ExecQuery</Operation>"
            "<ResultCode>0x80041032</ResultCode></Operation_ClientFailure></UserData></Event>"
        )
        event = xml_to_event(xml, "wmi.evtx")
        assert event is not None
        assert event.fields["Operation"] == "Start IWbemServices::ExecQuery"
        assert event.fields["ResultCode"] == "0x80041032"
