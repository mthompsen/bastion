"""OCSF and ECS views of events, and OCSF Detection Findings (B5).

The views are checked against the published schemas, kept as small attributed fixtures in
``tests/fixtures/standards`` (see its README): OCSF 1.9.0 class JSON Schemas with the host profile
applied, and the ECS 9.5.0 field list with its categorization allowed values.
"""

from __future__ import annotations

import copy
import gzip
import json
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from bastion.ingest.evtx import EvtxSource
from bastion.models import Detection, Event, FieldValue, TechniqueRef
from bastion.normalize import ECS_VERSION, OCSF_VERSION, detection_finding, to_ecs, to_ocsf
from bastion.normalize.ocsf import finding_uid

FIXTURES = Path(__file__).parent / "fixtures" / "standards"
EXAMPLES = Path(__file__).parent.parent / "examples" / "logs"
TS = datetime(2026, 11, 22, 8, 30, 0, tzinfo=UTC)

_CLASS_FILES = {
    0: "base_event",
    1001: "file_activity",
    1007: "process_activity",
    2004: "detection_finding",
    3002: "authentication",
    4001: "network_activity",
    201001: "registry_key_activity",
    201002: "registry_value_activity",
}


@cache
def ocsf_schema(class_uid: int) -> dict[str, Any]:
    path = FIXTURES / "ocsf-1.9.0" / f"{_CLASS_FILES[class_uid]}.schema.json.gz"
    loaded: dict[str, Any] = json.loads(gzip.decompress(path.read_bytes()))
    return loaded


@cache
def ecs_fields() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(
        gzip.decompress((FIXTURES / "ecs-9.5.0-fields.json.gz").read_bytes())
    )
    return loaded


def assert_ocsf_valid(view: dict[str, Any]) -> None:
    jsonschema.validate(view, ocsf_schema(view["class_uid"]))


def _flatten(doc: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for key, value in doc.items():
        dotted = f"{prefix}{key}"
        if isinstance(value, dict) and not dotted.startswith("bastion."):
            flat.update(_flatten(value, f"{dotted}."))
        else:
            flat[dotted] = value
    return flat


def assert_ecs_valid(doc: dict[str, Any]) -> None:
    spec = ecs_fields()
    flat = _flatten(doc)
    unknown = [k for k in flat if k not in spec["fields"] and not k.startswith("bastion.")]
    assert not unknown, unknown
    allowed = spec["allowed"]
    for category in flat.get("event.category", []):
        assert category in allowed["event.category"]
        for kind in flat.get("event.type", []):
            assert kind in allowed["event.category"][category], (category, kind)
    assert flat["event.kind"] in allowed["event.kind"]
    if "event.outcome" in flat:
        assert flat["event.outcome"] in allowed["event.outcome"]


def win(channel: str, event_id: int, **fields: Any) -> Event:
    base: dict[str, FieldValue] = {
        "Channel": channel,
        "EventID": event_id,
        "Computer": "ws01.corp.example",
        "Provider_Name": "Provider",
        "Provider": "Provider",
    }
    return Event(
        timestamp=TS,
        platform="windows",
        source="sample.evtx",
        fields={**base, **fields},
        raw=f"<Event>{event_id}</Event>",
    )


SYSMON = "Microsoft-Windows-Sysmon/Operational"

CASES: list[tuple[str, Event, int, int]] = [
    (
        "sysmon process start",
        win(
            SYSMON,
            1,
            Image="C:\\Windows\\System32\\cmd.exe",
            CommandLine="cmd.exe /c whoami",
            ProcessId="4242",
            ProcessGuid="{11111111-2222-3333-4444-555555555555}",
            ParentImage="C:\\Windows\\explorer.exe",
            ParentProcessId="1000",
            ParentCommandLine="explorer.exe",
            User="CORP\\alice",
            IntegrityLevel="Medium",
            Hashes="SHA256=00",
        ),
        1007,
        1,
    ),
    (
        "security 4688",
        win(
            "Security",
            4688,
            NewProcessName="C:\\Windows\\System32\\whoami.exe",
            Image="C:\\Windows\\System32\\whoami.exe",
            NewProcessId="0x1f4",
            ProcessId="0x3e8",
            CommandLine="whoami /all",
            ParentProcessName="C:\\Windows\\System32\\cmd.exe",
            ParentImage="C:\\Windows\\System32\\cmd.exe",
            SubjectUserName="alice",
        ),
        1007,
        1,
    ),
    (
        "sysmon process access",
        win(
            SYSMON,
            10,
            SourceImage="C:\\Tools\\dump.exe",
            SourceProcessId="77",
            TargetImage="C:\\Windows\\System32\\lsass.exe",
            TargetProcessId="600",
            GrantedAccess="0x1010",
        ),
        1007,
        3,
    ),
    (
        "sysmon network",
        win(
            SYSMON,
            3,
            Image="C:\\Windows\\System32\\rundll32.exe",
            ProcessId="321",
            SourceIp="10.0.0.5",
            SourcePort="51000",
            DestinationIp="198.51.100.7",
            DestinationPort="443",
            Protocol="tcp",
            Initiated="true",
        ),
        4001,
        1,
    ),
    (
        "security 5156",
        win(
            "Security",
            5156,
            Application="\\device\\harddiskvolume2\\windows\\system32\\svchost.exe",
            SourceAddress="10.0.0.5",
            SourcePort="135",
            DestAddress="10.0.0.9",
            DestPort="49700",
            ProcessID="900",
        ),
        4001,
        1,
    ),
    (
        "security 4624",
        win(
            "Security",
            4624,
            TargetUserName="alice",
            TargetDomainName="CORP",
            TargetUserSid="S-1-5-21-1-2-3-1104",
            SubjectUserName="WS01$",
            LogonType="3",
            IpAddress="10.0.0.9",
            IpPort="50123",
            AuthenticationPackageName="NTLM",
            WorkstationName="WS02",
        ),
        3002,
        1,
    ),
    (
        "security 4625",
        win(
            "Security",
            4625,
            TargetUserName="bob",
            LogonType="10",
            Status="0xc000006d",
            SubStatus="0xc000006a",
            IpAddress="-",
        ),
        3002,
        1,
    ),
    (
        "security 4768",
        win(
            "Security",
            4768,
            TargetUserName="carol",
            Status="0x0",
            ServiceName="krbtgt",
            IpAddress="::ffff:10.0.0.12",
        ),
        3002,
        3,
    ),
    (
        "security 4769",
        win("Security", 4769, TargetUserName="carol", ServiceName="MSSQLSvc", Status="0x1b"),
        3002,
        4,
    ),
    (
        "security 4771",
        win("Security", 4771, TargetUserName="dave", Status="0x18"),
        3002,
        6,
    ),
    (
        "security 4634",
        win("Security", 4634, TargetUserName="alice", LogonType="2"),
        3002,
        2,
    ),
    (
        "sysmon file create",
        win(
            SYSMON,
            11,
            Image="C:\\Windows\\System32\\cmd.exe",
            ProcessId="4242",
            TargetFilename="C:\\Users\\Public\\x.ps1",
        ),
        1001,
        1,
    ),
    (
        "sysmon file delete",
        win(SYSMON, 23, Image="C:\\a.exe", ProcessId="10", TargetFilename="C:\\b.txt"),
        1001,
        4,
    ),
    (
        "sysmon registry key create",
        win(
            SYSMON,
            12,
            EventType="CreateKey",
            Image="C:\\a.exe",
            ProcessId="10",
            TargetObject="HKLM\\SOFTWARE\\X",
        ),
        201001,
        1,
    ),
    (
        "sysmon registry value set",
        win(
            SYSMON,
            13,
            EventType="SetValue",
            Image="C:\\a.exe",
            ProcessId="10",
            TargetObject="HKU\\S-1-5-21\\Software\\Run\\x",
            Details="C:\\x.exe",
        ),
        201002,
        2,
    ),
    (
        "sysmon registry value delete",
        win(
            SYSMON,
            12,
            EventType="DeleteValue",
            Image="C:\\a.exe",
            ProcessId="10",
            TargetObject="HKLM\\X\\v",
        ),
        201002,
        4,
    ),
    (
        "sysmon registry rename",
        win(
            SYSMON,
            14,
            EventType="RenameKey",
            Image="C:\\a.exe",
            ProcessId="10",
            TargetObject="HKLM\\X\\old",
            NewName="HKLM\\X\\new",
        ),
        201001,
        5,
    ),
    (
        "system 7045",
        win("System", 7045, ServiceName="evil", ImagePath="C:\\evil.exe"),
        0,
        0,
    ),
    (
        "auditd exec",
        Event(
            timestamp=TS,
            platform="linux",
            source="audit.log",
            fields={
                "type": "SYSCALL",
                "SYSCALL": "execve",
                "exe": "/usr/bin/curl",
                "Image": "/usr/bin/curl",
                "CommandLine": "curl http://198.51.100.7/x",
                "pid": "4100",
                "ppid": "4000",
                "uid": "0",
                "node": "web01",
            },
            raw="type=SYSCALL msg=audit(1.0:1): syscall=59",
        ),
        1007,
        1,
    ),
    (
        "security 4689",
        win(
            "Security",
            4689,
            ProcessName="C:\\Windows\\System32\\whoami.exe",
            ProcessId="0x1f4",
            Status="0x0",
            SubjectUserName="alice",
            SubjectDomainName="CORP",
            SubjectUserSid="S-1-5-21-1-2-3-1001",
            SubjectLogonId="0x3e7",
        ),
        1007,
        2,
    ),
]


@pytest.mark.parametrize(
    ("name", "event", "class_uid", "activity_id"), CASES, ids=[c[0] for c in CASES]
)
class TestOcsfView:
    def test_class_and_activity(
        self, name: str, event: Event, class_uid: int, activity_id: int
    ) -> None:
        view = to_ocsf(event)
        assert (view["class_uid"], view["activity_id"]) == (class_uid, activity_id)
        assert view["type_uid"] == class_uid * 100 + activity_id

    def test_valid_against_ocsf_1_9_0(
        self, name: str, event: Event, class_uid: int, activity_id: int
    ) -> None:
        assert_ocsf_valid(to_ocsf(event))

    def test_pure_and_keeps_every_field(
        self, name: str, event: Event, class_uid: int, activity_id: int
    ) -> None:
        before = copy.deepcopy(event.fields)
        view = to_ocsf(event)
        assert event.fields == before
        assert view["raw_data"] == event.raw
        unmapped = view.get("unmapped", {})
        assert set(unmapped) <= set(before)
        assert all(unmapped[k] == before[k] for k in unmapped)

    def test_ecs_view_uses_only_ecs_fields(
        self, name: str, event: Event, class_uid: int, activity_id: int
    ) -> None:
        before = copy.deepcopy(event.fields)
        doc = to_ecs(event)
        assert event.fields == before
        assert doc["ecs"]["version"] == ECS_VERSION
        assert doc["event"]["original"] == event.raw
        assert_ecs_valid(doc)


def test_security_4688_new_process_and_creator_are_not_swapped() -> None:
    view = to_ocsf(CASES[1][1])
    assert view["process"]["pid"] == 0x1F4
    assert view["process"]["parent_process"]["pid"] == 0x3E8
    assert view["actor"]["process"]["pid"] == 0x3E8
    doc = to_ecs(CASES[1][1])
    assert doc["process"]["pid"] == 0x1F4
    assert doc["process"]["parent"]["pid"] == 0x3E8


def test_unmapped_keeps_fields_under_their_source_names() -> None:
    view = to_ocsf(CASES[0][1])
    assert view["unmapped"]["Hashes"] == "SHA256=00"
    assert "Image" not in view["unmapped"]
    doc = to_ecs(CASES[0][1])
    assert doc["bastion"]["unmapped"]["Hashes"] == "SHA256=00"


def test_authentication_status_and_logon_type() -> None:
    success = to_ocsf(CASES[5][1])
    assert success["status_id"] == 1 and success["logon_type_id"] == 3
    assert success["user"] == {"name": "alice", "domain": "CORP", "uid": "S-1-5-21-1-2-3-1104"}
    failure = to_ocsf(CASES[6][1])
    assert failure["status_id"] == 2 and failure["status_code"] == "0xc000006d"
    assert "src_endpoint" not in failure  # "-" is no address
    assert to_ocsf(CASES[7][1])["status_id"] == 1
    assert to_ocsf(CASES[8][1])["status_id"] == 2
    assert to_ecs(CASES[6][1])["event"]["outcome"] == "failure"


def test_registry_hive_and_value_in_ecs() -> None:
    doc = to_ecs(CASES[14][1])
    assert doc["registry"]["hive"] == "HKU"
    assert doc["registry"]["value"] == "x"
    assert doc["registry"]["data"]["strings"] == ["C:\\x.exe"]


def test_unknown_logon_type_is_other_not_a_guess() -> None:
    view = to_ocsf(win("Security", 4624, TargetUserName="x", LogonType="0"))
    assert view["logon_type_id"] == 99 and view["logon_type"] == "0"


def test_network_direction_and_auth_destination() -> None:
    assert to_ocsf(CASES[3][1])["connection_info"]["direction_id"] == 2
    assert to_ocsf(CASES[4][1])["connection_info"]["direction_id"] == 0
    inbound = win("Security", 5156, SourceAddress="10.0.0.5", Direction="%%14592", ProcessID="4")
    assert to_ocsf(inbound)["connection_info"]["direction_id"] == 1
    assert to_ocsf(CASES[5][1])["dst_endpoint"] == {"hostname": "ws01.corp.example"}


def test_record_without_host_has_no_device() -> None:
    event = CASES[0][1].model_copy(
        update={"fields": {k: v for k, v in CASES[0][1].fields.items() if k != "Computer"}}
    )
    assert "device" not in to_ocsf(event)


def test_event_without_timestamp_is_labelled_not_given_a_time() -> None:
    event = CASES[0][1].model_copy(update={"timestamp": None})
    view = to_ocsf(event)
    assert "time" not in view
    assert view["metadata"]["labels"] == ["bastion:no-timestamp"]
    assert "@timestamp" not in to_ecs(event)


def test_real_evtx_events_are_valid_views() -> None:
    events = [
        e
        for name in (
            "sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx",
            "Sysmon_13_1_UACBypass_SDCLTBypass.evtx",
        )
        for e in EvtxSource().parse(EXAMPLES / name)
    ]
    classes = set()
    for event in events:
        view = to_ocsf(event)
        assert_ocsf_valid(view)
        assert_ecs_valid(to_ecs(event))
        classes.add(view["class_uid"])
    assert {1007, 201002} <= classes


def _detection(level: str = "high", timestamp: datetime | None = TS) -> Detection:
    event = CASES[0][1].model_copy(update={"timestamp": timestamp})
    return Detection(
        rule_id="11111111-0000-0000-0000-000000000001",
        rule_title="Whoami Execution",
        level=level,  # type: ignore[arg-type]
        event=event,
        matched_fields={"Image": "C:\\Windows\\System32\\cmd.exe"},
        techniques=[
            TechniqueRef(id="T1033", name="System Owner/User Discovery", tactics=["discovery"]),
            TechniqueRef(
                id="T1059.003",
                name="Windows Command Shell",
                tactics=["execution"],
            ),
        ],
    )


def test_detection_finding_is_valid_and_carries_the_detection() -> None:
    finding = detection_finding(
        _detection(), attack_version="20.1", sigma_version="r2026-07-01", hunting=False
    )
    assert_ocsf_valid(finding)
    assert finding["class_uid"] == 2004 and finding["type_uid"] == 200401
    assert finding["metadata"]["version"] == OCSF_VERSION
    assert finding["severity_id"] == 4
    info = finding["finding_info"]
    assert info["analytic"]["uid"] == "11111111-0000-0000-0000-000000000001"
    assert info["analytic"]["version"] == "r2026-07-01"
    attacks = info["attacks"]
    assert {"uid": "T1033", "name": "System Owner/User Discovery"} in [
        a["technique"] for a in attacks
    ]
    sub = next(a for a in attacks if "sub_technique" in a)
    assert sub["technique"] == {"uid": "T1059"} and sub["sub_technique"]["uid"] == "T1059.003"
    assert all(a["version"] == "20.1" for a in attacks)
    assert finding["evidences"][0]["data"] == {
        "matched_fields": {"Image": "C:\\Windows\\System32\\cmd.exe"}
    }
    assert finding["evidences"][0]["process"]["pid"] == 4242
    assert finding["unmapped"]["hunting_class"] is False
    assert finding["time"] == int(TS.timestamp() * 1000)


@pytest.mark.parametrize(
    ("level", "severity_id"),
    [("informational", 1), ("low", 2), ("medium", 3), ("high", 4), ("critical", 5)],
)
def test_sigma_level_to_severity(level: str, severity_id: int) -> None:
    finding = detection_finding(_detection(level))
    assert finding["severity_id"] == severity_id
    assert_ocsf_valid(finding)


def test_finding_uid_is_deterministic_and_time_is_never_invented() -> None:
    first, second = _detection(), _detection()
    assert finding_uid(first) == finding_uid(second)
    undated = detection_finding(_detection(timestamp=None))
    assert "time" not in undated
    assert undated["metadata"]["labels"] == ["bastion:no-timestamp"]
    assert "hunting_class" not in undated["unmapped"]


def test_security_4689_actor_is_the_subject_user() -> None:
    view = to_ocsf(next(c[1] for c in CASES if c[0] == "security 4689"))
    assert view["actor"] == {
        "user": {"name": "alice", "domain": "CORP", "uid": "S-1-5-21-1-2-3-1001"}
    }
    assert view["process"]["pid"] == 0x1F4
    assert "labels" not in view["metadata"]


SYSMON_5 = win(
    SYSMON,
    5,
    Image="C:\\Windows\\System32\\whoami.exe",
    ProcessId="4242",
    ProcessGuid="{11111111-2222-3333-4444-555555555555}",
    User="CORP\\alice",
    RuleName="-",
)


def test_sysmon_5_names_no_actor_and_says_so() -> None:
    view = to_ocsf(SYSMON_5)
    assert (view["class_uid"], view["activity_id"]) == (1007, 2)
    assert "actor" not in view
    assert view["metadata"]["labels"] == ["bastion:no-actor"]
    # The owner of the process that ended is the process's user, not an actor.
    assert view["process"]["user"]["name"] == "alice"
    errors = list(jsonschema.Draft7Validator(ocsf_schema(1007)).iter_errors(view))
    assert [e.message for e in errors] == ["'actor' is a required property"]


def test_finding_on_an_actorless_event_carries_the_label() -> None:
    detection = _detection().model_copy(update={"event": SYSMON_5})
    finding = detection_finding(detection)
    assert_ocsf_valid(finding)
    assert finding["metadata"]["labels"] == ["bastion:no-actor"]
    assert "actor" not in finding["evidences"][0]
    undated = detection.model_copy(
        update={"event": SYSMON_5.model_copy(update={"timestamp": None})}
    )
    assert detection_finding(undated)["metadata"]["labels"] == [
        "bastion:no-timestamp",
        "bastion:no-actor",
    ]
