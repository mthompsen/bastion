"""Process lineage (B4 lever c): parent fields lent to process starts that lack them."""

from __future__ import annotations

from pathlib import Path

from bastion.engine import scan
from bastion.ingest.auditd import AuditdSource
from bastion.models import Event, FieldValue, SigmaRule
from bastion.process_tree import ProcessTree


def _sec(event_id: int, **fields: FieldValue) -> Event:
    return Event(
        platform="windows",
        source="Security.evtx",
        fields={"EventID": event_id, "Channel": "Security", "Computer": "ws1", **fields},
        raw="<Event/>",
    )


def _sysmon(event_id: int, **fields: FieldValue) -> Event:
    return Event(
        platform="windows",
        source="sysmon.evtx",
        fields={
            "EventID": event_id,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "ws1",
            **fields,
        },
        raw="<Event/>",
    )


def test_security_4688_child_gains_parent_image_and_command_line() -> None:
    tree = ProcessTree()
    parent = _sec(
        4688,
        NewProcessId="0x1a2b",
        Image=r"C:\Windows\System32\cmd.exe",
        CommandLine="cmd.exe /c whoami",
        User=r"CORP\alice",
        ProcessId="0x4",
    )
    child = _sec(4688, NewProcessId="0x2000", Image=r"C:\x\whoami.exe", ProcessId="0x1A2B")
    tree.observe(parent)
    tree.observe(child)
    assert child.fields["ParentImage"] == r"C:\Windows\System32\cmd.exe"
    assert child.fields["ParentCommandLine"] == "cmd.exe /c whoami"
    assert child.fields["ParentUser"] == r"CORP\alice"
    assert tree.enriched == 1
    assert "ParentImage" not in parent.fields  # its creator was never seen


def test_existing_parent_fields_are_never_overwritten() -> None:
    tree = ProcessTree()
    tree.observe(_sec(4688, NewProcessId="0x10", Image="a.exe", CommandLine="a"))
    child = _sec(4688, NewProcessId="0x11", ProcessId="0x10", ParentImage="logged.exe")
    tree.observe(child)
    assert child.fields["ParentImage"] == "logged.exe"
    assert child.fields["ParentCommandLine"] == "a"


def test_termination_forgets_a_process_so_a_reused_id_lends_nothing() -> None:
    tree = ProcessTree()
    tree.observe(_sec(4688, NewProcessId="0x10", Image="a.exe", CommandLine="a"))
    tree.observe(_sec(4689, ProcessId="0x10"))
    child = _sec(4688, NewProcessId="0x11", ProcessId="0x10")
    tree.observe(child)
    assert "ParentImage" not in child.fields and tree.enriched == 0


def test_sysmon_links_by_parent_guid_and_fills_parent_user() -> None:
    tree = ProcessTree()
    tree.observe(
        _sysmon(1, ProcessGuid="{p}", ProcessId=100, Image="p.exe", CommandLine="p", User="u1")
    )
    child = _sysmon(
        1,
        ProcessGuid="{c}",
        ProcessId=200,
        ParentProcessGuid="{p}",
        ParentProcessId=999,
        ParentImage="p.exe",
        ParentCommandLine="p",
    )
    tree.observe(child)
    assert child.fields["ParentUser"] == "u1"
    tree.observe(_sysmon(5, ProcessGuid="{p}", ProcessId=100))
    orphan = _sysmon(1, ProcessGuid="{d}", ProcessId=300, ParentProcessGuid="{p}")
    tree.observe(orphan)
    assert "ParentImage" not in orphan.fields


def test_other_events_are_ignored() -> None:
    tree = ProcessTree()
    event = _sysmon(3, ProcessGuid="{p}", ProcessId=100, Image="p.exe")
    tree.observe(event)
    assert tree.by_pid == {} and tree.by_guid == {}


def _audit(serial: int, pid: int, ppid: int, exe: str, args: list[str] | None) -> str:
    stamp = f"msg=audit(1731340000.{serial:03d}:{serial})"
    syscall = 59 if args is not None else 2
    line = (
        f"type=SYSCALL {stamp}: arch=c000003e syscall={syscall} success=yes exit=0 "
        f'ppid={ppid} pid={pid} auid=1000 uid=0 comm="x" exe="{exe}" key=(null)\n'
    )
    if args is not None:
        argv = " ".join(f'a{i}="{a}"' for i, a in enumerate(args))
        line += f"type=EXECVE {stamp}: argc={len(args)} {argv}\n"
    return line


def test_auditd_exec_chain_by_ppid_and_non_exec_events_do_not_replace(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    log.write_text(
        _audit(1, 100, 1, "/usr/bin/bash", ["bash", "-c", "curl x | sh"])
        + _audit(2, 100, 1, "/usr/bin/bash", None)  # an open() by the same process
        + _audit(3, 200, 100, "/usr/bin/curl", ["curl", "x"]),
        encoding="utf-8",
    )
    tree = ProcessTree()
    events = list(AuditdSource().parse(log))
    for event in events:
        tree.observe(event)
    child = events[-1]
    assert child.fields["ParentImage"] == "/usr/bin/bash"
    assert child.fields["ParentCommandLine"] == "bash -c curl x | sh"
    assert "ParentImage" not in events[1].fields  # not a process start


def test_scan_evaluates_rules_on_the_filled_parent_fields() -> None:
    rule = SigmaRule(
        id="r",
        title="Child of a whoami shell",
        logsource={"product": "windows", "category": "process_creation"},
        detection={"sel": {"ParentCommandLine|contains": "whoami"}, "condition": "sel"},
    )
    events = [
        _sec(4688, NewProcessId="0x1a2b", Image="cmd.exe", CommandLine="cmd.exe /c whoami"),
        _sec(4688, NewProcessId="0x2000", Image="whoami.exe", ProcessId="0x1a2b"),
    ]
    outcome = scan(events, [rule], {})
    assert len(outcome.detections) == 1 and outcome.lineage_enriched == 1
