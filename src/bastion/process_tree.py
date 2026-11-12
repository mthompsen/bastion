"""Process lineage within one scan, so a process start knows its parent (B4 lever c).

START_PROMPT section 6, lever 6: reconstruct parent and child lineage from Sysmon 1 and
Security 4688 (and auditd exec events on Linux) so rules can reason about ancestry. Many
process starts do not carry their parent's details: Security 4688 has no parent command line
and, before Windows 10, no parent image; a merged auditd exec event names only `ppid`.
SigmaHQ `process_creation` rules that read `ParentImage`, `ParentCommandLine` or `ParentUser`
are then not_evaluable on those events.

The tree records every process start it sees, keyed by host and process id (and by Sysmon's
`ProcessGuid`, which never repeats), and forgets a process at its termination event (Sysmon
5, Security 4689). When a later process start names that process as its parent, the parent's
`Image`, `CommandLine` and `User` are added as `ParentImage`, `ParentCommandLine` and
`ParentUser`, only where the event lacks them, never overwriting a field. A parent that
started before the scan began is unknown, and the event is left as it was.

Lineage is only as good as the order of the events: a parent must be seen before its child.
Process ids are reused; the tree holds the latest start for an id until that process ends,
so a reused id whose termination was not logged can name the wrong parent. That risk is a
precision cost, measured with the goodware replay rather than assumed away.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from bastion.models import Event, FieldValue

_SYSMON_CHANNELS = frozenset({"Microsoft-Windows-Sysmon/Operational", "Linux-Sysmon/Operational"})
#: the parent fields a child gains, from the parent's own fields of the same base name
_INHERITED = (
    ("ParentImage", "Image"),
    ("ParentCommandLine", "CommandLine"),
    ("ParentUser", "User"),
)


def _pid(value: FieldValue | None) -> int | None:
    """A process id as Windows (hex `0x...` in Security events) or Linux writes it."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


@dataclass
class _Process:
    image: FieldValue | None
    command_line: FieldValue | None
    user: FieldValue | None

    def value(self, name: str) -> FieldValue | None:
        return {"Image": self.image, "CommandLine": self.command_line, "User": self.user}[name]


@dataclass
class ProcessTree:
    """Process starts seen so far in one scan, and the parent fields they lend to children."""

    by_pid: dict[tuple[str, int], _Process] = field(default_factory=dict)
    by_guid: dict[str, _Process] = field(default_factory=dict)
    #: process starts that gained at least one parent field
    enriched: int = 0

    def observe(self, event: Event) -> None:
        """Enrich a process start from its parent, then record it; forget ended processes."""
        kind = _kind(event)
        if kind is None:
            return
        fields = event.fields
        host = str(fields.get("Computer") or fields.get("node") or "")
        if kind == "end":
            guid = fields.get("ProcessGuid")
            if guid is not None:
                self.by_guid.pop(str(guid), None)
            pid = _pid(fields.get("ProcessId"))
            if pid is not None:
                self.by_pid.pop((host, pid), None)
            return
        parent = self._parent(event, kind, host)
        if parent is not None:
            added = False
            for child_name, parent_name in _INHERITED:
                value = parent.value(parent_name)
                if child_name not in fields and value not in (None, "", "-"):
                    fields[child_name] = value
                    added = True
            self.enriched += int(added)
        process = _Process(fields.get("Image"), fields.get("CommandLine"), fields.get("User"))
        own_pid = _pid(fields.get("NewProcessId" if kind == "4688" else "ProcessId"))
        if kind == "auditd":
            own_pid = _pid(fields.get("pid"))
        if own_pid is not None:
            self.by_pid[(host, own_pid)] = process
        guid = fields.get("ProcessGuid")
        if kind == "sysmon" and guid is not None:
            self.by_guid[str(guid)] = process

    def _parent(self, event: Event, kind: str, host: str) -> _Process | None:
        fields = event.fields
        if kind == "sysmon":
            guid = fields.get("ParentProcessGuid")
            if guid is not None and str(guid) in self.by_guid:
                return self.by_guid[str(guid)]
            parent_pid = _pid(fields.get("ParentProcessId"))
        elif kind == "4688":
            parent_pid = _pid(fields.get("ProcessId"))  # the creator process
        else:
            parent_pid = _pid(fields.get("ppid"))
        return None if parent_pid is None else self.by_pid.get((host, parent_pid))


def _kind(event: Event) -> str | None:
    """`sysmon`, `4688` or `auditd` for a process start, `end` for a termination, else None."""
    fields = event.fields
    event_id = fields.get("EventID")
    channel = fields.get("Channel")
    if channel in _SYSMON_CHANNELS or (channel is None and "ProcessGuid" in fields):
        if event_id == 1:
            return "sysmon"
        if event_id == 5:
            return "end"
        return None
    if channel == "Security":
        if event_id == 4688:
            return "4688"
        if event_id == 4689:
            return "end"
        return None
    if (
        event.platform == "linux"
        and "pid" in fields
        and any(record.fields.get("type") == "EXECVE" for record in event.records)
    ):
        # A merged audit event with an EXECVE record is a program start. Every other audit
        # event also names the process's exe, but is not a start and must not replace it.
        return "auditd"
    return None
