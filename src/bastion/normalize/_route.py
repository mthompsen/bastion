"""What kind of activity an event records, shared by the OCSF and ECS views.

The routes are keyed on the channel and EventID a record carries (Sysmon on Windows and
Linux, the Security log) and on the merged auditd exec event. They decide only which
normalized shape a view uses; an event no route names keeps the generic shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from bastion.models import Event, FieldValue

SYSMON_CHANNELS = frozenset({"Microsoft-Windows-Sysmon/Operational", "Linux-Sysmon/Operational"})

#: Activity kinds. Each view maps a kind to its own class and activity.
PROCESS_START = "process_start"
PROCESS_END = "process_end"
PROCESS_ACCESS = "process_access"
PROCESS_INJECT = "process_inject"
NETWORK_OPEN = "network_open"
LOGON = "logon"
LOGOFF = "logoff"
KERBEROS_TGT = "kerberos_tgt"
KERBEROS_SERVICE = "kerberos_service"
KERBEROS_PREAUTH = "kerberos_preauth"
FILE_CREATE = "file_create"
FILE_DELETE = "file_delete"
REG_KEY_CREATE = "reg_key_create"
REG_KEY_DELETE = "reg_key_delete"
REG_KEY_RENAME = "reg_key_rename"
REG_VALUE_SET = "reg_value_set"
REG_VALUE_DELETE = "reg_value_delete"
OTHER = "other"

_SYSMON: dict[str, str] = {
    "1": PROCESS_START,
    "3": NETWORK_OPEN,
    "5": PROCESS_END,
    "8": PROCESS_INJECT,
    "10": PROCESS_ACCESS,
    "11": FILE_CREATE,
    "13": REG_VALUE_SET,
    "14": REG_KEY_RENAME,
    "23": FILE_DELETE,
    "26": FILE_DELETE,
}
#: Sysmon 12 carries both key and value operations; its EventType says which.
_SYSMON_12 = {
    "CreateKey": REG_KEY_CREATE,
    "DeleteKey": REG_KEY_DELETE,
    "DeleteValue": REG_VALUE_DELETE,
}
_SECURITY: dict[str, str] = {
    "4624": LOGON,
    "4625": LOGON,
    "4634": LOGOFF,
    "4647": LOGOFF,
    "4648": LOGON,
    "4688": PROCESS_START,
    "4689": PROCESS_END,
    "4768": KERBEROS_TGT,
    "4769": KERBEROS_SERVICE,
    "4771": KERBEROS_PREAUTH,
    "5156": NETWORK_OPEN,
}
_EXEC_SYSCALLS = frozenset({"execve", "execveat"})


def route(event: Event) -> str:
    """The activity kind of ``event``, or :data:`OTHER`."""
    fields = event.fields
    channel = str(fields.get("Channel") or "")
    event_id = str(fields.get("EventID") or "")
    if channel in SYSMON_CHANNELS:
        if event_id == "12":
            return _SYSMON_12.get(str(fields.get("EventType") or ""), OTHER)
        return _SYSMON.get(event_id, OTHER)
    if channel == "Security":
        return _SECURITY.get(event_id, OTHER)
    if event.platform == "linux" and str(fields.get("SYSCALL") or "") in _EXEC_SYSCALLS:
        return PROCESS_START
    return OTHER


@dataclass
class FieldReader:
    """Reads an event's fields and remembers which ones a view used.

    ``rest()`` returns every field the view did not use, so a view can keep them instead
    of dropping them.
    """

    fields: dict[str, FieldValue]
    used: set[str] = field(default_factory=set)

    def text(self, *names: str) -> str | None:
        """The first non-empty value among ``names``, as text; marks every name read."""
        found: str | None = None
        for name in names:
            value = self.fields.get(name)
            if value is None or value == "" or value == "-":
                continue
            self.used.add(name)
            if found is None:
                found = str(value)
        return found

    def integer(self, *names: str) -> int | None:
        """The first value among ``names`` that parses as an integer (decimal or ``0x``)."""
        for name in names:
            value = self.fields.get(name)
            if value is None or value == "":
                continue
            try:
                number = value if isinstance(value, int) else int(str(value).strip(), 0)
            except ValueError:
                continue
            self.used.add(name)
            return number
        return None

    def mark(self, *names: str) -> None:
        self.used.update(name for name in names if name in self.fields)

    def rest(self) -> dict[str, FieldValue]:
        return {k: v for k, v in self.fields.items() if k not in self.used}


def basename(path: str) -> str:
    """The last component of a Windows or POSIX path."""
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def epoch_ms(timestamp: datetime | None) -> int | None:
    if timestamp is None:
        return None
    return int(timestamp.timestamp() * 1000)
