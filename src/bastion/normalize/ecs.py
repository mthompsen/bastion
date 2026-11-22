"""Elastic Common Schema 9.5.0 view of an event.

The view is a nested ECS document. It uses only fields ECS 9.5.0 defines
(``elastic/ecs`` at the tag ``v9.5.0``, ``generated/ecs/ecs_flat.yml``), plus one custom
field set, ``bastion``, as the ECS guidelines advise for custom data: ``bastion.unmapped``
keeps every event field the view has no ECS field for, under its source name. The source
record is ``event.original``. ``event.category`` and ``event.type`` take values from the ECS
allowed lists only, and only when the route is known; otherwise they are left out.
"""

from __future__ import annotations

from typing import Any

from bastion.models import Event
from bastion.normalize import _route as r
from bastion.normalize._route import FieldReader, basename

ECS_VERSION = "9.5.0"

#: kind -> (event.category, event.type)
_CATEGORIZATION: dict[str, tuple[list[str], list[str]]] = {
    r.PROCESS_START: (["process"], ["start"]),
    r.PROCESS_END: (["process"], ["end"]),
    r.PROCESS_ACCESS: (["process"], ["access"]),
    r.PROCESS_INJECT: (["process"], ["change"]),
    r.NETWORK_OPEN: (["network"], ["connection", "start"]),
    r.LOGON: (["authentication"], ["start"]),
    r.LOGOFF: (["authentication"], ["end"]),
    r.KERBEROS_TGT: (["authentication"], ["start"]),
    r.KERBEROS_SERVICE: (["authentication"], ["start"]),
    r.KERBEROS_PREAUTH: (["authentication"], ["start"]),
    r.FILE_CREATE: (["file"], ["creation"]),
    r.FILE_DELETE: (["file"], ["deletion"]),
    r.REG_KEY_CREATE: (["registry"], ["creation"]),
    r.REG_KEY_DELETE: (["registry"], ["deletion"]),
    r.REG_KEY_RENAME: (["registry"], ["change"]),
    r.REG_VALUE_SET: (["registry"], ["change"]),
    r.REG_VALUE_DELETE: (["registry"], ["deletion"]),
}

_REGISTRY_HIVES = {
    "HKLM": "HKLM",
    "HKEY_LOCAL_MACHINE": "HKLM",
    "HKU": "HKU",
    "HKEY_USERS": "HKU",
    "HKCU": "HKCU",
    "HKEY_CURRENT_USER": "HKCU",
    "HKCR": "HKCR",
    "HKEY_CLASSES_ROOT": "HKCR",
}


def _put(doc: dict[str, Any], dotted: str, value: Any) -> None:
    node = doc
    *parents, leaf = dotted.split(".")
    for part in parents:
        node = node.setdefault(part, {})
    node[leaf] = value


def _process(
    doc: dict[str, Any],
    prefix: str,
    reader: FieldReader,
    *,
    image: tuple[str, ...],
    pid: tuple[str, ...],
    cmd: tuple[str, ...] = (),
    guid: tuple[str, ...] = (),
) -> None:
    path = reader.text(*image)
    if path is not None:
        _put(doc, f"{prefix}.executable", path)
        _put(doc, f"{prefix}.name", basename(path))
    number = reader.integer(*pid)
    if number is not None:
        _put(doc, f"{prefix}.pid", number)
    for attr, names in (("command_line", cmd), ("entity_id", guid)):
        value = reader.text(*names) if names else None
        if value is not None:
            _put(doc, f"{prefix}.{attr}", value)


def _user(doc: dict[str, Any], prefix: str, reader: FieldReader, *names: str) -> None:
    value = reader.text(*names)
    if value is None:
        return
    if "\\" in value:
        domain, _, name = value.partition("\\")
        _put(doc, f"{prefix}.domain", domain)
        _put(doc, f"{prefix}.name", name)
    else:
        _put(doc, f"{prefix}.name", value)


def _registry(doc: dict[str, Any], path: str) -> None:
    _put(doc, "registry.path", path)
    hive, _, key = path.partition("\\")
    if hive.upper() in _REGISTRY_HIVES:
        _put(doc, "registry.hive", _REGISTRY_HIVES[hive.upper()])
        _put(doc, "registry.key", key)


def to_ecs(event: Event) -> dict[str, Any]:
    """The ECS 9.5.0 view of ``event`` (a pure function; ``event`` is not changed)."""
    kind = r.route(event)
    reader = FieldReader(event.fields)
    doc: dict[str, Any] = {"ecs": {"version": ECS_VERSION}}
    if event.timestamp is not None:
        doc["@timestamp"] = event.timestamp.isoformat()
    _put(doc, "event.kind", "event")
    categorization = _CATEGORIZATION.get(kind)
    if categorization is not None:
        _put(doc, "event.category", list(categorization[0]))
        _put(doc, "event.type", list(categorization[1]))
    for dotted, names in (
        ("event.code", ("EventID",)),
        ("event.provider", ("Provider_Name", "Provider")),
        ("host.name", ("Computer", "hostname", "host", "node")),
    ):
        value = reader.text(*names)
        if value is not None:
            _put(doc, dotted, value)
    channel = reader.text("Channel")
    if channel is not None:
        _put(doc, "event.dataset", channel)
    reader.mark("UtcTime")

    security = event.fields.get("Channel") == "Security"
    if kind in (r.PROCESS_START, r.PROCESS_END):
        security_start = security and kind == r.PROCESS_START
        _process(
            doc,
            "process",
            reader,
            image=("Image", "NewProcessName", "ProcessName", "exe"),
            pid=("NewProcessId",) if security_start else ("ProcessId", "pid"),
            cmd=("CommandLine",),
            guid=("ProcessGuid",),
        )
        _process(
            doc,
            "process.parent",
            reader,
            image=("ParentImage", "ParentProcessName"),
            pid=("ProcessId",) if security_start else ("ParentProcessId", "ppid"),
            cmd=("ParentCommandLine",),
            guid=("ParentProcessGuid",),
        )
        working = reader.text("CurrentDirectory", "cwd")
        if working is not None:
            _put(doc, "process.working_directory", working)
        _user(doc, "user", reader, "User")
    elif kind in (r.PROCESS_ACCESS, r.PROCESS_INJECT):
        _process(
            doc,
            "process",
            reader,
            image=("SourceImage",),
            pid=("SourceProcessId",),
            guid=("SourceProcessGUID",),
        )
        # ECS has no target-process field set; the target stays in bastion.unmapped.
    elif kind == r.NETWORK_OPEN:
        for side, ip, port, host in (
            ("source", ("SourceIp", "SourceAddress"), ("SourcePort",), ("SourceHostname",)),
            (
                "destination",
                ("DestinationIp", "DestAddress"),
                ("DestinationPort", "DestPort"),
                ("DestinationHostname",),
            ),
        ):
            address = reader.text(*ip)
            if address is not None:
                _put(doc, f"{side}.ip", address)
            number = reader.integer(*port)
            if number is not None:
                _put(doc, f"{side}.port", number)
            name = reader.text(*host)
            if name is not None:
                _put(doc, f"{side}.domain", name)
        protocol = reader.text("Protocol")
        if protocol is not None:
            _put(doc, "network.transport", protocol.lower())
        _process(
            doc,
            "process",
            reader,
            image=("Image", "Application"),
            pid=("ProcessId", "ProcessID"),
            guid=("ProcessGuid",),
        )
        _user(doc, "user", reader, "User")
    elif categorization is not None and categorization[0] == ["authentication"]:
        _user(doc, "user", reader, "TargetUserName")
        domain = reader.text("TargetDomainName")
        if domain is not None:
            _put(doc, "user.domain", domain)
        sid = reader.text("TargetUserSid", "TargetSid")
        if sid is not None:
            _put(doc, "user.id", sid)
        address = reader.text("IpAddress")
        if address is not None:
            _put(doc, "source.ip", address)
        source_port = reader.integer("IpPort")
        if source_port:
            _put(doc, "source.port", source_port)
        workstation = reader.text("WorkstationName")
        if workstation is not None:
            _put(doc, "source.domain", workstation)
        event_id = str(event.fields.get("EventID") or "")
        status = reader.text("Status")
        if event_id in ("4624", "4634", "4647", "4648"):
            _put(doc, "event.outcome", "success")
        elif event_id in ("4625", "4771"):
            _put(doc, "event.outcome", "failure")
        elif status is not None:
            _put(doc, "event.outcome", "success" if status.lower() in ("0x0", "0") else "failure")
    elif kind in (r.FILE_CREATE, r.FILE_DELETE):
        path = reader.text("TargetFilename")
        if path is not None:
            _put(doc, "file.path", path)
            _put(doc, "file.name", basename(path))
        _process(
            doc, "process", reader, image=("Image",), pid=("ProcessId",), guid=("ProcessGuid",)
        )
        _user(doc, "user", reader, "User")
    elif categorization is not None and categorization[0] == ["registry"]:
        reader.mark("EventType")
        target = reader.text("NewName") if kind == r.REG_KEY_RENAME else None
        target = target or reader.text("TargetObject")
        if target is not None:
            _registry(doc, target)
        if kind in (r.REG_VALUE_SET, r.REG_VALUE_DELETE) and target is not None:
            _put(doc, "registry.value", basename(target))
        details = reader.text("Details")
        if details is not None:
            _put(doc, "registry.data.strings", [details])
        _process(
            doc, "process", reader, image=("Image",), pid=("ProcessId",), guid=("ProcessGuid",)
        )
        _user(doc, "user", reader, "User")

    rest = reader.rest()
    if rest:
        _put(doc, "bastion.unmapped", rest)
    _put(doc, "event.original", event.raw)
    return doc
