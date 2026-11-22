"""OCSF 1.9.0 view of an event, and detections as OCSF Detection Findings.

Classes used (OCSF schema 1.9.0, ``ocsf/ocsf-schema`` at the tag ``1.9.0``):

- Process Activity (1007): Sysmon 1, 5, 8, 10; Security 4688, 4689; auditd exec events.
- Network Activity (4001): Sysmon 3; Security 5156.
- Authentication (3002): Security 4624, 4625, 4634, 4647, 4648, 4768, 4769, 4771.
- File System Activity (1001): Sysmon 11, 23, 26.
- Registry Key Activity (201001) and Registry Value Activity (201002), from the Windows
  extension: Sysmon 12, 13, 14.
- Base Event (0) for every other event.
- Detection Finding (2004) for a Bastion detection.

The ``host`` profile is applied (``metadata.profiles``). Every event field the view has no
attribute for goes to ``unmapped`` under its source name, and the source record is kept in
``raw_data``.
Enumerations Bastion cannot decide are ``0`` (Unknown); none is guessed. An event without a
timestamp has no ``time``: OCSF requires one, and Bastion does not invent it, so such a view
is marked with the label ``bastion:no-timestamp`` and is not schema valid. In the same way,
an attribute a class requires stays absent when the source record does not carry it, rather
than being filled in. ``actor`` is the case that occurs: Process, File System, Registry Key and
Registry Value Activity require it, and a record that names no acting process or user (Sysmon
5 names only the process that ended and its owner) gets no ``actor`` and the label
``bastion:no-actor``; a Detection Finding on such an event carries the same label.
"""

from __future__ import annotations

import hashlib
from typing import Any

from bastion import __version__
from bastion.models import Detection, Event, TechniqueRef
from bastion.normalize import _route as r
from bastion.normalize._route import FieldReader, basename, epoch_ms

OCSF_VERSION = "1.9.0"
#: Bastion reads host logs, so every view and finding applies OCSF's ``host`` profile
#: (``device`` and ``actor`` on every class).
PROFILES = ("host",)

#: Labels on a view (and its finding) that lacks a value its class requires.
NO_TIMESTAMP = "bastion:no-timestamp"
NO_ACTOR = "bastion:no-actor"
#: Classes whose ``actor`` OCSF 1.9.0 requires (with the ``host`` profile).
_ACTOR_REQUIRED = frozenset({1001, 1007, 201001, 201002})

_PRODUCT = {"name": "Bastion", "vendor_name": "Bastion", "version": __version__}

#: kind -> (class_uid, class_name, category_uid, category_name, activity_id, activity_name)
_CLASSES: dict[str, tuple[int, str, int, str, int, str]] = {
    r.PROCESS_START: (1007, "Process Activity", 1, "System Activity", 1, "Launch"),
    r.PROCESS_END: (1007, "Process Activity", 1, "System Activity", 2, "Terminate"),
    r.PROCESS_ACCESS: (1007, "Process Activity", 1, "System Activity", 3, "Open"),
    r.PROCESS_INJECT: (1007, "Process Activity", 1, "System Activity", 4, "Inject"),
    r.NETWORK_OPEN: (4001, "Network Activity", 4, "Network Activity", 1, "Open"),
    r.LOGON: (3002, "Authentication", 3, "Identity & Access Management", 1, "Logon"),
    r.LOGOFF: (3002, "Authentication", 3, "Identity & Access Management", 2, "Logoff"),
    r.KERBEROS_TGT: (
        3002,
        "Authentication",
        3,
        "Identity & Access Management",
        3,
        "Authentication Ticket",
    ),
    r.KERBEROS_SERVICE: (
        3002,
        "Authentication",
        3,
        "Identity & Access Management",
        4,
        "Service Ticket Request",
    ),
    r.KERBEROS_PREAUTH: (3002, "Authentication", 3, "Identity & Access Management", 6, "Preauth"),
    r.FILE_CREATE: (1001, "File System Activity", 1, "System Activity", 1, "Create"),
    r.FILE_DELETE: (1001, "File System Activity", 1, "System Activity", 4, "Delete"),
    r.REG_KEY_CREATE: (201001, "Registry Key Activity", 1, "System Activity", 1, "Create"),
    r.REG_KEY_DELETE: (201001, "Registry Key Activity", 1, "System Activity", 4, "Delete"),
    r.REG_KEY_RENAME: (201001, "Registry Key Activity", 1, "System Activity", 5, "Rename"),
    r.REG_VALUE_SET: (201002, "Registry Value Activity", 1, "System Activity", 2, "Set"),
    r.REG_VALUE_DELETE: (201002, "Registry Value Activity", 1, "System Activity", 4, "Delete"),
}

#: OCSF ``severity_id`` for Sigma levels (Informational 1 ... Critical 5).
SIGMA_SEVERITY = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
_SEVERITY_NAMES = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
}

#: Windows logon types; OCSF ``logon_type_id`` uses the same numbers.
_LOGON_TYPES = {2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13}

_REGULAR_FILE = 1


def _file(path: str) -> dict[str, Any]:
    return {"path": path, "name": basename(path), "type_id": _REGULAR_FILE}


def _user(
    reader: FieldReader, name_fields: tuple[str, ...], **extra: tuple[str, ...]
) -> dict[str, Any]:
    user: dict[str, Any] = {}
    name = reader.text(*name_fields)
    if name is not None:
        if "\\" in name:
            domain, _, short = name.partition("\\")
            user["name"] = short
            user["domain"] = domain
        else:
            user["name"] = name
    for attr, names in extra.items():
        value = reader.text(*names)
        if value is not None:
            user[attr] = value
    return user


def _process(
    reader: FieldReader,
    *,
    image: tuple[str, ...],
    pid: tuple[str, ...],
    cmd: tuple[str, ...] = (),
    guid: tuple[str, ...] = (),
    user: tuple[str, ...] = (),
) -> dict[str, Any]:
    before = set(reader.used)
    process: dict[str, Any] = {}
    path = reader.text(*image)
    if path is not None:
        process["file"] = _file(path)
        process["name"] = basename(path)
    number = reader.integer(*pid)
    if number is not None:
        process["pid"] = number
    for attr, names in (("cmd_line", cmd), ("uid", guid)):
        value = reader.text(*names) if names else None
        if value is not None:
            process[attr] = value
    owner = _user(reader, user) if user else {}
    if owner:
        process["user"] = owner
    if "pid" not in process and "uid" not in process:
        # OCSF identifies a process by pid or uid; without either the fields stay unmapped.
        reader.used = before
        return {}
    return process


def _device(reader: FieldReader) -> dict[str, Any]:
    """The host the record came from; empty when the record names none (OCSF needs an id)."""
    hostname = reader.text("Computer", "hostname", "host", "node")
    return {"type_id": 0, "hostname": hostname} if hostname is not None else {}


def _metadata(reader: FieldReader, event: Event) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "product": dict(_PRODUCT),
        "version": OCSF_VERSION,
        "profiles": list(PROFILES),
    }
    for attr, names in (
        ("log_name", ("Channel",)),
        ("log_provider", ("Provider_Name", "Provider")),
        ("event_code", ("EventID",)),
        ("uid", ("EventRecordID",)),
    ):
        value = reader.text(*names)
        if value is not None:
            metadata[attr] = value
    metadata["log_source"] = event.source
    if event.timestamp is None:
        metadata["labels"] = [NO_TIMESTAMP]
    return metadata


def _process_view(kind: str, reader: FieldReader, view: dict[str, Any]) -> None:
    if kind in (r.PROCESS_ACCESS, r.PROCESS_INJECT):
        actor = _process(
            reader, image=("SourceImage",), pid=("SourceProcessId",), guid=("SourceProcessGUID",)
        )
        target = _process(
            reader, image=("TargetImage",), pid=("TargetProcessId",), guid=("TargetProcessGUID",)
        )
        reader.mark("GrantedAccess", "CallTrace", "StartAddress", "StartFunction", "StartModule")
    else:
        # Security 4688 names the new process NewProcessId and its creator ProcessId;
        # Sysmon, 4689 and auditd name the process itself ProcessId (or pid).
        security_start = reader.fields.get("Channel") == "Security" and kind == r.PROCESS_START
        target = _process(
            reader,
            image=("Image", "NewProcessName", "ProcessName", "exe"),
            pid=("NewProcessId",) if security_start else ("ProcessId", "pid"),
            cmd=("CommandLine",),
            guid=("ProcessGuid",),
            user=("User",),
        )
        parent = _process(
            reader,
            image=("ParentImage", "ParentProcessName"),
            pid=("ProcessId",) if security_start else ("ParentProcessId", "ppid"),
            cmd=("ParentCommandLine",),
            guid=("ParentProcessGuid",),
        )
        working = reader.text("CurrentDirectory", "cwd")
        if working is not None:
            target["working_directory"] = working
        integrity = reader.text("IntegrityLevel")
        if integrity is not None:
            target["integrity"] = integrity
        if parent:
            target["parent_process"] = parent
        actor = parent
    view["process"] = target
    view["actor"] = {"process": actor} if actor else {}
    if reader.fields.get("Channel") == "Security":
        # 4688 and 4689 name the account that created or ended the process: the actor user.
        subject = _user(
            reader, ("SubjectUserName",), domain=("SubjectDomainName",), uid=("SubjectUserSid",)
        )
        if subject:
            view["actor"]["user"] = subject


def _network_view(reader: FieldReader, view: dict[str, Any]) -> None:
    for side, ip, port, host in (
        ("src_endpoint", ("SourceIp", "SourceAddress"), ("SourcePort",), ("SourceHostname",)),
        (
            "dst_endpoint",
            ("DestinationIp", "DestAddress"),
            ("DestinationPort", "DestPort"),
            ("DestinationHostname",),
        ),
    ):
        endpoint: dict[str, Any] = {}
        address = reader.text(*ip)
        if address is not None:
            endpoint["ip"] = address
        number = reader.integer(*port)
        if number is not None:
            endpoint["port"] = number
        name = reader.text(*host)
        if name is not None:
            endpoint["hostname"] = name
        if endpoint:
            view[side] = endpoint
    connection: dict[str, Any] = {"direction_id": _direction(reader)}
    protocol = reader.text("Protocol")
    if protocol is not None:
        connection["protocol_name"] = protocol.lower()
    view["connection_info"] = connection
    actor = _process(
        reader,
        image=("Image", "Application"),
        pid=("ProcessId", "ProcessID"),
        guid=("ProcessGuid",),
        user=("User",),
    )
    if actor:
        view["actor"] = {"process": actor}


#: Security 5156 ``Direction`` message codes; Sysmon 3 ``Initiated`` (the process opened it).
_DIRECTIONS = {"%%14592": 1, "%%14593": 2, "inbound": 1, "outbound": 2}


def _direction(reader: FieldReader) -> int:
    """OCSF ``direction_id``: 1 Inbound, 2 Outbound, 0 Unknown."""
    initiated = reader.text("Initiated")
    if initiated is not None:
        return 2 if initiated.lower() == "true" else 1
    direction = reader.text("Direction")
    return _DIRECTIONS.get((direction or "").lower(), 0)


def _auth_view(kind: str, reader: FieldReader, view: dict[str, Any]) -> None:
    event_id = str(reader.fields.get("EventID") or "")
    user = _user(
        reader,
        ("TargetUserName",),
        domain=("TargetDomainName",),
        uid=("TargetUserSid", "TargetSid"),
    )
    view["user"] = user
    subject = _user(
        reader, ("SubjectUserName",), domain=("SubjectDomainName",), uid=("SubjectUserSid",)
    )
    if subject:
        view["actor"] = {"user": subject}
    source: dict[str, Any] = {}
    address = reader.text("IpAddress")
    if address is not None:
        source["ip"] = address
    port = reader.integer("IpPort")
    if port:
        source["port"] = port
    workstation = reader.text("WorkstationName")
    if workstation is not None:
        source["hostname"] = workstation
    if source:
        view["src_endpoint"] = source
    logon_type = reader.integer("LogonType")
    if logon_type is not None:
        view["logon_type_id"] = logon_type if logon_type in _LOGON_TYPES else 99
        if logon_type not in _LOGON_TYPES:
            view["logon_type"] = str(logon_type)
    package = reader.text("AuthenticationPackageName", "PackageName")
    if package is not None:
        view["auth_protocol"] = package
        view["auth_protocol_id"] = (
            99
            if package.lower() not in ("ntlm", "kerberos")
            else (1 if package.lower() == "ntlm" else 2)
        )
    service = reader.text("ServiceName")
    if service is not None:
        view["service"] = {"name": service}
    # The Security log is written by the computer authenticated to: the destination.
    hostname = view.get("device", {}).get("hostname")
    if hostname:
        view["dst_endpoint"] = {"hostname": hostname}
    status = reader.text("Status")
    if status is not None:
        view["status_code"] = status
    sub_status = reader.text("SubStatus", "FailureReason")
    if sub_status is not None:
        view["status_detail"] = sub_status
    if event_id in ("4624", "4634", "4647", "4648"):
        view["status_id"] = 1
    elif event_id in ("4625", "4771"):
        view["status_id"] = 2
    elif status is not None:
        view["status_id"] = 1 if status.lower() in ("0x0", "0") else 2


def _file_view(reader: FieldReader, view: dict[str, Any]) -> None:
    path = reader.text("TargetFilename")
    view["file"] = _file(path) if path is not None else {"name": "", "type_id": 0}
    actor = _process(
        reader, image=("Image",), pid=("ProcessId",), guid=("ProcessGuid",), user=("User",)
    )
    view["actor"] = {"process": actor} if actor else {}


def _registry_view(kind: str, reader: FieldReader, view: dict[str, Any]) -> None:
    target = reader.text("TargetObject")
    reader.mark("EventType")
    if kind == r.REG_KEY_RENAME:
        new_name = reader.text("NewName")
        view["reg_key"] = {"path": new_name or ""}
        if target is not None:
            view["prev_reg_key"] = {"path": target}
    elif kind in (r.REG_VALUE_SET, r.REG_VALUE_DELETE):
        value: dict[str, Any] = {"path": target or "", "name": basename(target or "")}
        details = reader.text("Details")
        if details is not None:
            value["data"] = details
        view["reg_value"] = value
    else:
        view["reg_key"] = {"path": target or ""}
    actor = _process(
        reader, image=("Image",), pid=("ProcessId",), guid=("ProcessGuid",), user=("User",)
    )
    view["actor"] = {"process": actor} if actor else {}


def to_ocsf(event: Event) -> dict[str, Any]:
    """The OCSF 1.9.0 view of ``event`` (a pure function; ``event`` is not changed)."""
    kind = r.route(event)
    reader = FieldReader(event.fields)
    class_uid, class_name, category_uid, category_name, activity_id, activity_name = _CLASSES.get(
        kind, (0, "Base Event", 0, "Uncategorized", 0, "Unknown")
    )
    view: dict[str, Any] = {
        "class_uid": class_uid,
        "class_name": class_name,
        "category_uid": category_uid,
        "category_name": category_name,
        "activity_id": activity_id,
        "activity_name": activity_name,
        "type_uid": class_uid * 100 + activity_id,
        "severity_id": 0,
        "severity": "Unknown",
    }
    time = epoch_ms(event.timestamp)
    if time is not None:
        view["time"] = time
    view["metadata"] = _metadata(reader, event)
    device = _device(reader)
    if device:
        view["device"] = device
    if kind in (r.PROCESS_START, r.PROCESS_END, r.PROCESS_ACCESS, r.PROCESS_INJECT):
        _process_view(kind, reader, view)
    elif kind == r.NETWORK_OPEN:
        _network_view(reader, view)
    elif class_uid == 3002:
        _auth_view(kind, reader, view)
    elif kind in (r.FILE_CREATE, r.FILE_DELETE):
        _file_view(reader, view)
    elif class_uid in (201001, 201002):
        _registry_view(kind, reader, view)
    if view.get("actor") == {}:
        del view["actor"]
    if class_uid in _ACTOR_REQUIRED and "actor" not in view:
        view["metadata"].setdefault("labels", []).append(NO_ACTOR)
    reader.mark("UtcTime")
    rest = reader.rest()
    if rest:
        view["unmapped"] = rest
    view["raw_data"] = event.raw
    return view


# --- Detection Finding --------------------------------------------------------------------


def _attacks(techniques: list[TechniqueRef], attack_version: str | None) -> list[dict[str, Any]]:
    """One OCSF ``attack`` object per (technique, tactic) the detection maps to."""
    attacks: list[dict[str, Any]] = []
    for ref in techniques:
        base: dict[str, Any] = {}
        if "." in ref.id:
            base["technique"] = {"uid": ref.id.split(".", 1)[0]}
            base["sub_technique"] = {"uid": ref.id, "name": ref.name}
        else:
            base["technique"] = {"uid": ref.id, "name": ref.name}
        if attack_version:
            base["version"] = attack_version
        for tactic in ref.tactics or [""]:
            item = dict(base)
            if tactic:
                item["tactic"] = {"name": tactic}
            attacks.append(item)
    return attacks


def finding_uid(detection: Detection) -> str:
    """Deterministic id: the rule id and the raw record it fired on."""
    digest = hashlib.sha256(f"{detection.rule_id}\n{detection.event.raw}".encode())
    return digest.hexdigest()[:32]


def detection_finding(
    detection: Detection,
    *,
    attack_version: str | None = None,
    sigma_version: str | None = None,
    hunting: bool | None = None,
) -> dict[str, Any]:
    """A Bastion detection as an OCSF 1.9.0 Detection Finding (2004), activity Create.

    The finding's time is the event's time (no wall clock is read). The matched fields go
    to the evidence ``data``; the event's own OCSF view is the evidence's source record.
    """
    severity_id = SIGMA_SEVERITY.get(detection.level, 0)
    analytic: dict[str, Any] = {
        "uid": detection.rule_id,
        "name": detection.rule_title,
        "type_id": 1,
        "type": "Rule",
    }
    if sigma_version:
        analytic["version"] = sigma_version
    finding_info: dict[str, Any] = {
        "uid": finding_uid(detection),
        "title": detection.rule_title,
        "analytic": analytic,
        "types": ["Sigma rule match"],
    }
    attacks = _attacks(detection.techniques, attack_version)
    if attacks:
        finding_info["attacks"] = attacks
    event_view = to_ocsf(detection.event)
    evidence: dict[str, Any] = {"data": {"matched_fields": dict(detection.matched_fields)}}
    for attr in (
        "actor",
        "process",
        "file",
        "reg_key",
        "reg_value",
        "src_endpoint",
        "dst_endpoint",
        "user",
    ):
        if attr in event_view and attr in _EVIDENCE_ATTRS and event_view[attr]:
            evidence[attr] = event_view[attr]
    finding: dict[str, Any] = {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,
        "severity_id": severity_id,
        "severity": _SEVERITY_NAMES.get(severity_id, "Unknown"),
        "status_id": 1,
        "status": "New",
        "is_alert": True,
        "finding_info": finding_info,
        "evidences": [evidence],
        "metadata": {
            "product": dict(_PRODUCT),
            "version": OCSF_VERSION,
            "profiles": list(PROFILES),
            "log_source": detection.event.source,
        },
        "unmapped": {
            "sigma_level": detection.level,
            "hunting_class": hunting,
            "source_event_class_uid": event_view["class_uid"],
        },
        "raw_data": detection.event.raw,
    }
    if hunting is None:
        del finding["unmapped"]["hunting_class"]
    time = epoch_ms(detection.event.timestamp)
    if time is not None:
        finding["time"] = time
    labels = [
        label
        for label in event_view["metadata"].get("labels", [])
        if label in (NO_TIMESTAMP, NO_ACTOR)
    ]
    if labels:
        finding["metadata"]["labels"] = labels
    device = event_view.get("device")
    if device:
        finding["device"] = device
    return finding


#: Evidence Artifacts attributes Bastion fills from the event view (OCSF 1.9.0 ``evidences``).
_EVIDENCE_ATTRS = frozenset(
    {"actor", "process", "file", "reg_key", "reg_value", "src_endpoint", "dst_endpoint", "user"}
)
