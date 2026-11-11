"""Linux auditd log ingestion.

Parses ``/var/log/audit/audit.log``-style records. Audit events span
multiple lines (SYSCALL, EXECVE, CWD, PATH, PROCTITLE, ...) that share one
audit id (``msg=audit(<stamp>:<serial>)``); records with the same id are
merged into a single Event so a rule can match the executable from the
SYSCALL record and the argv from the EXECVE record together.

Two on-disk formats are read:

- **Raw** (what auditd writes): ``msg=audit(1722957155.494:4802): ...``.
  Values are quoted, hex encoded, or bare. With ``log_format=ENRICHED`` a
  ``\\x1d`` (group separator) is followed by the interpreted names
  (``ARCH=x86_64 SYSCALL=connect AUID="ubuntu"``); both halves are read.
- **Interpreted** (``ausearch -i``): ``msg=audit(04/16/2025 09:14:42.784:96444) : ...``.
  Values are already decoded and are never quoted, so an EXECVE argument or
  a PROCTITLE can contain spaces. The timestamp is rendered in the local time
  of whatever host ran ``ausearch``, which the record does not name; Bastion
  reads it as UTC and says so here rather than guessing a zone.

Field normalization: every ``key=value`` pair lands in ``Event.fields`` under
its auditd name (``exe``, ``comm``, ``syscall``, ``key``, ``uid``, ``a0``...,
``cwd``, ``name``, ``proctitle``, ...). The pairs inside a single-quoted
``msg='...'`` (SERVICE_STOP, ADD_USER, USER_CMD) and inside a brace group are
also lifted to fields. Two aliases are added so Sigma's generic process
fields work: ``Image`` (from ``exe``) and ``CommandLine`` (the EXECVE argv
joined). ``CommandLine`` is built from EXECVE only; the ``a0`` to ``a3`` of a
SYSCALL record are the raw syscall arguments (pointers), not a command.
Lines that are not audit records are skipped with a warning and counted.

The record merging, argv handling, hyphenated keys, brace groups and the
field-scoped hex decoding are ported from Citadel's ``core/ingest/auditd.py``
(commits 496c484, 5bd6f5d, 5cac630, 56dcb04), which found each defect on its
own captures.
"""

from __future__ import annotations

import logging
import re
from collections import Counter, OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from bastion.models import Event, FieldValue
from bastion.pipelines import AuditdMapping, linux_pipeline

logger = logging.getLogger(__name__)

#: One audit record. ``stamp`` is an epoch (raw) or ``MM/DD/YYYY HH:MM:SS.mmm``
#: (interpreted); raw records separate the body with ``): ``, interpreted ones with ``) : ``.
_RECORD_RE = re.compile(
    r"^type=(?P<type>\w+)\s+msg=audit\((?P<stamp>\d+(?:\.\d+)?|\d\d/\d\d/\d{4} [\d:.]+)"
    r":(?P<serial>\d+)\)\s*:\s?(?P<body>.*)$"
)
#: A ``key=value`` pair in a raw record. Keys carry hyphens (``old-auid``); a value is a
#: double-quoted string, a single-quoted ``msg='...'`` group, a brace group, or a bare token.
_PAIR_RE = re.compile(r"([\w-]+)=(\"[^\"]*\"|'[^']*'|\{[^}]*\}|\S+)")
_HEX_RE = re.compile(r"^(?:[0-9A-F]{2})+$")
#: argv fields (a0, a1, ...) of an EXECVE record.
_ARG_RE = re.compile(r"^a(\d+)$")
#: ``ausearch`` prints this between events; it carries no data.
_SEPARATOR = "----"
#: The enriched half of a raw record starts after this character.
_ENRICHED_SEPARATOR = "\x1d"

#: Fields auditd may hex encode in raw records; nothing else is decoded, because a bare
#: ``4294967295`` (no session) is valid hex and is a number. See Citadel 5cac630.
_DECODABLE = frozenset({"proctitle", "cwd", "name", "comm", "exe", "key"})

#: How many records an audit id may go unseen before its event is emitted. The records of
#: one event are usually adjacent and are not always (several CPUs write at once); Citadel
#: measured a worst case of 28 foreign records in between. See Citadel 5bd6f5d.
MERGE_WINDOW_RECORDS = 1000


def _decode_raw(key: str, value: str, record_type: str = "") -> str:
    """Unquote a raw value, and hex decode it only where auditd could have encoded one.

    ``a0``, ``a1`` ... are hex encoded argv only on EXECVE; on SYSCALL they are the raw syscall
    arguments, already in hex, and decoding them turned ``a0=26`` into ``&``.
    """
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    encodable = key in _DECODABLE or (record_type == "EXECVE" and _ARG_RE.match(key))
    if encodable and _HEX_RE.match(value):
        decoded = bytes.fromhex(value).decode("utf-8", errors="replace")
        # A proctitle is the argv joined by NUL bytes; ausearch -i shows it space-joined.
        return decoded.replace("\x00", " ").rstrip() if key == "proctitle" else decoded
    return value


def _raw_pairs(record_type: str, body: str) -> Iterator[tuple[str, str, str]]:
    """``(key, decoded value, undecoded value)`` for each pair of a raw record body."""
    for half in body.split(_ENRICHED_SEPARATOR):
        for key, value in _PAIR_RE.findall(half):
            yield key, _decode_raw(key, value, record_type), value


def _interpreted_pairs(record_type: str, body: str) -> Iterator[tuple[str, str, str]]:
    """Pairs of an ``ausearch -i`` record body, whose values may contain spaces.

    PROCTITLE holds one field that runs to the end of the line. EXECVE holds ``argc`` and
    then ``a0`` to ``a<argc-1>`` in order, each running to the next argument's key. Every
    other interpreted record type observed (SYSCALL, PATH, CWD, DAEMON_*, SERVICE_*) has
    space-free values.
    """
    body = body.rstrip()
    if record_type == "PROCTITLE" and body.startswith("proctitle="):
        value = body[len("proctitle=") :]
        yield "proctitle", value, value
        return
    if record_type == "EXECVE":
        argc_match = re.match(r"argc=(\d+)\s*", body)
        if argc_match is not None:
            yield "argc", argc_match.group(1), argc_match.group(1)
            rest = body[argc_match.end() :]
            argc = int(argc_match.group(1))
            for index in range(argc):
                prefix = f"a{index}="
                if not rest.startswith(prefix):
                    break
                rest = rest[len(prefix) :]
                if index + 1 < argc:
                    end = rest.find(f" a{index + 1}=")
                    value, rest = (rest, "") if end < 0 else (rest[:end], rest[end + 1 :])
                else:
                    value, rest = rest, ""
                yield f"a{index}", value, value
            return
    for key, value in _PAIR_RE.findall(body):
        yield key, value, value


def _timestamp(stamp: str) -> datetime:
    if "/" in stamp:
        return datetime.strptime(stamp, "%m/%d/%Y %H:%M:%S.%f").replace(tzinfo=UTC)
    return datetime.fromtimestamp(float(stamp), tz=UTC)


@dataclass
class _Partial:
    """One audit event being assembled from records that may not be adjacent."""

    timestamp: datetime
    fields: dict[str, FieldValue] = field(default_factory=dict)
    argv: dict[int, str] = field(default_factory=dict)
    raw_lines: list[str] = field(default_factory=list)
    #: each record's own fields, in arrival order, for per-record rule evaluation
    records: list[tuple[dict[str, FieldValue], str]] = field(default_factory=list)
    last_seen: int = 0

    def absorb(self, match: re.Match[str], raw: str, seen: int) -> None:
        self.raw_lines.append(raw)
        self.last_seen = seen
        record_type = match.group("type")
        # The merged event's ``type`` is its first record's; each record keeps its own in
        # ``records`` (finding F1 of B2: a merged event typed SYSCALL hid its EXECVE record).
        self.fields.setdefault("type", record_type)
        own: dict[str, FieldValue] = {"type": record_type}
        self.records.append((own, raw))
        body = match.group("body")
        interpreted = "/" in match.group("stamp")
        pairs = (
            _interpreted_pairs(record_type, body) if interpreted else _raw_pairs(record_type, body)
        )
        is_execve = record_type == "EXECVE"
        for key, decoded, undecoded in pairs:
            if key not in own:
                own[key] = decoded
            argument = _ARG_RE.match(key)
            if is_execve and argument:
                # The argv comes from EXECVE, never from SYSCALL (Citadel 496c484).
                self.argv[int(argument.group(1))] = decoded
                self.fields[key] = decoded
                continue
            # PATH records repeat keys (item=0, item=1); the merged view keeps the first,
            # each record's own view keeps its own.
            if key not in self.fields:
                self.fields[key] = decoded
            # A brace group or a quoted msg='...' is kept whole under its own key and its
            # inner pairs are lifted to fields as well.
            if len(undecoded) >= 2 and (undecoded[0], undecoded[-1]) in {("{", "}"), ("'", "'")}:
                for inner_key, inner_value in _PAIR_RE.findall(undecoded[1:-1]):
                    inner = _decode_raw(inner_key, inner_value)
                    if inner_key not in self.fields:
                        self.fields[inner_key] = inner
                    if inner_key not in own:
                        own[inner_key] = inner

    def build(self, source: str) -> Event:
        if self.argv:
            self.fields["CommandLine"] = " ".join(v for _, v in sorted(self.argv.items()))
        exe = self.fields.get("exe")
        if isinstance(exe, str):
            self.fields["Image"] = exe
        _map_fields(self.fields, [own for own, _ in self.records], linux_pipeline().auditd)
        records = [
            Event(timestamp=self.timestamp, platform="linux", source=source, fields=own, raw=line)
            for own, line in self.records
        ]
        return Event(
            timestamp=self.timestamp,
            platform="linux",
            source=source,
            fields=self.fields,
            raw="\n".join(self.raw_lines),
            records=records,
        )


def _map_fields(
    merged: dict[str, FieldValue], records: list[dict[str, FieldValue]], mapping: AuditdMapping
) -> None:
    """Add the Sigma names the Linux pipeline derives from audit records (never overwriting).

    ``SYSCALL`` (the enriched syscall name) on each SYSCALL record and on the merged event;
    on the merged event ``CommandLine`` from PROCTITLE when no EXECVE argv exists, and
    ``TargetFilename`` from a PATH record the syscall created.
    """
    for own in records:
        if own.get("type") == "SYSCALL" and "SYSCALL" not in own:
            syscall = mapping.syscall_name(own)
            if syscall is not None:
                own["SYSCALL"] = syscall
                merged.setdefault("SYSCALL", syscall)
    if mapping.command_line_from_proctitle and "CommandLine" not in merged:
        proctitle = next(
            (own.get("proctitle") for own in records if own.get("type") == "PROCTITLE"), None
        )
        if isinstance(proctitle, str) and proctitle:
            merged["CommandLine"] = proctitle
    if mapping.target_filename_from_created_path and "TargetFilename" not in merged:
        cwd = next((own.get("cwd") for own in records if own.get("type") == "CWD"), None)
        for own in records:
            created = own.get("name")
            if own.get("type") != "PATH" or str(own.get("nametype", "")).upper() != "CREATE":
                continue
            if isinstance(created, str) and created and created != "(null)":
                if not created.startswith("/") and isinstance(cwd, str) and cwd.startswith("/"):
                    created = cwd.rstrip("/") + "/" + created
                merged["TargetFilename"] = created
                break


class AuditdSource:
    """Parse auditd logs into one normalized Event per audit event id.

    After :meth:`parse` is exhausted, :attr:`stats` counts ``records`` parsed,
    ``separators`` skipped and ``skipped`` lines that were not audit records, so a caller
    can show whether a file parsed completely.
    """

    def __init__(self) -> None:
        self.stats: Counter[str] = Counter()

    def parse(self, path: Path) -> Iterator[Event]:
        self.stats = Counter()
        # Keyed by audit id, in order of first appearance, so an event whose records are
        # interleaved with another's is still assembled whole.
        pending: OrderedDict[tuple[str, str], _Partial] = OrderedDict()
        closed: set[tuple[str, str]] = set()
        seen = 0

        # newline="\n": a record's enriched half follows a \x1d, which str.splitlines() would
        # treat as a line break; reading by "\n" keeps each record whole.
        with path.open(encoding="utf-8", errors="replace", newline="\n") as handle:
            for line_no, line in enumerate(handle, start=1):
                raw = line.rstrip("\r\n")
                if not raw.strip():
                    continue
                if raw.strip() == _SEPARATOR:
                    self.stats["separators"] += 1
                    continue
                match = _RECORD_RE.match(raw)
                if match is None:
                    self.stats["skipped"] += 1
                    logger.warning("%s:%d: skipping malformed auditd line", path, line_no)
                    continue
                self.stats["records"] += 1
                seen += 1
                timestamp = _timestamp(match.group("stamp"))
                record_id = (f"{timestamp.timestamp():.3f}", match.group("serial"))
                if record_id in closed:
                    logger.warning(
                        "%s:%d: audit id %s:%s reappeared after its event was emitted, so that "
                        "event is missing this %s record; the merge window may be too narrow",
                        path,
                        line_no,
                        record_id[0],
                        record_id[1],
                        match.group("type"),
                    )
                partial = pending.get(record_id)
                if partial is None:
                    partial = _Partial(timestamp=timestamp)
                    pending[record_id] = partial
                partial.absorb(match, raw, seen)

                while pending:
                    oldest_id, oldest = next(iter(pending.items()))
                    if seen - oldest.last_seen < MERGE_WINDOW_RECORDS:
                        break
                    del pending[oldest_id]
                    closed.add(oldest_id)
                    yield oldest.build(path.name)

        for record_id, partial in pending.items():
            closed.add(record_id)
            yield partial.build(path.name)
