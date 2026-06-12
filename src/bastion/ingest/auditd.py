"""Linux auditd log ingestion.

Parses ``/var/log/audit/audit.log``-style records. Audit events span
multiple lines (SYSCALL, EXECVE, CWD, PATH, ...) that share one audit id
(``msg=audit(<epoch>.<ms>:<serial>)``); consecutive lines with the same id
are merged into a single Event so a rule can match the executable from the
SYSCALL record and the argv from the EXECVE record together.

Field normalization: every ``key=value`` pair lands in ``Event.fields``
under its auditd name (``exe``, ``comm``, ``syscall``, ``key``, ``uid``,
``auid``, ``a0``..., ``cwd``, ``name``, ...). Two aliases are added so
Sigma's generic process-creation fields work: ``Image`` (from ``exe``) and
``CommandLine`` (the EXECVE argv joined). Hex-encoded EXECVE arguments are
decoded. Malformed lines are skipped with a warning.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from bastion.models import Event, FieldValue

logger = logging.getLogger(__name__)

_RECORD_RE = re.compile(
    r"^type=(?P<type>\w+)\s+msg=audit\((?P<epoch>\d+(?:\.\d+)?):(?P<serial>\d+)\):\s*(?P<body>.*)$"
)
_PAIR_RE = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")
_HEX_RE = re.compile(r"^(?:[0-9A-F]{2})+$")

#: argv fields (a0, a1, ...) that form the command line.
_ARG_RE = re.compile(r"^a(\d+)$")


def _decode_value(value: str) -> str:
    """Unquote a value; bare even-length uppercase hex is auditd's encoding
    for strings with special characters."""
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if _HEX_RE.match(value):
        try:
            return bytes.fromhex(value).decode("utf-8", errors="replace")
        except ValueError:
            return value
    return value


class AuditdSource:
    """Parse auditd logs into one normalized Event per audit event id."""

    def parse(self, path: Path) -> Iterator[Event]:
        current_id: tuple[str, str] | None = None
        fields: dict[str, FieldValue] = {}
        raw_lines: list[str] = []
        timestamp: datetime | None = None

        with path.open(encoding="utf-8", errors="replace") as handle:
            for line_no, line in enumerate(handle, start=1):
                raw = line.rstrip("\n")
                if not raw.strip():
                    continue
                match = _RECORD_RE.match(raw)
                if match is None:
                    logger.warning("%s:%d: skipping malformed auditd line", path, line_no)
                    continue
                record_id = (match.group("epoch"), match.group("serial"))
                if record_id != current_id:
                    if current_id is not None:
                        yield self._build_event(fields, raw_lines, timestamp, path.name)
                    current_id = record_id
                    fields = {}
                    raw_lines = []
                    timestamp = datetime.fromtimestamp(float(match.group("epoch")), tz=UTC)
                raw_lines.append(raw)
                record_type = match.group("type")
                fields.setdefault("type", record_type)
                for key, value in _PAIR_RE.findall(match.group("body")):
                    decoded = _decode_value(value)
                    # PATH records repeat keys (item=0, item=1); keep the first.
                    if key not in fields:
                        fields[key] = decoded
        if current_id is not None:
            yield self._build_event(fields, raw_lines, timestamp, path.name)

    @staticmethod
    def _build_event(
        fields: dict[str, FieldValue],
        raw_lines: list[str],
        timestamp: datetime | None,
        source: str,
    ) -> Event:
        args: list[tuple[int, str]] = []
        for key, value in fields.items():
            arg_match = _ARG_RE.match(key)
            if arg_match and isinstance(value, str):
                args.append((int(arg_match.group(1)), value))
        if args:
            fields["CommandLine"] = " ".join(value for _, value in sorted(args))
        exe = fields.get("exe")
        if isinstance(exe, str):
            fields["Image"] = exe
        return Event(
            timestamp=timestamp,
            platform="linux",
            source=source,
            fields=fields,
            raw="\n".join(raw_lines),
        )
