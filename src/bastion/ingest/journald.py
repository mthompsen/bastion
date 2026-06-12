"""journald JSON-export ingestion.

Parses the output of ``journalctl -o json`` (one JSON object per line)
into normalized Events: ``MESSAGE`` becomes ``message``, ``_HOSTNAME``
``host``, ``_PID`` ``pid``, ``_COMM``/``SYSLOG_IDENTIFIER`` ``process``,
and ``__REALTIME_TIMESTAMP`` (microseconds since the epoch) the event
timestamp. The same user-extraction patterns as the plain syslog ingester
apply, so auth-style rules behave identically on either format.
Lines that are not JSON objects are skipped with a warning.

(Plain ``journalctl`` short output is classic syslog and is handled by
:class:`~bastion.ingest.linux.LinuxLogSource`.)
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from bastion.ingest.linux import _extract_user
from bastion.models import Event, FieldValue

logger = logging.getLogger(__name__)


class JournaldSource:
    """Parse `journalctl -o json` exports into normalized Events."""

    def parse(self, path: Path) -> Iterator[Event]:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line_no, line in enumerate(handle, start=1):
                raw = line.rstrip("\n")
                if not raw.strip():
                    continue
                try:
                    record = json.loads(raw)
                except json.JSONDecodeError:
                    record = None
                if not isinstance(record, dict):
                    logger.warning("%s:%d: skipping non-JSON journald line", path, line_no)
                    continue
                message = record.get("MESSAGE")
                if not isinstance(message, str):
                    # Binary/blob messages arrive as byte arrays; skip them.
                    logger.warning("%s:%d: skipping journald entry without text", path, line_no)
                    continue
                fields: dict[str, FieldValue] = {
                    "message": message,
                    "host": _text_or_none(record.get("_HOSTNAME")),
                    "process": _text_or_none(
                        record.get("_COMM") or record.get("SYSLOG_IDENTIFIER")
                    ),
                    "pid": _int_or_none(record.get("_PID")),
                }
                if user := _extract_user(message):
                    fields["user"] = user
                yield Event(
                    timestamp=_timestamp(record.get("__REALTIME_TIMESTAMP")),
                    platform="linux",
                    source=path.name,
                    fields=fields,
                    raw=raw,
                )


def _text_or_none(value: object) -> str | None:
    return str(value) if isinstance(value, str | int) else None


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _timestamp(value: object) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(str(value)) / 1_000_000, tz=UTC)
    except (TypeError, ValueError, OSError):
        return None
