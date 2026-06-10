"""Linux auth.log / syslog ingestion.

Supports the two common syslog line shapes:

* classic BSD format: ``Jun 10 06:12:01 host sshd[412]: message``
  (this format carries no year; the current year is assumed)
* ISO-8601 / RFC 5424-style timestamps:
  ``2026-06-10T06:12:01.123456+00:00 host sshd[412]: message``

Each well-formed line becomes one Event with normalized fields
(``process``, ``pid``, ``host``, ``message`` and, where extractable,
``user``). Malformed lines are skipped with a warning.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from bastion.models import Event, FieldValue

logger = logging.getLogger(__name__)

_CLASSIC_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[^:\s\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$"
)

_ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ][0-9:.,]+(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<process>[^:\s\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$"
)

# Patterns that pull the acting user out of common auth.log messages.
_USER_PATTERNS = (
    re.compile(r"(?:Accepted|Failed) \S+ for (?:invalid user )?(?P<user>\S+)"),
    re.compile(r"session (?:opened|closed) for user (?P<user>[^\s(]+)"),
    re.compile(r"^\s*(?P<user>[^\s:]+) : "),  # sudo's "  alice : TTY=pts/0 ..." shape
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}  # fmt: skip


def _extract_user(message: str) -> str | None:
    for pattern in _USER_PATTERNS:
        match = pattern.search(message)
        if match:
            return match.group("user")
    return None


def _parse_iso_timestamp(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace(",", "."))
    except ValueError:
        return None


class LinuxLogSource:
    """Parse auth.log/syslog-style text logs into normalized Events."""

    def parse(self, path: Path) -> Iterator[Event]:
        # Classic syslog timestamps carry no year, so assume the current one.
        default_year = datetime.now().year
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line_no, line in enumerate(handle, start=1):
                raw = line.rstrip("\n")
                if not raw.strip():
                    continue
                event = self._parse_line(raw, source=path.name, default_year=default_year)
                if event is None:
                    logger.warning("%s:%d: skipping malformed line", path, line_no)
                else:
                    yield event

    def _parse_line(self, raw: str, source: str, default_year: int) -> Event | None:
        timestamp: datetime | None
        if match := _ISO_RE.match(raw):
            timestamp = _parse_iso_timestamp(match.group("ts"))
        elif match := _CLASSIC_RE.match(raw):
            try:
                timestamp = datetime(
                    year=default_year,
                    month=_MONTHS[match.group("month")],
                    day=int(match.group("day")),
                    hour=int(match.group("time")[0:2]),
                    minute=int(match.group("time")[3:5]),
                    second=int(match.group("time")[6:8]),
                )
            except (KeyError, ValueError):
                timestamp = None
        else:
            return None

        message = match.group("message")
        fields: dict[str, FieldValue] = {
            "host": match.group("host"),
            "process": match.group("process"),
            "pid": int(match.group("pid")) if match.group("pid") else None,
            "message": message,
        }
        if user := _extract_user(message):
            fields["user"] = user
        return Event(
            timestamp=timestamp,
            platform="linux",
            source=source,
            fields=fields,
            raw=raw,
        )
