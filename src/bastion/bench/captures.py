"""The unit of measurement: a labelled capture.

A :class:`Capture` names one or more log files in the corpus cache, how to
parse them, what the corpus says happened in them (techniques, or benign),
and optionally the event-time window that attribution is bounded by. It
holds no derived data: every bench run re-parses the logs with Bastion's
own ingesters, so a result is always about the parser that ships.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from bastion.ingest import (
    AuditdSource,
    EvtxSource,
    JournaldSource,
    LinuxLogSource,
    LogSource,
    SysmonLinuxSource,
    XmlEventLogSource,
)
from bastion.models import Event, Platform

CaptureKind = Literal["positive", "benign", "regression", "fixture"]
"""What a capture is evidence of: a labelled technique, goodware, a per-rule
regression case, or an in-repo synthetic fixture (the weakest ladder rung)."""

SourceKind = Literal["evtx", "xmlevents", "sysmon_linux", "auditd", "syslog", "journald"]

_SOURCES: dict[str, Callable[[], LogSource]] = {
    "evtx": EvtxSource,
    "xmlevents": XmlEventLogSource,
    "sysmon_linux": SysmonLinuxSource,
    "auditd": AuditdSource,
    "syslog": LinuxLogSource,
    "journald": JournaldSource,
}

Window = tuple[datetime, datetime]


@dataclass
class Capture:
    """One measurable unit of telemetry with its labels."""

    id: str
    corpus: str
    kind: CaptureKind
    platform: Platform
    source_kind: SourceKind
    paths: tuple[Path, ...]
    #: live ATT&CK technique ids after resolving retired ones
    techniques: tuple[str, ...] = ()
    #: the technique ids exactly as the corpus labelled them
    raw_labels: tuple[str, ...] = ()
    #: how raw labels became techniques (remaps, exclusions)
    label_notes: tuple[str, ...] = ()
    tactic: str = ""
    host: str = ""
    license: str = ""
    #: regression cases: rule id -> expected match count (None = at least one)
    expected_matches: dict[str, int | None] = field(default_factory=dict)
    #: only events inside this window count (event time, inclusive)
    window: Window | None = None
    #: events inside any of these windows are dropped (for example a harness's own cleanup)
    exclude_windows: tuple[Window, ...] = ()
    notes: dict[str, str] = field(default_factory=dict)
    #: tests and synthetic suites can supply events directly
    events_override: Callable[[], Iterator[Event]] | None = None

    @property
    def labelled(self) -> bool:
        return bool(self.techniques)

    def events(self) -> Iterator[Event]:
        """Parse the capture's files, applying the window filters."""
        override = self.events_override
        stream = override() if override is not None else self._parse_paths()
        if self.window is None and not self.exclude_windows:
            yield from stream
            return
        for event in stream:
            if self._admits(event.timestamp):
                yield event

    def _parse_paths(self) -> Iterator[Event]:
        source = _SOURCES[self.source_kind]()
        for path in self.paths:
            yield from source.parse(path)

    def _admits(self, when: datetime | None) -> bool:
        if when is None:
            # An event with no timestamp cannot be placed in a window.
            return self.window is None
        when = aware(when)
        if self.window is not None and not (aware(self.window[0]) <= when <= aware(self.window[1])):
            return False
        return not any(aware(start) <= when <= aware(end) for start, end in self.exclude_windows)


def aware(when: datetime) -> datetime:
    """A comparable timestamp: naive values (classic syslog carries no zone) are read as UTC."""
    return when if when.tzinfo is not None else when.replace(tzinfo=UTC)
