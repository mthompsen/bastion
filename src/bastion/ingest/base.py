"""LogSource protocol and ingester auto-selection."""

from __future__ import annotations

import platform as _platform
from collections.abc import Iterator
from pathlib import Path
from typing import Protocol, runtime_checkable

from bastion.models import Event, Platform

#: Extensions that unambiguously identify a Windows event log export.
_EVTX_EXTENSIONS = {".evtx"}
#: Extensions that unambiguously identify a Linux-style text log.
_TEXT_EXTENSIONS = {".log", ".txt", ".syslog"}


@runtime_checkable
class LogSource(Protocol):
    """A read-only parser that turns a log file into normalized Events."""

    def parse(self, path: Path) -> Iterator[Event]:
        """Yield one Event per well-formed record; skip malformed records."""
        ...


def host_platform() -> Platform:
    """The platform of the machine Bastion is running on."""
    return "windows" if _platform.system() == "Windows" else "linux"


def select_source(path: Path, platform_override: Platform | None = None) -> LogSource:
    """Pick the right ingester for ``path``.

    The file extension decides when it is unambiguous: ``.evtx`` is always
    Windows; ``.json``/``.jsonl`` are journald JSON exports;
    ``.log``/``.txt``/``.syslog`` are Linux-style text, with the first line
    sniffed to tell auditd records and journald JSON from plain syslog.
    Otherwise the explicit ``platform_override`` wins, falling back to the
    host OS, so the default platform is the one the tool is running on.
    """
    from bastion.ingest.evtx import EvtxSource
    from bastion.ingest.journald import JournaldSource

    suffix = path.suffix.lower()
    if suffix in _EVTX_EXTENSIONS:
        return EvtxSource()
    if suffix in {".json", ".jsonl"}:
        return JournaldSource()
    if suffix in _TEXT_EXTENSIONS:
        return _sniff_text_source(path)
    platform = platform_override or host_platform()
    return EvtxSource() if platform == "windows" else _sniff_text_source(path)


def _sniff_text_source(path: Path) -> LogSource:
    """Distinguish auditd / journald-JSON / plain syslog by the first line."""
    from bastion.ingest.auditd import AuditdSource
    from bastion.ingest.journald import JournaldSource
    from bastion.ingest.linux import LinuxLogSource

    first_line = ""
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.strip():
                    first_line = line.strip()
                    break
    except OSError:
        return LinuxLogSource()
    if first_line.startswith("type=") and "msg=audit(" in first_line:
        return AuditdSource()
    if first_line.startswith("{"):
        return JournaldSource()
    return LinuxLogSource()
