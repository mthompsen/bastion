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

    The file extension decides when it is unambiguous (``.evtx`` is always
    Windows; ``.log``/``.txt``/``.syslog`` are always Linux-style text).
    Otherwise the explicit ``platform_override`` wins, falling back to the
    host OS — the default platform is the one the tool is running on.
    """
    from bastion.ingest.evtx import EvtxSource
    from bastion.ingest.linux import LinuxLogSource

    suffix = path.suffix.lower()
    if suffix in _EVTX_EXTENSIONS:
        return EvtxSource()
    if suffix in _TEXT_EXTENSIONS:
        return LinuxLogSource()
    platform = platform_override or host_platform()
    return EvtxSource() if platform == "windows" else LinuxLogSource()
