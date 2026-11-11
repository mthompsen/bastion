"""Windows EVTX ingestion.

Uses ``python-evtx`` to walk the binary event log, then normalizes each
record's XML into an Event: the ``<System>`` block contributes ``EventID``,
``Channel``, ``Computer`` and ``Provider``, and every
``<EventData><Data Name=...>`` element (Sysmon's ``Image``, ``CommandLine``,
``ParentImage``, ``User``, ``DestinationIp``, and so on) lands in
``Event.fields`` under its own name. Records that fail to decode or parse
are skipped with a warning.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree

from Evtx.Evtx import Evtx

from bastion.models import Event, FieldValue
from bastion.pipelines import windows_pipeline

logger = logging.getLogger(__name__)

# Trim sub-microsecond precision (EVTX uses 100ns ticks) so fromisoformat accepts it.
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")


def _parse_system_time(value: str) -> datetime | None:
    normalized = _FRACTION_RE.sub(r"\1", value.strip().replace("Z", "+00:00"))
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def xml_to_event(xml_str: str, source: str) -> Event | None:
    """Normalize one Windows event-XML record into an Event.

    Returns None (after logging a warning) when the XML is malformed.
    """
    try:
        root = ElementTree.fromstring(xml_str)
    except ElementTree.ParseError as exc:
        logger.warning("%s: skipping malformed event XML: %s", source, exc)
        return None

    fields: dict[str, FieldValue] = {}
    timestamp: datetime | None = None

    system = root.find("{*}System")
    if system is not None:
        event_id = system.find("{*}EventID")
        if event_id is not None and event_id.text and event_id.text.strip().isdigit():
            fields["EventID"] = int(event_id.text.strip())
        for tag in ("Channel", "Computer"):
            element = system.find(f"{{*}}{tag}")
            if element is not None and element.text:
                fields[tag] = element.text.strip()
        provider = system.find("{*}Provider")
        if provider is not None and provider.get("Name"):
            fields["Provider"] = provider.get("Name")
        time_created = system.find("{*}TimeCreated")
        if time_created is not None and (system_time := time_created.get("SystemTime")):
            timestamp = _parse_system_time(system_time)

    unnamed: list[str] = []
    for data in root.iterfind("{*}EventData/{*}Data"):
        name = data.get("Name")
        if name:
            fields[name] = data.text if data.text is not None else ""
        elif data.text:
            unnamed.append(data.text)
    # Classic event logs ("Windows PowerShell" 400, 600, 800 and others) carry unnamed <Data>
    # elements; Sigma reads them as one field, Data (taxonomy ps_classic_* rules).
    if unnamed and "Data" not in fields:
        fields["Data"] = "\n".join(unnamed)
    # UserData events (WMI-Activity 5858, many Operational channels) put their values under
    # one provider-defined element; each leaf becomes a field under its own name (B2 F3).
    for leaf in root.iterfind("{*}UserData//*"):
        if len(leaf):
            continue
        name = leaf.tag.rsplit("}", 1)[-1]
        if name and name not in fields:
            fields[name] = leaf.text if leaf.text is not None else ""
    windows_pipeline().apply(fields)

    return Event(
        timestamp=timestamp,
        platform="windows",
        source=source,
        fields=fields,
        raw=xml_str,
    )


class EvtxSource:
    """Parse Windows .evtx files into normalized Events."""

    def parse(self, path: Path) -> Iterator[Event]:
        with Evtx(str(path)) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                except Exception as exc:  # skip unreadable records, keep parsing
                    logger.warning("%s: skipping unreadable record: %s", path, exc)
                    continue
                event = xml_to_event(xml_str, source=path.name)
                if event is not None:
                    yield event


#: One ``<Event ...>...</Event>`` element in an XML export (namespace and attributes vary).
_XML_EVENT_RE = re.compile(r"<Event[\s>].*?</Event>", re.DOTALL)


def iter_xml_events(chunks: Iterable[str]) -> Iterator[str]:
    """Split a stream of text into whole ``<Event>`` elements, across chunk boundaries."""
    buffer = ""
    for chunk in chunks:
        buffer += chunk
        end = 0
        for found in _XML_EVENT_RE.finditer(buffer):
            yield found.group(0)
            end = found.end()
        buffer = buffer[end:]
    if buffer.strip():
        logger.warning("trailing text after the last complete <Event> element was skipped")


class XmlEventLogSource:
    """Parse Windows event XML exports (Splunk ``XmlWinEventLog``) into normalized Events.

    The file holds rendered ``<Event>`` elements, one after another, as Windows Event
    Forwarding and Splunk write them; each is normalized by :func:`xml_to_event` exactly
    like a record read from an ``.evtx`` file.
    """

    def parse(self, path: Path) -> Iterator[Event]:
        with path.open(encoding="utf-8", errors="replace") as handle:
            chunks = iter(lambda: handle.read(1 << 20), "")
            for xml_str in iter_xml_events(chunks):
                event = xml_to_event(xml_str, source=path.name)
                if event is not None:
                    yield event
