"""Declarative processing pipelines: log source routing and field mapping (B3).

The pipelines live in ``bastion/data/pipelines/`` (each file's header states its sources and
semantics); this module loads each once. ``linux.yml`` routes ``product: linux`` rules by the
kind of Linux event (auditd, Sysmon for Linux, text logs). The Windows pipeline offers two
operations:

- :meth:`WindowsPipeline.admits`: does a rule's ``logsource`` route to this event? A listed
  ``service`` requires the event's ``Channel``; a listed ``category`` requires one of its
  (channel, EventID) routes. Anything not listed is not restricted, as before B3.
- :meth:`WindowsPipeline.apply`: add the Sigma field names a mapping declares (for example
  ``Image`` from Security 4688 ``NewProcessName``) as aliases, never overwriting a field.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from functools import cache
from importlib import resources
from typing import Any

import yaml

from bastion.models import Event, FieldValue, SigmaRule

_TEMPLATE_FIELD = re.compile(r"\{([^{}]+)\}")


@dataclass(frozen=True)
class Route:
    """Events on any of ``channels`` (lowercase) with an EventID in ``event_ids``."""

    channels: frozenset[str]
    event_ids: frozenset[int]

    def admits(self, channel: str | None, event_id: object) -> bool:
        if channel is not None and channel not in self.channels:
            return False
        return not isinstance(event_id, int) or event_id in self.event_ids


@dataclass(frozen=True)
class FieldRule:
    """How one Sigma field is derived: renamed, templated, or value mapped."""

    templates: tuple[str, ...] = ()
    source: str | None = None
    values: Mapping[str, str] | None = None

    def derive(self, fields: Mapping[str, FieldValue]) -> str | None:
        if self.source is not None:
            raw = fields.get(self.source)
            if raw is None:
                return None
            text = str(raw)
            if self.values is None:
                return text
            return self.values.get(text)
        for template in self.templates:
            names = _TEMPLATE_FIELD.findall(template)
            parts = {name: str(fields.get(name) or "") for name in names}
            if all(value not in {"", "-"} for value in parts.values()):
                text = template
                for name, value in parts.items():
                    text = text.replace("{" + name + "}", value)
                return text
        return None


@dataclass(frozen=True)
class FieldMapping:
    name: str
    route: Route
    fields: tuple[tuple[str, FieldRule], ...]


@dataclass(frozen=True)
class WindowsPipeline:
    services: Mapping[str, frozenset[str]]
    categories: Mapping[str, tuple[Route, ...]]
    mappings: tuple[FieldMapping, ...] = field(default_factory=tuple)

    def routes_for(self, rule: SigmaRule) -> tuple[frozenset[str] | None, tuple[Route, ...] | None]:
        """(service channels, category routes) for a rule; None where nothing restricts."""
        service = rule.logsource.get("service", "").lower()
        category = rule.logsource.get("category", "").lower()
        return self.services.get(service), self.categories.get(category)

    @staticmethod
    def admits_with(
        channels: frozenset[str] | None,
        routes: tuple[Route, ...] | None,
        channel: str | None,
        event_id: object,
    ) -> bool:
        if channels is not None and channel is not None and channel not in channels:
            return False
        return routes is None or any(route.admits(channel, event_id) for route in routes)

    def admits(self, rule: SigmaRule, event: Event) -> bool:
        if event.platform != "windows":
            return True
        channels, routes = self.routes_for(rule)
        return self.admits_with(channels, routes, event_channel(event), event.fields.get("EventID"))

    def apply(self, fields: MutableMapping[str, FieldValue]) -> list[str]:
        """Add every mapped field this event's route allows; returns the mapping names used."""
        raw_channel = fields.get("Channel")
        channel = str(raw_channel).lower() if raw_channel is not None else None
        event_id = fields.get("EventID")
        used: list[str] = []
        for mapping in self.mappings:
            if channel is None or not mapping.route.admits(channel, event_id):
                continue
            if not isinstance(event_id, int):
                continue
            for name, rule in mapping.fields:
                if name in fields:
                    continue
                value = rule.derive(fields)
                if value is not None:
                    fields[name] = value
            used.append(mapping.name)
        return used


def event_channel(event: Event) -> str | None:
    channel = event.fields.get("Channel")
    return str(channel).lower() if channel is not None else None


def _route(raw: Mapping[str, Any]) -> Route:
    return Route(
        frozenset(str(c).lower() for c in raw.get("channels", [])),
        frozenset(int(i) for i in raw.get("event_ids", [])),
    )


def _field_rule(raw: object) -> FieldRule:
    if isinstance(raw, str):
        return FieldRule(source=raw)
    if isinstance(raw, list):
        return FieldRule(templates=tuple(str(t) for t in raw))
    if isinstance(raw, dict) and "from" in raw:
        values = {str(k): str(v) for k, v in dict(raw.get("values") or {}).items()}
        return FieldRule(source=str(raw["from"]), values=values or None)
    raise ValueError(f"unsupported field mapping: {raw!r}")


def parse_windows_pipeline(doc: Mapping[str, Any]) -> WindowsPipeline:
    services = {
        str(name).lower(): frozenset(str(c).lower() for c in channels)
        for name, channels in dict(doc.get("services") or {}).items()
    }
    categories = {
        str(name).lower(): tuple(_route(r) for r in routes)
        for name, routes in dict(doc.get("categories") or {}).items()
    }
    mappings = tuple(
        FieldMapping(
            name=str(m["name"]),
            route=_route(m),
            fields=tuple((str(k), _field_rule(v)) for k, v in dict(m["fields"]).items()),
        )
        for m in doc.get("mappings") or []
    )
    return WindowsPipeline(services, categories, mappings)


@dataclass(frozen=True)
class KindRoute:
    """Linux events of one of ``kinds``, with an EventID in ``event_ids`` when given."""

    kinds: frozenset[str]
    event_ids: frozenset[int] | None = None

    def admits(self, kind: str, event_id: object) -> bool:
        if kind not in self.kinds:
            return False
        return self.event_ids is None or (isinstance(event_id, int) and event_id in self.event_ids)


@dataclass(frozen=True)
class LinuxPipeline:
    """Routes for ``product: linux`` rules by the kind of Linux event (see linux.yml)."""

    sysmon_channel: str
    services: Mapping[str, frozenset[str]]
    categories: Mapping[str, tuple[KindRoute, ...]]

    def kind(self, event: Event) -> str:
        if event.records:
            return "auditd"
        if event_channel(event) == self.sysmon_channel:
            return "sysmon"
        return "text"

    def routes_for(
        self, rule: SigmaRule
    ) -> tuple[frozenset[str] | None, tuple[KindRoute, ...] | None]:
        service = rule.logsource.get("service", "").lower()
        category = rule.logsource.get("category", "").lower()
        return self.services.get(service), self.categories.get(category)

    @staticmethod
    def admits_with(
        kinds: frozenset[str] | None,
        routes: tuple[KindRoute, ...] | None,
        kind: str,
        event_id: object,
    ) -> bool:
        if kinds is not None and kind not in kinds:
            return False
        return routes is None or any(route.admits(kind, event_id) for route in routes)

    def admits(self, rule: SigmaRule, event: Event) -> bool:
        if event.platform != "linux":
            return True
        kinds, routes = self.routes_for(rule)
        return self.admits_with(kinds, routes, self.kind(event), event.fields.get("EventID"))


def parse_linux_pipeline(doc: Mapping[str, Any]) -> LinuxPipeline:
    def kind_route(raw: Mapping[str, Any]) -> KindRoute:
        ids = raw.get("event_ids")
        return KindRoute(
            frozenset(str(k) for k in raw.get("kinds", [])),
            frozenset(int(i) for i in ids) if ids is not None else None,
        )

    return LinuxPipeline(
        sysmon_channel=str(doc.get("sysmon_channel", "")).lower(),
        services={
            str(name).lower(): frozenset(str(k) for k in kinds)
            for name, kinds in dict(doc.get("services") or {}).items()
        },
        categories={
            str(name).lower(): tuple(kind_route(r) for r in routes)
            for name, routes in dict(doc.get("categories") or {}).items()
        },
    )


def _packaged(name: str) -> dict[str, Any]:
    text = resources.files("bastion.data").joinpath(f"pipelines/{name}").read_text(encoding="utf-8")
    return dict(yaml.safe_load(text) or {})


@cache
def linux_pipeline() -> LinuxPipeline:
    """The packaged Linux pipeline, parsed once per process."""
    return parse_linux_pipeline(_packaged("linux.yml"))


@cache
def windows_pipeline() -> WindowsPipeline:
    """The packaged Windows pipeline, parsed once per process."""
    return parse_windows_pipeline(_packaged("windows.yml"))
