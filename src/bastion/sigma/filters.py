"""Sigma filter documents (meta filters): environment exclusions as reviewable files.

A filter is a Sigma document whose ``filter`` block names the rules it applies
to and a selection; when the selection matches an event, detections from those
rules on that event are suppressed. Filters never edit upstream rules, and every
suppression is counted and disclosed, so an exclusion is a file a reviewer can
read and a number a report carries, not a silent edit.

Semantics follow the Sigma filters specification: the ``filter`` block carries
``rules`` (ids), one or more search identifiers, and a ``condition`` over them,
evaluated with the same matcher as a rule's detection block. A filter applies
only to events whose product, category and service agree with its ``logsource``
where both sides name them. A filter whose grammar the matcher cannot evaluate
fails open: the detection is kept and the filter error is recorded.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from bastion.models import Event, SigmaRule

logger = logging.getLogger(__name__)

_FILTER_META_KEYS = {"rules"}


@dataclass
class SigmaFilter:
    """One filter document."""

    id: str
    title: str
    rule_ids: tuple[str, ...]
    logsource: dict[str, str]
    detection: dict[str, Any]
    description: str = ""
    file_path: str = ""
    justification: str = ""
    notes: dict[str, str] = field(default_factory=dict)

    def as_rule(self) -> SigmaRule:
        """The filter's selection as a pseudo rule, so the matcher can evaluate it."""
        return SigmaRule(
            id=self.id,
            title=self.title,
            logsource=dict(self.logsource),
            detection=dict(self.detection),
            file_path=self.file_path,
        )

    def applies_to_source(self, event: Event, rule: SigmaRule) -> bool:
        """Does the filter's logsource agree with the event's platform and the rule's logsource?"""
        product = self.logsource.get("product", "").lower()
        if product and product != event.platform:
            return False
        for key in ("category", "service"):
            mine = self.logsource.get(key, "").lower()
            theirs = rule.logsource.get(key, "").lower()
            if mine and theirs and mine != theirs:
                return False
        return True


def load_filters(directory: Path) -> list[SigmaFilter]:
    """Parse every filter document under ``directory`` (recursively); non-filters are skipped."""
    filters: list[SigmaFilter] = []
    if not directory.is_dir():
        return filters
    for path in sorted(p for p in directory.rglob("*") if p.suffix.lower() in (".yml", ".yaml")):
        loaded = _load_filter_file(path)
        if loaded is not None:
            filters.append(loaded)
    return filters


def _load_filter_file(path: Path) -> SigmaFilter | None:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        logger.warning("%s: skipping unparseable filter file: %s", path, exc)
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("filter"), dict):
        logger.warning("%s: skipping file without a filter block", path)
        return None
    block: dict[str, Any] = doc["filter"]
    raw_rules = block.get("rules")
    rule_ids = tuple(
        str(r) for r in (raw_rules if isinstance(raw_rules, list) else [raw_rules]) if r
    )
    detection = {str(k): v for k, v in block.items() if k not in _FILTER_META_KEYS}
    if not rule_ids or "condition" not in detection:
        logger.warning("%s: skipping filter without rules or condition", path)
        return None
    logsource = doc.get("logsource")
    return SigmaFilter(
        id=str(doc.get("id") or path.stem),
        title=str(doc.get("title") or path.stem),
        rule_ids=rule_ids,
        logsource=(
            {str(k): str(v) for k, v in logsource.items() if v is not None}
            if isinstance(logsource, dict)
            else {}
        ),
        detection=detection,
        description=str(doc.get("description") or ""),
        file_path=str(path),
        justification=str(doc.get("justification") or ""),
    )
