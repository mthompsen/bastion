"""Pydantic data models shared across Bastion (SPEC.md section 9)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Platform = Literal["windows", "linux"]
"""Log platforms Bastion understands."""

Severity = Literal["informational", "low", "medium", "high", "critical"]
"""Sigma rule `level` values."""

FieldValue = str | int | None
"""A normalized event field value."""


class Event(BaseModel):
    """A single normalized log record — the common shape both ingesters emit."""

    timestamp: datetime | None = None
    platform: Platform
    source: str
    fields: dict[str, FieldValue] = Field(default_factory=dict)
    raw: str


class TechniqueRef(BaseModel):
    """Enriched MITRE ATT&CK technique context."""

    id: str
    name: str
    tactics: list[str] = Field(default_factory=list)


class SigmaRule(BaseModel):
    """A detection rule parsed from a Sigma YAML file."""

    id: str
    title: str
    level: Severity = "medium"
    description: str = ""
    logsource: dict[str, str] = Field(default_factory=dict)
    detection: dict[str, Any] = Field(default_factory=dict)
    attack_techniques: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)
    file_path: str = ""


class Detection(BaseModel):
    """One rule firing on one event, with the evidence that triggered it."""

    rule_id: str
    rule_title: str
    level: Severity
    event: Event
    matched_fields: dict[str, str] = Field(default_factory=dict)
    techniques: list[TechniqueRef] = Field(default_factory=list)


class CoverageEntry(BaseModel):
    """Per-ATT&CK-technique coverage status of the loaded ruleset."""

    technique: TechniqueRef
    rule_count: int = 0
    covered: bool = False


class ScanResult(BaseModel):
    """The full output of a scan run."""

    detections: list[Detection] = Field(default_factory=list)
    events_scanned: int = 0
    rules_loaded: int = 0
    coverage: list[CoverageEntry] = Field(default_factory=list)
