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
    """A single normalized log record, the common shape both ingesters emit."""

    timestamp: datetime | None = None
    platform: Platform
    source: str
    fields: dict[str, FieldValue] = Field(default_factory=dict)
    raw: str
    #: The source records merged into this event, each as its own Event with only that
    #: record's fields and line. Set by sources that merge several records into one event
    #: (auditd: SYSCALL, EXECVE, PATH, ... sharing an audit id), so rules written against
    #: single records can be evaluated per record. Not serialized.
    records: list[Event] = Field(default_factory=list, exclude=True, repr=False)


class TechniqueRef(BaseModel):
    """Enriched MITRE ATT&CK technique context."""

    id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    #: log source names from ATT&CK's detection strategies (e.g. "WinEventLog:Sysmon")
    log_sources: list[str] = Field(default_factory=list)


class SigmaRule(BaseModel):
    """A detection rule parsed from a Sigma YAML file."""

    id: str
    title: str
    level: Severity = "medium"
    #: Sigma lifecycle status (``stable``, ``test``, ``experimental``, ``deprecated``,
    #: ``unsupported``); empty when the rule file carries none.
    status: str = ""
    description: str = ""
    logsource: dict[str, str] = Field(default_factory=dict)
    detection: dict[str, Any] = Field(default_factory=dict)
    #: technique tags exactly as the rule file writes them (upstream data, never edited)
    attack_techniques: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)
    file_path: str = ""
    #: live technique ids after ``attack.resolve_rule_tags`` followed revoked-by links and
    #: dropped deprecated or unknown tags; None until resolution has run
    resolved_techniques: list[str] | None = None

    def technique_ids(self) -> list[str]:
        """The technique ids every count uses: resolved if resolution ran, else as tagged."""
        if self.resolved_techniques is not None:
            return self.resolved_techniques
        return [t.upper() for t in self.attack_techniques]


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
    #: detections suppressed by Sigma filter documents, per rule id (disclosed, never silent)
    filtered_detections: dict[str, int] = Field(default_factory=dict)
    #: ids of the filter documents that were loaded for this scan
    filters_applied: list[str] = Field(default_factory=list)
    #: how rule technique tags resolved against the ATT&CK release (revoked-by remaps,
    #: deprecated and unknown tags excluded); see ``attack.resolve_rule_tags``
    tag_resolution: dict[str, Any] = Field(default_factory=dict)
    #: tri-state: rule id -> events on which the rule was not evaluable because a field
    #: it needs is absent from the source; never counted as a no match
    not_evaluable: dict[str, int] = Field(default_factory=dict)
    #: missing field -> rule-event pairs it left undecided (the reason, by field)
    not_evaluable_fields: dict[str, int] = Field(default_factory=dict)
    #: rule id -> events carrying none of the fields the rule reads (logsource not routed)
    outside_source: dict[str, int] = Field(default_factory=dict)
