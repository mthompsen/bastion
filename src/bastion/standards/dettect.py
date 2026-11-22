"""Read DeTT&CT administration files (DeTT&CT 2.2.0 file formats).

Two file types are read: ``data-source-administration`` (format 1.1) and
``technique-administration`` (format 1.2). A file of another type, or another format version,
is read as far as its fields allow and reported as unsupported rather than rejected. Drift:
technique ids are resolved against the pinned ATT&CK release; data source names are checked
against the release's data components (DeTT&CT names those). Bastion computes no DeTT&CT
score; the scores in the file are reported as the file states them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from bastion.attack import AttackData
from bastion.pins import load_pins
from bastion.standards.drift import AttackDrift, attack_drift


def supported_formats() -> dict[str, str]:
    formats = load_pins()["standards"]["dettect"]["file_formats"]
    return {str(k): str(v) for k, v in formats.items()}


@dataclass
class DettectFile:
    """What a DeTT&CT administration file holds, and how it lines up with the pins."""

    path: str
    file_type: str
    version: str
    name: str
    domain: str
    supported: bool
    #: why the file is not supported (empty when it is)
    reason: str = ""
    #: technique-administration: live technique id -> latest detection and visibility scores
    techniques: dict[str, dict[str, int | None]] = field(default_factory=dict)
    #: data-source-administration: data source names and the systems they apply to
    data_sources: dict[str, list[str]] = field(default_factory=dict)
    #: data source names the pinned ATT&CK release has no data component for
    unknown_data_sources: list[str] = field(default_factory=list)
    drift: AttackDrift | None = None

    @property
    def warnings(self) -> list[str]:
        notes = [] if self.supported else [self.reason]
        if self.unknown_data_sources:
            notes.append(
                f"{len(self.unknown_data_sources)} data sources are not data components "
                "in the pinned ATT&CK release"
            )
        if self.drift is not None:
            notes.extend(self.drift.warnings)
        return notes


def _latest_score(entries: list[dict[str, Any]] | None) -> int | None:
    """The score of the most recent logbook entry over all ``applicable_to`` blocks."""
    best: tuple[str, int] | None = None
    for block in entries or []:
        for item in block.get("score_logbook") or []:
            score = item.get("score")
            if score is None:
                continue
            stamp = str(item.get("date") or "")
            if best is None or stamp > best[0]:
                best = (stamp, int(score))
    return None if best is None else best[1]


def load_dettect(path: Path, attack: AttackData) -> DettectFile:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    file_type = str(data.get("file_type") or "")
    version = str(data.get("version") or "")
    formats = supported_formats()
    if file_type not in formats:
        supported, reason = False, f"file_type {file_type or '(none)'} is not one Bastion reads"
    elif version != formats[file_type]:
        supported = False
        reason = (
            f"{file_type} format {version or '(none)'}; "
            f"Bastion reads format {formats[file_type]} (DeTT&CT 2.2.0)"
        )
    else:
        supported, reason = True, ""
    result = DettectFile(
        path=str(path),
        file_type=file_type,
        version=version,
        name=str(data.get("name") or ""),
        domain=str(data.get("domain") or ""),
        supported=supported,
        reason=reason,
    )
    if file_type == "technique-administration":
        rows = [t for t in data.get("techniques") or [] if t.get("technique_id")]
        drift, resolved = attack_drift(
            f"DeTT&CT {path.name}", "", (str(t["technique_id"]) for t in rows), attack
        )
        result.drift = drift
        for row in rows:
            live = resolved.get(str(row["technique_id"]).strip().upper())
            if live is None:
                continue
            result.techniques[live] = {
                "detection": _latest_score(row.get("detection")),
                "visibility": _latest_score(row.get("visibility")),
            }
    elif file_type == "data-source-administration":
        for row in data.get("data_sources") or []:
            name = str(row.get("data_source_name") or "")
            if not name:
                continue
            systems = sorted(
                {
                    str(s)
                    for block in row.get("data_source") or []
                    for s in block.get("applicable_to") or []
                }
            )
            result.data_sources[name] = systems
        result.unknown_data_sources = sorted(
            n for n in result.data_sources if n not in attack.data_components
        )
    return result
