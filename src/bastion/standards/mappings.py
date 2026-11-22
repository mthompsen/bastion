"""Loaders for the technique mappings: D3FEND, CTID ATT&CK to NIST 800-53, and MITRE CAR.

Each loader reads the pinned file from the standards cache (``bastion standards fetch``),
keeps only enterprise ATT&CK rows, resolves the ids against the pinned ATT&CK release and
returns the mapping keyed by live technique id together with its :class:`AttackDrift`.
Nothing here is used by the engine.
"""

from __future__ import annotations

import csv
import io
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generic, TypeVar

import yaml

from bastion.attack import AttackData
from bastion.standards.drift import AttackDrift, attack_drift

T = TypeVar("T")

_D3FEND_ENTERPRISE = "#ATTACKEnterpriseTechnique"


@dataclass(frozen=True)
class Countermeasure:
    """A D3FEND defensive technique related to an offensive technique."""

    id: str
    name: str
    tactic: str
    #: how D3FEND relates them (the first artifact path found; not part of identity)
    via: str = field(default="", compare=False)


@dataclass(frozen=True)
class Control:
    """A NIST SP 800-53 Rev. 5 control CTID maps to a technique."""

    id: str
    name: str
    family: str
    mapping_type: str


@dataclass(frozen=True)
class Analytic:
    """A MITRE CAR analytic that covers a technique."""

    id: str
    title: str
    coverage: str
    platforms: tuple[str, ...]


@dataclass
class TechniqueMapping(Generic[T]):
    """One mapping source, keyed by live ATT&CK technique id."""

    source: str
    version: str
    drift: AttackDrift
    entries: dict[str, list[T]] = field(default_factory=dict)
    #: rows left out before resolution, by reason (for example other ATT&CK domains)
    skipped: dict[str, int] = field(default_factory=dict)

    def for_technique(self, technique_id: str) -> list[T]:
        return list(self.entries.get(technique_id.upper(), []))


def _group(rows: list[tuple[str, T]], resolved: dict[str, str]) -> dict[str, list[T]]:
    entries: dict[str, list[T]] = {}
    for raw, item in rows:
        live = resolved.get(raw.strip().upper())
        if live is None:
            continue
        bucket = entries.setdefault(live, [])
        if item not in bucket:
            bucket.append(item)
    return dict(sorted(entries.items()))


def load_d3fend(
    mappings_csv: Path, techniques_csv: Path, attack: AttackData, version: str
) -> TechniqueMapping[Countermeasure]:
    """D3FEND's inferred offensive to defensive mappings (``d3fend-full-mappings.csv``).

    D3FEND infers each relation through digital artifacts (a countermeasure hardens or
    analyzes an artifact the technique uses); ``via`` names them. Only enterprise ATT&CK rows
    are kept. The countermeasure is the most specific technique the row names.
    """
    ids: dict[str, str] = {}
    with techniques_csv.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            for column in (
                "D3FEND Technique",
                "D3FEND Technique Level 0",
                "D3FEND Technique Level 1",
            ):
                label = (row.get(column) or "").strip()
                if label:
                    ids.setdefault(label, row["ID"].strip())
    rows: list[tuple[str, Countermeasure]] = []
    skipped: dict[str, int] = {}
    with mappings_csv.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if not row.get("framework_root_iri", "").endswith(_D3FEND_ENTERPRISE):
                key = row.get("framework_root_iri", "").rsplit("#", 1)[-1] or "unknown"
                skipped[key] = skipped.get(key, 0) + 1
                continue
            name = row["query_def_tech_label"].strip()
            via = (
                f"{row['def_artifact_rel_label']} {row['def_artifact_label']}; "
                f"technique {row['off_artifact_rel_label']} {row['off_artifact_label']}"
            )
            rows.append(
                (
                    row["off_tech_id"],
                    Countermeasure(
                        id=ids.get(name, ""),
                        name=name,
                        tactic=row["def_tactic_label"].strip(),
                        via=via,
                    ),
                )
            )
    drift, resolved = attack_drift("D3FEND", "", (raw for raw, _ in rows), attack)
    return TechniqueMapping("D3FEND", version, drift, _group(rows, resolved), skipped)


def load_ctid_800_53(path: Path, attack: AttackData) -> TechniqueMapping[Control]:
    """CTID's ATT&CK to NIST 800-53 Rev. 5 mapping; ``non_mappable`` rows are left out."""
    data = json.loads(path.read_text(encoding="utf-8"))
    metadata = data.get("metadata", {})
    rows: list[tuple[str, Control]] = []
    skipped: dict[str, int] = {}
    for item in data.get("mapping_objects", []):
        if item.get("status") == "non_mappable" or not item.get("capability_id"):
            skipped["non_mappable"] = skipped.get("non_mappable", 0) + 1
            continue
        rows.append(
            (
                str(item["attack_object_id"]),
                Control(
                    id=str(item["capability_id"]),
                    name=str(item.get("capability_description") or ""),
                    family=str(item.get("capability_group") or ""),
                    mapping_type=str(item.get("mapping_type") or ""),
                ),
            )
        )
    declared = str(metadata.get("attack_version") or "")
    drift, resolved = attack_drift(
        "CTID ATT&CK to NIST 800-53", declared, (raw for raw, _ in rows), attack
    )
    version = f"{metadata.get('mapping_framework_version', '')} for ATT&CK {declared}".strip()
    return TechniqueMapping("CTID 800-53", version, drift, _group(rows, resolved), skipped)


def _car_analytics(path: Path) -> list[dict[str, object]]:
    analytics: list[dict[str, object]] = []
    if path.is_dir():
        files = sorted((path / "analytics").glob("*.yaml"))
        texts = [f.read_text(encoding="utf-8") for f in files]
    else:
        with zipfile.ZipFile(path) as archive:
            names = sorted(
                n for n in archive.namelist() if "/analytics/" in n and n.endswith(".yaml")
            )
            texts = [io.TextIOWrapper(archive.open(n), encoding="utf-8").read() for n in names]
    for text in texts:
        loaded = yaml.safe_load(text)
        if isinstance(loaded, dict) and loaded.get("id"):
            analytics.append(loaded)
    return analytics


def load_car(path: Path, attack: AttackData, version: str) -> TechniqueMapping[Analytic]:
    """MITRE CAR analytics (``analytics/*.yaml``, from the pinned archive or a checkout)."""
    rows: list[tuple[str, Analytic]] = []
    for item in _car_analytics(path):
        for cover in item.get("coverage") or []:  # type: ignore[attr-defined]
            analytic = Analytic(
                id=str(item["id"]),
                title=str(item.get("title") or ""),
                coverage=str(cover.get("coverage") or ""),
                platforms=tuple(str(p) for p in item.get("platforms") or []),  # type: ignore[attr-defined]
            )
            ids = [str(cover.get("technique") or "")] + [
                str(s) for s in cover.get("subtechniques") or []
            ]
            rows.extend((i, analytic) for i in ids if i)
    drift, resolved = attack_drift("MITRE CAR", "", (raw for raw, _ in rows), attack)
    return TechniqueMapping("MITRE CAR", version, drift, _group(rows, resolved))
