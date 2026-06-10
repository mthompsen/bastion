"""MITRE ATT&CK STIX parsing: technique id → enriched TechniqueRef lookup.

Parses the ``enterprise-attack.json`` STIX 2.1 bundle directly (no ``stix2``
dependency): every ``attack-pattern`` object, covering techniques and
sub-techniques alike, becomes a TechniqueRef keyed by its ATT&CK id (``T1059``,
``T1059.001``). Revoked and deprecated techniques are excluded from the
lookup, so a Sigma tag that points at one is surfaced as unresolved by
:func:`resolve_techniques` instead of silently enriched with stale data.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bastion.models import TechniqueRef


@dataclass
class AttackData:
    """The parsed bundle: technique lookup plus the ATT&CK release it came from."""

    techniques: dict[str, TechniqueRef] = field(default_factory=dict)
    version: str | None = None


def _attack_id(obj: dict[str, Any]) -> str | None:
    """The ATT&CK external id (e.g. T1059.001) of a STIX object, if any."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def _tactics(obj: dict[str, Any]) -> list[str]:
    """ATT&CK tactic names (kill-chain phases) of a technique object."""
    return [
        str(phase["phase_name"])
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
    ]


def load_attack_data(stix_path: Path) -> AttackData:
    """Parse a STIX bundle into a technique lookup plus the bundle version."""
    bundle: dict[str, Any] = json.loads(stix_path.read_text(encoding="utf-8"))
    data = AttackData()
    for obj in bundle.get("objects", []):
        obj_type = obj.get("type")
        if obj_type == "x-mitre-collection":
            data.version = obj.get("x_mitre_version")
            continue
        if obj_type != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        attack_id = _attack_id(obj)
        if attack_id is None:
            continue
        data.techniques[attack_id.upper()] = TechniqueRef(
            id=attack_id.upper(),
            name=str(obj.get("name", "")),
            tactics=_tactics(obj),
        )
    return data


def load_attack(stix_path: Path) -> dict[str, TechniqueRef]:
    """Parse the enterprise-attack STIX bundle into a technique-id lookup."""
    return load_attack_data(stix_path).techniques


def resolve_techniques(
    technique_ids: list[str], lookup: dict[str, TechniqueRef]
) -> tuple[list[TechniqueRef], list[str]]:
    """Resolve ATT&CK ids (case-insensitive) to enriched TechniqueRefs.

    Returns ``(resolved, unresolved)``: ids that are unknown, revoked or
    deprecated land in ``unresolved`` so callers can report them rather than
    drop them silently.
    """
    resolved: list[TechniqueRef] = []
    unresolved: list[str] = []
    for technique_id in technique_ids:
        normalized = technique_id.upper()
        if normalized in lookup:
            resolved.append(lookup[normalized])
        else:
            unresolved.append(normalized)
    return resolved, unresolved
