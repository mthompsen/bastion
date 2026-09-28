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
    #: revoked technique id -> the id ATT&CK says replaced it (``revoked-by``)
    revoked_by: dict[str, str] = field(default_factory=dict)
    #: technique ids ATT&CK marks deprecated (no replacement is named)
    deprecated: frozenset[str] = frozenset()

    def resolve_retired(self, technique_id: str) -> tuple[str | None, str]:
        """Follow ``revoked-by`` links to a live technique id.

        Returns ``(live_id, status)`` where status is ``"live"``, ``"revoked"``
        (remapped through one or more revoked-by links), ``"deprecated"`` (no
        replacement; ``live_id`` is None) or ``"unknown"`` (not in this release).
        """
        current = technique_id.upper()
        if current in self.techniques:
            return current, "live"
        if current in self.deprecated:
            return None, "deprecated"
        seen: set[str] = set()
        while current in self.revoked_by and current not in seen:
            seen.add(current)
            current = self.revoked_by[current]
            if current in self.techniques:
                return current, "revoked"
        return None, "deprecated" if current in self.deprecated else "unknown"


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
    """Parse a STIX bundle into a technique lookup plus the bundle version.

    Besides the attack-pattern objects, this walks ATT&CK's detection
    metadata (detection strategies -> analytics -> log sources, linked to
    techniques via ``detects`` relationships) so each TechniqueRef records
    which log sources ATT&CK says can observe it.
    """
    bundle: dict[str, Any] = json.loads(stix_path.read_text(encoding="utf-8"))
    data = AttackData()
    stix_to_attack: dict[str, str] = {}
    retired_stix_to_attack: dict[str, str] = {}
    deprecated: set[str] = set()
    analytic_log_sources: dict[str, list[str]] = {}
    strategy_analytics: dict[str, list[str]] = {}
    detects: list[tuple[str, str]] = []
    revoked_by_refs: list[tuple[str, str]] = []

    for obj in bundle.get("objects", []):
        obj_type = obj.get("type")
        if obj_type == "x-mitre-collection":
            data.version = obj.get("x_mitre_version")
        elif obj_type == "x-mitre-analytic":
            analytic_log_sources[str(obj.get("id"))] = [
                str(ref["name"])
                for ref in obj.get("x_mitre_log_source_references", [])
                if ref.get("name")
            ]
        elif obj_type == "x-mitre-detection-strategy":
            strategy_analytics[str(obj.get("id"))] = [
                str(ref) for ref in obj.get("x_mitre_analytic_refs", [])
            ]
        elif obj_type == "relationship" and obj.get("relationship_type") == "detects":
            detects.append((str(obj.get("source_ref")), str(obj.get("target_ref"))))
        elif obj_type == "relationship" and obj.get("relationship_type") == "revoked-by":
            revoked_by_refs.append((str(obj.get("source_ref")), str(obj.get("target_ref"))))
        elif obj_type == "attack-pattern":
            attack_id = _attack_id(obj)
            if attack_id is None:
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                retired_stix_to_attack[str(obj.get("id"))] = attack_id.upper()
                if obj.get("x_mitre_deprecated") and not obj.get("revoked"):
                    deprecated.add(attack_id.upper())
                continue
            stix_to_attack[str(obj.get("id"))] = attack_id.upper()
            data.techniques[attack_id.upper()] = TechniqueRef(
                id=attack_id.upper(),
                name=str(obj.get("name", "")),
                tactics=_tactics(obj),
                platforms=[str(p) for p in obj.get("x_mitre_platforms", [])],
            )

    for strategy_ref, technique_ref in detects:
        attack_id_for_ref = stix_to_attack.get(technique_ref)
        if attack_id_for_ref is None:
            continue
        names: set[str] = set()
        for analytic_ref in strategy_analytics.get(strategy_ref, []):
            names.update(analytic_log_sources.get(analytic_ref, []))
        if names:
            technique = data.techniques[attack_id_for_ref]
            technique.log_sources = sorted(set(technique.log_sources) | names)

    all_ids = {**retired_stix_to_attack, **stix_to_attack}
    for old_ref, new_ref in revoked_by_refs:
        old_id, new_id = retired_stix_to_attack.get(old_ref), all_ids.get(new_ref)
        if old_id is not None and new_id is not None and old_id != new_id:
            data.revoked_by[old_id] = new_id
    data.deprecated = frozenset(deprecated)
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
