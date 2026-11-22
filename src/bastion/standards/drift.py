"""Version drift: how a mapping's ATT&CK ids resolve against Bastion's pinned ATT&CK release.

A mapping built for an older ATT&CK release can name techniques that have since been
revoked (and replaced), deprecated, or that the pinned release does not know. Each loader
reports that, beside the ATT&CK version the mapping declares (or that it declares none),
and how many live techniques the mapping does not cover. A revoked id is followed through
``revoked-by`` exactly as rule tags are (``AttackData.resolve_retired``).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from bastion.attack import AttackData


def _version_key(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for piece in version.split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


@dataclass
class AttackDrift:
    """How one mapping's technique ids resolve against the pinned ATT&CK release."""

    source: str
    #: the ATT&CK release the mapping says it was built for; empty when it states none
    declared_attack_version: str
    pinned_attack_version: str
    ids_total: int = 0
    ids_live: int = 0
    #: revoked id -> the live id it resolves to
    revoked: dict[str, str] = field(default_factory=dict)
    deprecated: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    #: live enterprise techniques (and sub-techniques) the mapping names nowhere
    live_unmapped: int = 0
    live_total: int = 0

    @property
    def older(self) -> bool | None:
        """True when the declared release is older than the pin; None when none is declared."""
        if not self.declared_attack_version:
            return None
        return _version_key(self.declared_attack_version) < _version_key(self.pinned_attack_version)

    @property
    def warnings(self) -> list[str]:
        notes: list[str] = []
        if self.older:
            notes.append(
                f"{self.source} maps ATT&CK {self.declared_attack_version}, older than the pinned "
                f"{self.pinned_attack_version}"
            )
        elif self.older is None:
            notes.append(
                f"{self.source} states no ATT&CK release; "
                f"ids checked against {self.pinned_attack_version}"
            )
        if self.revoked:
            notes.append(
                f"{len(self.revoked)} ids revoked in {self.pinned_attack_version}, "
                "followed to their replacements"
            )
        if self.deprecated:
            notes.append(
                f"{len(self.deprecated)} ids deprecated in {self.pinned_attack_version}, dropped"
            )
        if self.unknown:
            notes.append(
                f"{len(self.unknown)} ids unknown to {self.pinned_attack_version}, dropped"
            )
        return notes

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["older"] = self.older
        data["warnings"] = self.warnings
        return data


def attack_drift(
    source: str, declared_attack_version: str, technique_ids: Iterable[str], attack: AttackData
) -> tuple[AttackDrift, dict[str, str]]:
    """Resolve ``technique_ids`` against ``attack``.

    Returns the drift report and ``id -> live id`` for every id that resolves (live ids map to
    themselves, revoked ids to their replacement); deprecated and unknown ids are left out.
    """
    drift = AttackDrift(
        source=source,
        declared_attack_version=declared_attack_version,
        pinned_attack_version=attack.version or "",
    )
    resolved: dict[str, str] = {}
    deprecated: set[str] = set()
    unknown: set[str] = set()
    for raw in {i.strip().upper() for i in technique_ids if i and i.strip()}:
        drift.ids_total += 1
        live, status = attack.resolve_retired(raw)
        if live is not None:
            resolved[raw] = live
            if status == "revoked":
                drift.revoked[raw] = live
            else:
                drift.ids_live += 1
        elif status == "deprecated":
            deprecated.add(raw)
        else:
            unknown.add(raw)
    drift.deprecated = sorted(deprecated)
    drift.unknown = sorted(unknown)
    drift.revoked = dict(sorted(drift.revoked.items()))
    covered = set(resolved.values())
    drift.live_total = len(attack.techniques)
    drift.live_unmapped = sum(1 for t in attack.techniques if t not in covered)
    return drift, resolved
