"""Pinned standards data with version drift reporting (START_PROMPT section 8, item 5).

D3FEND, CTID ATT&CK to NIST 800-53, and MITRE CAR are fetched once into the cache
(``bastion standards fetch``); CSF 2.0 labels are packaged; DeTT&CT files are the user's own.
A source that has not been fetched is reported as not fetched; nothing here fails a scan.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bastion.attack import AttackData
from bastion.fetch import DEFAULT_DATA_DIR
from bastion.pins import load_pins
from bastion.standards.csf import CsfLabels, load_csf_labels
from bastion.standards.fetch import standards_path
from bastion.standards.mappings import (
    Analytic,
    Control,
    Countermeasure,
    TechniqueMapping,
    load_car,
    load_ctid_800_53,
    load_d3fend,
)

__all__ = ["Standards", "load_standards"]


@dataclass
class Standards:
    """The standards data available for one ATT&CK release; None where not fetched."""

    attack_version: str
    d3fend: TechniqueMapping[Countermeasure] | None
    ctid_800_53: TechniqueMapping[Control] | None
    car: TechniqueMapping[Analytic] | None
    csf: CsfLabels

    def mappings(self) -> dict[str, TechniqueMapping[Any] | None]:
        return {"d3fend": self.d3fend, "ctid_800_53": self.ctid_800_53, "car": self.car}

    def status(self) -> list[dict[str, Any]]:
        """One row per mapping source: pin, whether it is cached, and its drift."""
        pins = load_pins()["standards"]
        rows: list[dict[str, Any]] = []
        for key, mapping in self.mappings().items():
            pin = pins[key]
            row: dict[str, Any] = {
                "source": key,
                "pin": str(pin.get("version") or str(pin.get("commit", ""))[:12]),
                "declared_attack_version": str(pin.get("attack_version") or ""),
                "fetched": mapping is not None,
            }
            if mapping is not None:
                row["techniques_mapped"] = len(mapping.entries)
                row["drift"] = mapping.drift.as_dict()
                row["skipped_rows"] = dict(mapping.skipped)
            rows.append(row)
        rows.append(
            {
                "source": "csf",
                "pin": self.csf.version,
                "declared_attack_version": "",
                "fetched": True,
                "functions_labelled": len(self.csf.labels),
                "assertion": self.csf.assertion,
            }
        )
        return rows


def load_standards(attack: AttackData, data_dir: Path = DEFAULT_DATA_DIR) -> Standards:
    pins = load_pins()["standards"]
    d3fend_paths = standards_path("d3fend", data_dir)
    ctid_paths = standards_path("ctid_800_53", data_dir)
    car_paths = standards_path("car", data_dir)
    d3fend = (
        load_d3fend(d3fend_paths[0], d3fend_paths[1], attack, str(pins["d3fend"]["version"]))
        if all(p.exists() for p in d3fend_paths)
        else None
    )
    ctid = load_ctid_800_53(ctid_paths[0], attack) if ctid_paths[0].exists() else None
    car = (
        load_car(car_paths[0], attack, str(pins["car"]["commit"])[:12])
        if car_paths[0].exists()
        else None
    )
    return Standards(attack.version or "", d3fend, ctid, car, load_csf_labels())
