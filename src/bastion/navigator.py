"""ATT&CK Navigator layers (layer format 4.5), marked lossy.

A layer carries one score and one comment per technique. Bastion's evidence model does not
fit: tri-state results, the basis and interval of every rate, the hunting class and the
per-event evidence behind a detection are not representable. Every layer therefore says it is
lossy in its description and its metadata (START_PROMPT section 3, rule 8), names the basis of
its scores, and carries the pins it was computed under.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from bastion import __version__
from bastion.coverage import CoverageSummary
from bastion.models import ScanResult
from bastion.pins import load_pins, standards_pin_summary

LOSSY_NOTE = (
    "Lossy export: a Navigator layer holds one score per technique, so Bastion's tri-state "
    "results, rate bases and intervals, hunting class and per-event evidence are not carried. "
    "Use result.json, result.sarif or findings.ocsf.json for the full record."
)

#: Evidence ladder rungs as layer scores (weakest to strongest).
LADDER_SCORES = {
    "none": 0,
    "rule-only": 1,
    "fixture-proven": 2,
    "sample-proven": 3,
    "held-out-proven": 4,
}
#: Rung colors: no rung is drawn in a success green; only held-out evidence uses the accent.
LADDER_COLORS = {
    "none": "#3a1f2a",
    "rule-only": "#d9d9d9",
    "fixture-proven": "#b9c2cf",
    "sample-proven": "#7fb2ff",
    "held-out-proven": "#1f6fb2",
}


@dataclass
class BenchEvidence:
    """The evidence ladder of one bench run, as read from its ``summary.json``."""

    run: str
    ladder: dict[str, str]
    pins: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_summary(cls, summary: dict[str, Any]) -> BenchEvidence:
        return cls(
            run=str(summary.get("run", "")),
            ladder={str(k): str(v) for k, v in summary["ladder"]["per_technique"].items()},
            pins={str(k): str(v) for k, v in summary.get("pins", {}).items()},
        )

    def pins_match(self, sigma_version: str | None, attack_version: str | None) -> bool:
        """Did the bench run use the same Sigma release and ATT&CK version as this scan?"""
        return self.pins.get("sigma") == sigma_version and self.pins.get("attack") == attack_version


def _metadata(basis: str, pins: dict[str, str]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = [
        {"name": "lossy", "value": "true"},
        {"name": "lossy_reason", "value": LOSSY_NOTE},
        {"name": "basis", "value": basis},
        {"divider": True},
    ]
    items.extend({"name": f"pin {k}", "value": v} for k, v in pins.items() if v)
    items.append({"name": "generator", "value": f"Bastion {__version__}"})
    return items


def _layer(
    name: str,
    description: str,
    basis: str,
    attack_version: str | None,
    pins: dict[str, str],
    techniques: list[dict[str, Any]],
    **extra: Any,
) -> dict[str, Any]:
    nav = load_pins()["standards"]["navigator"]
    layer: dict[str, Any] = {
        "name": name,
        "versions": {
            "attack": (attack_version or "").split(".")[0],
            "navigator": str(nav["navigator_version"]),
            "layer": str(nav["layer_format"]),
        },
        "domain": "enterprise-attack",
        "description": f"{description} {LOSSY_NOTE}",
        "sorting": 3,
        "hideDisabled": False,
        "techniques": techniques,
        "metadata": _metadata(basis, pins),
    }
    if not layer["versions"]["attack"]:
        del layer["versions"]["attack"]
    layer.update(extra)
    return layer


def render_layers(
    result: ScanResult,
    summary: CoverageSummary,
    *,
    logfile: str,
    attack_version: str | None,
    sigma_version: str | None,
    bench: BenchEvidence | None = None,
) -> str:
    """The scan's Navigator layers as one JSON array (Navigator opens a list of layers)."""
    pins = {"sigma": sigma_version or "", "attack": attack_version or ""}
    pins.update({f"standards {k}": v for k, v in standards_pin_summary().items()})

    tagged = [
        {
            "techniqueID": entry.technique.id,
            "score": entry.rule_count,
            "comment": f"{entry.rule_count} loaded rules tagged; rule-only evidence",
        }
        for entry in summary.entries
        if entry.covered
    ]
    max_rules = max((entry.rule_count for entry in summary.entries if entry.covered), default=1)
    layers = [
        _layer(
            "Bastion: techniques tagged by loaded rules",
            f"{summary.covered_count} of {summary.total_count} enterprise techniques are tagged by "
            "at least one loaded rule. A tag is not a validated detection.",
            "techniques tagged by at least one loaded rule (any status, hunting class included); "
            f"numerator {summary.covered_count}, denominator {summary.total_count} enterprise "
            "techniques; score is the number of rules",
            attack_version,
            pins,
            tagged,
            gradient={"colors": ["#ffffff", "#7fb2ff"], "minValue": 0, "maxValue": max_rules},
        )
    ]

    fired: dict[str, int] = {}
    for detection in result.detections:
        for ref in detection.techniques:
            fired[ref.id] = fired.get(ref.id, 0) + 1
    layers.append(
        _layer(
            f"Bastion: detections in {logfile}",
            f"{len(result.detections)} detections over {result.events_scanned} events, by the "
            "techniques of the rules that fired.",
            "detections per technique in this scan; a detection is a rule match on one event, not "
            "a confirmed attack",
            attack_version,
            pins,
            [
                {"techniqueID": tid, "score": count, "comment": f"{count} detections"}
                for tid, count in sorted(fired.items())
            ],
            gradient={
                "colors": ["#ffffff", "#ff9a4d"],
                "minValue": 0,
                "maxValue": max(fired.values(), default=1),
            },
        )
    )

    if bench is not None:
        match = bench.pins_match(sigma_version, attack_version)
        caveat = (
            ""
            if match
            else " The bench run used other pins than this scan "
            f"(bench Sigma {bench.pins.get('sigma', '?')}, ATT&CK {bench.pins.get('attack', '?')})."
        )
        layers.append(
            _layer(
                f"Bastion: evidence ladder (bench run {bench.run})",
                "Strongest evidence any rule has per technique, from the bench run." + caveat,
                "evidence ladder rung per enterprise technique from bench run "
                f"{bench.run}: 0 none, 1 rule-only, 2 fixture-proven, 3 sample-proven, "
                "4 held-out-proven",
                attack_version,
                {**pins, **{f"bench {k}": v for k, v in bench.pins.items()}},
                [
                    {
                        "techniqueID": tid,
                        "score": LADDER_SCORES.get(rung, 0),
                        "color": LADDER_COLORS.get(rung, ""),
                        "comment": rung,
                    }
                    for tid, rung in sorted(bench.ladder.items())
                ],
                legendItems=[
                    {"label": rung, "color": color} for rung, color in LADDER_COLORS.items()
                ],
            )
        )
    return json.dumps(layers, indent=2)
