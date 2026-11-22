"""Report rendering: Markdown, JSON, SARIF, and the HTML dashboard.

All artifacts are rendered from one ScanResult/CoverageSummary pair, which
keeps their numbers consistent. Output contains no wall-clock timestamps,
and the dashboard makes no network requests (inline CSS only).
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader

from bastion import __version__
from bastion.coverage import CoverageSummary
from bastion.models import CoverageEntry, Detection, ScanResult
from bastion.navigator import BenchEvidence, render_layers
from bastion.normalize import OCSF_VERSION, detection_finding
from bastion.pins import pin_summary, standards_pin_summary

#: Sigma levels mapped to SARIF result levels.
_SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}

_LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

_env = Environment(
    loader=PackageLoader("bastion", "templates"),
    autoescape=lambda name: name is not None and ".html" in name,
    trim_blocks=True,
    lstrip_blocks=True,
)


def _mdcell(value: object) -> str:
    """Make a value safe inside a Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\n", " ")


_env.filters["mdcell"] = _mdcell


@dataclass
class ReportContext:
    """Run metadata shared by every artifact."""

    logfile: str
    platform: str
    attack_version: str | None = None
    sigma_version: str | None = None
    unsupported_rule_count: int = 0
    rule_error_count: int = 0
    unresolved_techniques: list[str] | None = None
    #: evidence ladder of a bench run, given explicitly (a scan has no ladder of its own)
    bench: BenchEvidence | None = None


def detections_by_tactic(detections: list[Detection]) -> dict[str, list[Detection]]:
    """Group detections under each ATT&CK tactic they map to.

    A detection with techniques in several tactics appears under each;
    one with no resolved technique lands under "unmapped". Groups are
    ordered by detection count (largest first), detections by severity.
    """
    groups: dict[str, list[Detection]] = defaultdict(list)
    for detection in detections:
        tactics = sorted({t for ref in detection.techniques for t in ref.tactics})
        for tactic in tactics or ["unmapped"]:
            groups[tactic].append(detection)
    for group in groups.values():
        group.sort(key=lambda d: _LEVEL_ORDER.get(d.level, 9))
    return dict(sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])))


def coverage_by_tactic(
    entries: list[CoverageEntry],
) -> dict[str, dict[str, list[CoverageEntry]]]:
    """Per tactic: which techniques are covered and which are blind spots."""
    grouped: dict[str, dict[str, list[CoverageEntry]]] = {}
    for entry in entries:
        for tactic in entry.technique.tactics:
            bucket = grouped.setdefault(tactic, {"covered": [], "uncovered": []})
            bucket["covered" if entry.covered else "uncovered"].append(entry)
    return dict(sorted(grouped.items()))


def _template_args(
    result: ScanResult, summary: CoverageSummary, context: ReportContext
) -> dict[str, object]:
    techniques_hit = sorted(
        {ref.id for detection in result.detections for ref in detection.techniques}
    )
    timeline = sorted(
        result.detections,
        key=lambda d: (
            d.event.timestamp is None,
            d.event.timestamp.isoformat() if d.event.timestamp else "",
            d.rule_title,
        ),
    )
    return {
        "result": result,
        "summary": summary,
        "ctx": context,
        "techniques_hit": techniques_hit,
        "detection_groups": detections_by_tactic(result.detections),
        "coverage_groups": coverage_by_tactic(summary.entries),
        "uncovered_count": summary.total_count - summary.covered_count,
        "timeline": timeline,
    }


def render_markdown(result: ScanResult, summary: CoverageSummary, context: ReportContext) -> str:
    return _env.get_template("report.md.j2").render(_template_args(result, summary, context))


def render_dashboard(result: ScanResult, summary: CoverageSummary, context: ReportContext) -> str:
    return _env.get_template("dashboard.html.j2").render(_template_args(result, summary, context))


#: Basis of the scan's coverage numbers, as every output names it (contract rule 4).
TAGGED_COVERAGE_BASIS = (
    "enterprise techniques tagged by at least one loaded rule (any status, hunting class "
    "included); rule-only evidence, not validated detection"
)


def _ladder_levels(technique_ids: list[str], bench: BenchEvidence | None) -> dict[str, str]:
    """Evidence ladder rung per technique from the given bench run; empty without one."""
    if bench is None:
        return {}
    return {tid: bench.ladder.get(tid, "none") for tid in technique_ids}


def _sarif_run_properties(
    context: ReportContext, summary: CoverageSummary | None
) -> dict[str, Any]:
    bench = context.bench
    ladder: dict[str, Any] = {
        "source": f"bench run {bench.run}" if bench else None,
        "note": (
            "ladder levels come from the named bench run"
            if bench
            else "no bench summary given (bastion report --bench-summary); "
            "no ladder level is stated"
        ),
    }
    if bench is not None:
        ladder["pinsMatchScan"] = bench.pins_match(context.sigma_version, context.attack_version)
        ladder["benchPins"] = dict(bench.pins)
    properties: dict[str, Any] = {
        "scanPins": {"sigma": context.sigma_version, "attack": context.attack_version},
        "pins": pin_summary(),
        "standardsPins": standards_pin_summary(),
        "evidenceLadder": ladder,
        "ocsfFindings": {"file": "findings.ocsf.json", "ocsfVersion": OCSF_VERSION},
    }
    if summary is not None:
        properties["taggedCoverage"] = {
            "numerator": summary.covered_count,
            "denominator": summary.total_count,
            "basis": TAGGED_COVERAGE_BASIS,
            "attackVersion": context.attack_version,
            "sigmaVersion": context.sigma_version,
        }
    return properties


def render_sarif(
    result: ScanResult, context: ReportContext, summary: CoverageSummary | None = None
) -> str:
    """Serialize the detections as a SARIF 2.1.0 log.

    Each fired Sigma rule becomes a SARIF reporting rule; each detection
    becomes a result pointing at the scanned log file, with the matched
    fields and ATT&CK techniques in the message and properties. The run's
    ``properties.bastion`` carries the pins, the coverage numbers with their
    basis, and where ladder levels come from; each rule and result carries the
    ladder level of its techniques when a bench summary was given.
    """
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for detection in result.detections:
        if detection.rule_id not in rules:
            rules[detection.rule_id] = {
                "id": detection.rule_id,
                "name": detection.rule_title,
                "defaultConfiguration": {"level": _SARIF_LEVELS.get(detection.level, "warning")},
                "properties": {
                    "sigmaLevel": detection.level,
                    "attackTechniques": [ref.id for ref in detection.techniques],
                    "ladderLevels": _ladder_levels(
                        [ref.id for ref in detection.techniques], context.bench
                    ),
                },
            }
        evidence = "; ".join(f"{k}={v}" for k, v in detection.matched_fields.items())
        techniques = ", ".join(f"{ref.id} {ref.name}" for ref in detection.techniques)
        message = detection.rule_title
        if techniques:
            message += f" [{techniques}]"
        if evidence:
            message += f" | {evidence}"
        sarif_result: dict[str, Any] = {
            "ruleId": detection.rule_id,
            "level": _SARIF_LEVELS.get(detection.level, "warning"),
            "message": {"text": message},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": context.logfile}}}],
            "properties": {
                "matchedFields": detection.matched_fields,
                "attackTechniques": [ref.id for ref in detection.techniques],
                "eventSource": detection.event.source,
                "ladderLevels": _ladder_levels(
                    [ref.id for ref in detection.techniques], context.bench
                ),
            },
        }
        if detection.event.timestamp is not None:
            sarif_result["properties"]["eventTimestamp"] = detection.event.timestamp.isoformat()
        results.append(sarif_result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "bastion",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"bastion": _sarif_run_properties(context, summary)},
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render_ocsf_findings(result: ScanResult, context: ReportContext) -> str:
    """Every detection as an OCSF 1.9.0 Detection Finding (2004), as one JSON array."""
    findings = [
        detection_finding(
            detection,
            attack_version=context.attack_version,
            sigma_version=context.sigma_version,
        )
        for detection in result.detections
    ]
    return json.dumps(findings, indent=2)


def write_report(
    result: ScanResult,
    summary: CoverageSummary,
    context: ReportContext,
    outdir: Path,
) -> dict[str, Path]:
    """Write report.md, result.json, result.sarif, dashboard.html, the OCSF findings and the
    Navigator layers (lossy) into ``outdir``."""
    outdir.mkdir(parents=True, exist_ok=True)
    paths = {
        "report.md": outdir / "report.md",
        "result.json": outdir / "result.json",
        "result.sarif": outdir / "result.sarif",
        "dashboard.html": outdir / "dashboard.html",
        "findings.ocsf.json": outdir / "findings.ocsf.json",
        "layers.navigator.json": outdir / "layers.navigator.json",
    }
    paths["report.md"].write_text(render_markdown(result, summary, context), encoding="utf-8")
    paths["result.json"].write_text(result.model_dump_json(indent=2), encoding="utf-8")
    paths["result.sarif"].write_text(render_sarif(result, context, summary), encoding="utf-8")
    paths["dashboard.html"].write_text(render_dashboard(result, summary, context), encoding="utf-8")
    paths["findings.ocsf.json"].write_text(render_ocsf_findings(result, context), encoding="utf-8")
    layers = render_layers(
        result,
        summary,
        logfile=context.logfile,
        attack_version=context.attack_version,
        sigma_version=context.sigma_version,
        bench=context.bench,
    )
    paths["layers.navigator.json"].write_text(layers, encoding="utf-8")
    return paths
