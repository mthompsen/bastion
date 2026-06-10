"""Report rendering: Markdown, JSON, and the self-contained HTML dashboard.

All three artifacts are rendered from one ScanResult/CoverageSummary pair,
which keeps their numbers consistent. Output contains no wall-clock
timestamps, and the dashboard makes no network requests (inline CSS only).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from jinja2 import Environment, PackageLoader

from bastion.coverage import CoverageSummary
from bastion.models import CoverageEntry, Detection, ScanResult

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
    return {
        "result": result,
        "summary": summary,
        "ctx": context,
        "techniques_hit": techniques_hit,
        "detection_groups": detections_by_tactic(result.detections),
        "coverage_groups": coverage_by_tactic(summary.entries),
        "uncovered_count": summary.total_count - summary.covered_count,
    }


def render_markdown(
    result: ScanResult, summary: CoverageSummary, context: ReportContext
) -> str:
    return _env.get_template("report.md.j2").render(_template_args(result, summary, context))


def render_dashboard(
    result: ScanResult, summary: CoverageSummary, context: ReportContext
) -> str:
    return _env.get_template("dashboard.html.j2").render(_template_args(result, summary, context))


def write_report(
    result: ScanResult,
    summary: CoverageSummary,
    context: ReportContext,
    outdir: Path,
) -> dict[str, Path]:
    """Write report.md, result.json and dashboard.html into ``outdir``."""
    outdir.mkdir(parents=True, exist_ok=True)
    paths = {
        "report.md": outdir / "report.md",
        "result.json": outdir / "result.json",
        "dashboard.html": outdir / "dashboard.html",
    }
    paths["report.md"].write_text(render_markdown(result, summary, context), encoding="utf-8")
    paths["result.json"].write_text(result.model_dump_json(indent=2), encoding="utf-8")
    paths["dashboard.html"].write_text(
        render_dashboard(result, summary, context), encoding="utf-8"
    )
    return paths
