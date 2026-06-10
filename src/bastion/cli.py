"""Bastion command-line interface (Typer app).

Commands (SPEC.md section 11): ``fetch``, ``scan``, ``coverage``,
``report`` and ``rules list``. Everything except the one-time ``fetch``
runs fully offline against the cached datasets.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import httpx
import typer
from rich.console import Console
from rich.table import Table

from bastion import __version__, engine
from bastion.attack import load_attack_data
from bastion.coverage import CoverageSummary, summarize_coverage
from bastion.fetch import (
    ATTACK_VERSION,
    DEFAULT_DATA_DIR,
    SIGMA_VERSION,
    attack_bundle_path,
    fetch_attack,
    fetch_sigma,
    sigma_rules_path,
)
from bastion.ingest import EvtxSource, select_source
from bastion.models import Platform, ScanResult
from bastion.report import ReportContext, write_report
from bastion.sigma import load_rules

app = typer.Typer(
    name="bastion",
    help="Sigma/ATT&CK detection engine for host log files (defensive; read-only).",
    no_args_is_help=True,
)
rules_app = typer.Typer(help="Inspect the loaded Sigma ruleset.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")

console = Console()

_LEVEL_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "informational": "dim",
}


class PlatformOption(StrEnum):
    """--platform choices."""

    windows = "windows"
    linux = "linux"


PlatformFlag = Annotated[
    PlatformOption | None,
    typer.Option(
        "--platform",
        help="Force the log platform instead of auto-detecting from file type / host OS.",
    ),
]
RulesDirFlag = Annotated[
    Path | None,
    typer.Option("--rules-dir", help="Sigma rules directory (default: the fetched cache)."),
]
AttackFileFlag = Annotated[
    Path | None,
    typer.Option("--attack-file", help="ATT&CK STIX bundle (default: the fetched cache)."),
]
LogfileArg = Annotated[
    Path,
    typer.Argument(exists=True, dir_okay=False, readable=True, help="Log file to scan."),
]


def _require(path: Path, what: str) -> Path:
    if not path.exists():
        console.print(f"[red]{what} not found at {path}.[/] Run [bold]bastion fetch[/] first.")
        raise typer.Exit(code=1)
    return path


def _level_cell(level: str) -> str:
    return f"[{_LEVEL_STYLES.get(level, '')}]{level}[/]"


def _print_scan_caveats(outcome: engine.ScanOutcome) -> None:
    if outcome.unsupported_rules:
        console.print(
            f"[yellow]{len(outcome.unsupported_rules)} rules use unsupported Sigma grammar"
            " and were not evaluated[/] (recorded, not counted as coverage)."
        )
    if outcome.rule_errors:
        console.print(
            f"[yellow]{len(outcome.rule_errors)} rules errored and were skipped[/];"
            " the scan continued without them."
        )
    if outcome.unresolved_techniques:
        ids = ", ".join(outcome.unresolved_techniques)
        console.print(
            f"[yellow]Technique tags not found in ATT&CK (deprecated or unknown):[/] {ids}"
        )


@app.callback(invoke_without_command=True)
def main(
    version: Annotated[
        bool, typer.Option("--version", help="Show the version and exit.", is_eager=True)
    ] = False,
) -> None:
    if version:
        console.print(f"bastion {__version__}")
        raise typer.Exit()


@app.command()
def scan(
    logfile: LogfileArg,
    platform: PlatformFlag = None,
    rules_dir: RulesDirFlag = None,
    attack_file: AttackFileFlag = None,
) -> None:
    """Scan a log file against the Sigma ruleset and print detections."""
    result, outcome, _, _, _ = _run_scan(logfile, platform, rules_dir, attack_file)

    if not result.detections:
        console.print("[green]No detections.[/]")
    else:
        table = Table(title=f"Detections in {logfile.name}")
        table.add_column("Rule", overflow="fold", max_width=48)
        table.add_column("Level")
        table.add_column("ATT&CK", overflow="fold")
        table.add_column("Evidence", overflow="fold", max_width=60)
        for detection in result.detections:
            techniques = ", ".join(
                f"{ref.id} {ref.name}" for ref in detection.techniques
            ) or "-"
            evidence = "; ".join(f"{k}={v}" for k, v in detection.matched_fields.items())
            table.add_row(
                detection.rule_title, _level_cell(detection.level), techniques, evidence
            )
        console.print(table)

    techniques_hit = {ref.id for det in result.detections for ref in det.techniques}
    covered = sum(1 for entry in result.coverage if entry.covered)
    console.print(
        f"[bold]{len(result.detections)}[/] detections across "
        f"[bold]{len(techniques_hit)}[/] techniques "
        f"({result.events_scanned} events, {result.rules_loaded} rules); "
        f"ruleset covers {covered} of {len(result.coverage)} enterprise techniques."
    )
    _print_scan_caveats(outcome)


@app.command()
def coverage(
    platform: PlatformFlag = None,
    rules_dir: RulesDirFlag = None,
    attack_file: AttackFileFlag = None,
    full: Annotated[
        bool, typer.Option("--full", help="List every technique, covered or not.")
    ] = False,
) -> None:
    """Show the ATT&CK coverage map of the loaded ruleset, including blind spots."""
    directory = _require(rules_dir or sigma_rules_path(), "Sigma rules")
    bundle = _require(attack_file or attack_bundle_path(), "ATT&CK STIX bundle")
    override: Platform | None = platform.value if platform else None
    rules = load_rules(directory, platform=override)
    attack_data = load_attack_data(bundle)
    summary = summarize_coverage(rules, attack_data.techniques)
    _print_coverage(summary, attack_data.version, len(rules), full)


def _print_coverage(
    summary: CoverageSummary, attack_version: str | None, rule_count: int, full: bool
) -> None:
    version_label = f"ATT&CK v{attack_version}" if attack_version else "ATT&CK"
    table = Table(title=f"Coverage by tactic ({version_label})")
    table.add_column("Tactic")
    table.add_column("Covered", justify="right")
    table.add_column("Total", justify="right")
    table.add_column("Share", justify="right")
    for tactic, (covered_count, total) in sorted(
        summary.tactic_totals.items(), key=lambda item: item[1][0] / item[1][1]
    ):
        share = covered_count / total
        style = "red" if share < 0.25 else "yellow" if share < 0.5 else "green"
        table.add_row(tactic, str(covered_count), str(total), f"[{style}]{share:.0%}[/]")
    console.print(table)

    uncovered = summary.total_count - summary.covered_count
    console.print(
        f"The loaded ruleset ({rule_count} rules) references "
        f"[bold]{summary.covered_count}[/] of [bold]{summary.total_count}[/] enterprise "
        f"techniques; [bold red]{uncovered} techniques have no detection rule[/]. "
        "Coverage counts rules, not proven detections."
    )
    if summary.unknown_technique_ids:
        ids = ", ".join(summary.unknown_technique_ids)
        console.print(
            f"[yellow]Rule tags not in this ATT&CK release (deprecated/unknown):[/] {ids}"
        )

    if full:
        detail = Table(title="Per-technique coverage")
        detail.add_column("Technique")
        detail.add_column("Name", overflow="fold", max_width=50)
        detail.add_column("Tactics", overflow="fold")
        detail.add_column("Rules", justify="right")
        for entry in summary.entries:
            style = "" if entry.covered else "[red]"
            close = "[/]" if style else ""
            detail.add_row(
                f"{style}{entry.technique.id}{close}",
                entry.technique.name,
                ", ".join(entry.technique.tactics),
                str(entry.rule_count),
            )
        console.print(detail)


@app.command()
def fetch(
    force: Annotated[
        bool, typer.Option("--force", help="Re-download even if a cached copy exists.")
    ] = False,
    data_dir: Annotated[
        Path, typer.Option("--data-dir", help="Cache directory.")
    ] = DEFAULT_DATA_DIR,
) -> None:
    """Download and cache the Sigma ruleset and the ATT&CK STIX bundle.

    After this one-time fetch, every other command runs fully offline.
    """
    try:
        attack_path = fetch_attack(data_dir=data_dir, force=force)
        size_mb = attack_path.stat().st_size / 1_000_000
        console.print(
            f"ATT&CK v{ATTACK_VERSION} STIX bundle cached at [bold]{attack_path}[/]"
            f" ({size_mb:.1f} MB)"
        )
        sigma_path = fetch_sigma(data_dir=data_dir, force=force)
        rule_files = sum(1 for _ in sigma_path.rglob("*.yml"))
        console.print(
            f"Sigma ruleset {SIGMA_VERSION} cached at [bold]{sigma_path}[/]"
            f" ({rule_files} rule files)"
        )
    except (httpx.HTTPError, ValueError) as exc:
        console.print(f"[red]Fetch failed:[/] {exc}")
        raise typer.Exit(code=1) from exc


@app.command()
def report(
    logfile: LogfileArg,
    outdir: Annotated[
        Path, typer.Option("--outdir", "-o", help="Directory for report artifacts.")
    ] = Path("out"),
    platform: PlatformFlag = None,
    rules_dir: RulesDirFlag = None,
    attack_file: AttackFileFlag = None,
) -> None:
    """Full run: report.md + result.json + dashboard.html."""
    result, outcome, summary, attack_version, log_platform = _run_scan(
        logfile, platform, rules_dir, attack_file
    )
    context = ReportContext(
        logfile=logfile.name,
        platform=log_platform,
        attack_version=attack_version,
        sigma_version=_sigma_version(rules_dir or sigma_rules_path()),
        unsupported_rule_count=len(outcome.unsupported_rules),
        rule_error_count=len(outcome.rule_errors),
        unresolved_techniques=outcome.unresolved_techniques or None,
    )
    paths = write_report(result, summary, context, outdir)
    techniques_hit = {ref.id for det in result.detections for ref in det.techniques}
    console.print(
        f"[bold]{len(result.detections)}[/] detections across "
        f"[bold]{len(techniques_hit)}[/] techniques; ruleset covers "
        f"{summary.covered_count} of {summary.total_count} enterprise techniques."
    )
    _print_scan_caveats(outcome)
    for path in paths.values():
        console.print(f"  wrote [bold]{path}[/]")


def _sigma_version(rules_dir: Path) -> str | None:
    """The pinned release recorded by fetch, if this is the fetched cache."""
    version_file = rules_dir.parent / "sigma.version.txt"
    if not version_file.exists():
        return None
    for line in version_file.read_text(encoding="utf-8").splitlines():
        if line.startswith("version:"):
            return line.split(":", 1)[1].strip()
    return None


@rules_app.command("list")
def rules_list(
    platform: PlatformFlag = None,
    rules_dir: RulesDirFlag = None,
    limit: Annotated[
        int, typer.Option("--limit", help="Max rules to display (0 = no limit).")
    ] = 50,
) -> None:
    """List loaded Sigma rules and their ATT&CK techniques."""
    directory = _require(rules_dir or sigma_rules_path(), "Sigma rules")
    override: Platform | None = platform.value if platform else None
    rules = load_rules(directory, platform=override)

    table = Table(title=f"Sigma rules ({directory})")
    table.add_column("Title", overflow="fold", max_width=60)
    table.add_column("Level")
    table.add_column("Logsource")
    table.add_column("ATT&CK techniques")
    shown = rules if limit == 0 else rules[:limit]
    for rule in shown:
        parts = ("product", "category", "service")
        logsource = "/".join(value for key in parts if (value := rule.logsource.get(key)))
        table.add_row(
            rule.title, _level_cell(rule.level), logsource, ", ".join(rule.attack_techniques)
        )
    console.print(table)
    suffix = "" if len(shown) == len(rules) else f" (showing first {len(shown)}; use --limit 0)"
    console.print(f"[bold]{len(rules)}[/] rules loaded{suffix}.")


def _run_scan(
    logfile: Path,
    platform: PlatformOption | None,
    rules_dir: Path | None,
    attack_file: Path | None,
) -> tuple[ScanResult, engine.ScanOutcome, CoverageSummary, str | None, Platform]:
    """Shared scan pipeline: ingest → rules → engine → ScanResult.

    Returns the assembled ScanResult, the raw engine outcome (for the
    caveat notes), the coverage summary, the ATT&CK bundle version, and
    the platform the log was treated as.
    """
    directory = _require(rules_dir or sigma_rules_path(), "Sigma rules")
    bundle = _require(attack_file or attack_bundle_path(), "ATT&CK STIX bundle")

    override: Platform | None = platform.value if platform else None
    source = select_source(logfile, override)
    log_platform: Platform = "windows" if isinstance(source, EvtxSource) else "linux"

    rules = load_rules(directory, platform=log_platform)
    attack_data = load_attack_data(bundle)
    outcome = engine.scan(source.parse(logfile), rules, attack_data.techniques)
    summary = summarize_coverage(rules, attack_data.techniques)
    result = ScanResult(
        detections=outcome.detections,
        events_scanned=outcome.events_scanned,
        rules_loaded=len(rules),
        coverage=summary.entries,
    )
    return result, outcome, summary, attack_data.version, log_platform


if __name__ == "__main__":
    app()
