"""Bastion command-line interface (Typer app).

Phase 1 ships the skeleton: every command from SPEC.md section 11 exists and
is ``--help``-documented; ``scan`` already ingests logs (detection arrives
with the Sigma engine in later phases), the rest exit non-zero until their
phase lands.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from bastion import __version__
from bastion.ingest import select_source
from bastion.models import Platform

app = typer.Typer(
    name="bastion",
    help="Sigma/ATT&CK detection engine for host log files (defensive; read-only).",
    no_args_is_help=True,
)
rules_app = typer.Typer(help="Inspect the loaded Sigma ruleset.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")

console = Console()


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


def _not_implemented(feature: str, phase: int) -> None:
    console.print(f"[yellow]{feature} is not implemented yet — it lands in Phase {phase}.[/]")
    raise typer.Exit(code=2)


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
    logfile: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, readable=True, help="Log file to scan."),
    ],
    platform: PlatformFlag = None,
) -> None:
    """Scan a log file and report detections to the terminal.

    Phase 1 behaviour: parse and summarize the log (the Sigma rule engine
    that turns events into detections arrives in Phases 3-4).
    """
    override: Platform | None = platform.value if platform else None
    source = select_source(logfile, override)
    events = list(source.parse(logfile))

    table = Table(title=f"Events parsed from {logfile.name} (first 10)")
    table.add_column("Timestamp")
    table.add_column("Platform")
    table.add_column("Summary", overflow="fold")
    for event in events[:10]:
        timestamp = event.timestamp.isoformat() if event.timestamp else "-"
        summary = ", ".join(
            f"{key}={value}" for key, value in list(event.fields.items())[:4] if value is not None
        )
        table.add_row(timestamp, event.platform, summary)
    console.print(table)
    console.print(
        f"Parsed [bold]{len(events)}[/] events. "
        "[yellow]Rule evaluation arrives with the Sigma engine (Phases 3-4).[/]"
    )


@app.command()
def fetch() -> None:
    """Download and cache the Sigma ruleset and the ATT&CK STIX bundle."""
    _not_implemented("bastion fetch", phase=2)


@app.command()
def coverage(platform: PlatformFlag = None) -> None:
    """Show the ATT&CK coverage map of the loaded ruleset."""
    _not_implemented("bastion coverage", phase=4)


@app.command()
def report(
    logfile: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, readable=True, help="Log file to scan."),
    ],
    outdir: Annotated[
        Path, typer.Option("--outdir", "-o", help="Directory for report artifacts.")
    ] = Path("out"),
    platform: PlatformFlag = None,
) -> None:
    """Full run: report.md + result.json + dashboard.html."""
    _not_implemented("bastion report", phase=5)


@rules_app.command("list")
def rules_list(platform: PlatformFlag = None) -> None:
    """List loaded Sigma rules and their ATT&CK techniques."""
    _not_implemented("bastion rules list", phase=3)


if __name__ == "__main__":
    app()
