"""``bastion standards``: fetch the pinned standards data and report on it (B5)."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any

import httpx
import typer
from rich.console import Console
from rich.table import Table

from bastion.attack import AttackData, load_attack_data
from bastion.fetch import DEFAULT_DATA_DIR, attack_bundle_path
from bastion.standards import Standards, load_standards
from bastion.standards.dettect import load_dettect
from bastion.standards.fetch import fetch_standards

standards_app = typer.Typer(
    help="Pinned standards data (D3FEND, CTID 800-53, CAR, CSF, DeTT&CT) and version drift.",
    no_args_is_help=True,
)
console = Console()

DataDirFlag = Annotated[Path, typer.Option("--data-dir", help="Cache directory.")]
AttackFlag = Annotated[
    Path | None,
    typer.Option("--attack-file", help="ATT&CK STIX bundle (default: the fetched cache)."),
]
JsonFlag = Annotated[bool, typer.Option("--json", help="Print JSON instead of a table.")]


def _attack(attack_file: Path | None, data_dir: Path) -> AttackData:
    bundle = attack_file or attack_bundle_path(data_dir)
    if not bundle.exists():
        console.print(f"[red]ATT&CK STIX bundle not found:[/] {bundle}. Run `bastion fetch` first.")
        raise typer.Exit(code=1)
    return load_attack_data(bundle)


def _load(attack_file: Path | None, data_dir: Path) -> Standards:
    return load_standards(_attack(attack_file, data_dir), data_dir)


@standards_app.command("fetch")
def fetch(
    force: Annotated[bool, typer.Option("--force", help="Re-download cached files.")] = False,
    data_dir: DataDirFlag = DEFAULT_DATA_DIR,
) -> None:
    """Download the pinned D3FEND, CTID and CAR files into the cache and check their digests."""
    try:
        rows = fetch_standards(data_dir=data_dir, force=force)
    except (httpx.HTTPError, ValueError) as exc:
        console.print(f"[red]Fetch failed:[/] {exc}")
        raise typer.Exit(code=1) from exc
    for row in rows:
        note = (
            "" if row["digest_matches"] else " (digest differs from the pin; the commit is the pin)"
        )
        console.print(f"{row['status']}: {row['file']}{note}")


@standards_app.command("status")
def status(
    data_dir: DataDirFlag = DEFAULT_DATA_DIR,
    attack_file: AttackFlag = None,
    as_json: JsonFlag = False,
) -> None:
    """Each source's pin, whether it is fetched, and how its ATT&CK ids drift from the pin."""
    standards = _load(attack_file, data_dir)
    rows = standards.status()
    if as_json:
        print(json.dumps({"attack_version": standards.attack_version, "sources": rows}, indent=2))
        return
    table = Table(title=f"Standards data against ATT&CK {standards.attack_version}")
    for column in ("Source", "Pin", "Maps ATT&CK", "Fetched", "Techniques", "Drift"):
        table.add_column(column)
    for row in rows:
        drift: dict[str, Any] = row.get("drift") or {}
        table.add_row(
            row["source"],
            row["pin"],
            row["declared_attack_version"] or ("not stated" if row["source"] != "csf" else "n/a"),
            "yes" if row["fetched"] else "no (run `bastion standards fetch`)",
            str(row.get("techniques_mapped", row.get("functions_labelled", ""))),
            "; ".join(drift.get("warnings", []))
            or ("labels are Bastion's assertion" if row["source"] == "csf" else ""),
        )
    console.print(table)


@standards_app.command("technique")
def technique(
    technique_id: Annotated[
        str, typer.Argument(help="ATT&CK technique id, for example T1003.001.")
    ],
    data_dir: DataDirFlag = DEFAULT_DATA_DIR,
    attack_file: AttackFlag = None,
    as_json: JsonFlag = False,
) -> None:
    """D3FEND countermeasures, 800-53 controls and CAR analytics mapped to one technique."""
    standards = _load(attack_file, data_dir)
    wanted = technique_id.strip().upper()
    out: dict[str, Any] = {"technique": wanted, "attack_version": standards.attack_version}
    for key, mapping in standards.mappings().items():
        if mapping is None:
            out[key] = None
            continue
        entries = mapping.for_technique(wanted)
        out[key] = {
            "pin": mapping.version,
            "entries": [asdict(entry) for entry in entries],
            "warnings": mapping.drift.warnings,
        }
    if as_json:
        print(json.dumps(out, indent=2))
        return
    for key in ("d3fend", "ctid_800_53", "car"):
        block = out[key]
        if block is None:
            console.print(f"[bold]{key}[/]: not fetched (run `bastion standards fetch`)")
            continue
        console.print(f"[bold]{key}[/] ({block['pin']}): {len(block['entries'])} entries")
        for entry in block["entries"]:
            console.print("  " + ", ".join(f"{k}={v}" for k, v in entry.items() if v))
        for warning in block["warnings"]:
            console.print(f"  [yellow]drift:[/] {warning}")


@standards_app.command("dettect")
def dettect(
    path: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="DeTT&CT administration YAML file.")
    ],
    data_dir: DataDirFlag = DEFAULT_DATA_DIR,
    attack_file: AttackFlag = None,
    as_json: JsonFlag = False,
) -> None:
    """Read a DeTT&CT administration file and report its format and drift; scores as stated."""
    loaded = load_dettect(path, _attack(attack_file, data_dir))
    out: dict[str, Any] = {
        "path": loaded.path,
        "file_type": loaded.file_type,
        "version": loaded.version,
        "name": loaded.name,
        "supported": loaded.supported,
        "techniques": len(loaded.techniques),
        "data_sources": len(loaded.data_sources),
        "unknown_data_sources": loaded.unknown_data_sources,
        "warnings": loaded.warnings,
        "drift": loaded.drift.as_dict() if loaded.drift else None,
    }
    if as_json:
        print(json.dumps(out, indent=2))
        return
    console.print(
        f"{loaded.file_type or '(no file_type)'} format {loaded.version or '(none)'}: "
        f"{'supported' if loaded.supported else 'not supported'}; "
        f"{len(loaded.techniques)} techniques, {len(loaded.data_sources)} data sources."
    )
    for warning in loaded.warnings:
        console.print(f"  [yellow]{warning}[/]")
