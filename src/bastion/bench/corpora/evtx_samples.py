"""EVTX-ATTACK-SAMPLES: real Windows attack telemetry, labelled from the author's sheet.

The archive is fetched by pinned commit; only ``.evtx`` members are kept,
under their tactic folders. Technique labels come from the committed table
(:mod:`bastion.bench.labels`); files the table does not label are still
captures, marked unlabelled, so the bench can count them as scanned without
counting them in any rate.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import httpx

from bastion.attack import AttackData
from bastion.bench.cache import download, extract_zip
from bastion.bench.captures import Capture
from bastion.bench.labels import LabelRow, SupplementRow, resolve_labels
from bastion.pins import load_pins

CORPUS = "evtx_attack_samples"


def corpus_dir(cache: Path) -> Path:
    commit = str(load_pins()["corpora"][CORPUS]["commit"])
    return cache / "evtx-attack-samples" / commit


def fetch_evtx_samples(
    cache: Path, client: httpx.Client | None = None, force: bool = False
) -> Path:
    pins = load_pins()["corpora"][CORPUS]
    archive = download(
        str(pins["url"]),
        cache / "evtx-attack-samples" / f"{pins['commit']}.zip",
        client,
        force=force,
    )

    def select(name: str) -> Path | None:
        parts = name.split("/", 1)
        if len(parts) < 2 or not parts[1].lower().endswith(".evtx"):
            return None
        return Path(parts[1])

    root = corpus_dir(cache)
    extract_zip(archive, root, select, force=force)
    return root


def sample_paths(root: Path) -> list[str]:
    """Corpus-relative POSIX paths of every EVTX file."""
    return sorted(
        p.relative_to(root).as_posix() for p in root.rglob("*") if p.suffix.lower() == ".evtx"
    )


def evtx_sample_captures(
    root: Path,
    labels: Mapping[str, LabelRow],
    attack: AttackData,
    supplement: Mapping[str, SupplementRow] | None = None,
) -> list[Capture]:
    """One capture per EVTX file, labelled from the sheet table.

    A file the sheet table leaves without a live label takes its label from the
    supplement (``bench/labels/evtx-attack-samples-supplement.csv``) when that row is
    ``exact`` or ``inferred_from_name``; the capture's notes record the source and the
    confidence. Ambiguous supplement rows leave the file unlabelled.
    """
    license_text = str(load_pins()["corpora"][CORPUS]["license"])
    captures: list[Capture] = []
    for relative in sample_paths(root):
        row = labels.get(relative)
        raw = row.technique_ids if row else ()
        live, notes = resolve_labels(raw, attack)
        extra = (supplement or {}).get(relative)
        capture_notes: dict[str, str] = (
            {} if row else {"label": "file not named in the mapping sheet"}
        )
        if not live and extra is not None:
            capture_notes["label_confidence"] = extra.confidence
            capture_notes["label_source"] = extra.source
            if extra.applied:
                sheet_notes = notes
                raw = extra.technique_ids
                live, notes = resolve_labels(raw, attack)
                notes = sheet_notes + notes
        folder = relative.split("/", 1)[0] if "/" in relative else ""
        captures.append(
            Capture(
                id=f"{CORPUS}/{relative}",
                corpus=CORPUS,
                kind="positive",
                platform="windows",
                source_kind="evtx",
                paths=(root / relative,),
                techniques=live,
                raw_labels=raw,
                label_notes=notes,
                tactic=folder,
                license=license_text,
                notes=capture_notes,
            )
        )
    return captures
