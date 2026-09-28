"""In-repo synthetic logs: the ``fixture-proven`` rung of the evidence ladder.

These are hand-written traces committed with the repository, labelled in
``bench/labels/fixtures.csv``. A rule that fires on one is fixture-proven
and nothing more; they never enter the dev or test split.
"""

from __future__ import annotations

import csv
from pathlib import Path

from bastion.attack import AttackData
from bastion.bench.captures import Capture, SourceKind
from bastion.bench.labels import resolve_labels

CORPUS = "fixtures"
_KINDS: dict[str, SourceKind] = {
    "evtx": "evtx",
    "auditd": "auditd",
    "syslog": "syslog",
    "journald": "journald",
}


def fixture_captures(repo_root: Path, labels_file: Path, attack: AttackData) -> list[Capture]:
    captures: list[Capture] = []
    lines = [
        line
        for line in labels_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    for record in csv.DictReader(lines):
        path = repo_root / record["path"]
        if not path.is_file():
            continue
        raw = tuple(record["technique_ids"].split())
        live, notes = resolve_labels(raw, attack)
        platform = record.get("platform", "linux")
        captures.append(
            Capture(
                id=f"{CORPUS}/{record['path']}",
                corpus=CORPUS,
                kind="fixture",
                platform="windows" if platform == "windows" else "linux",
                source_kind=_KINDS[record["source_kind"]],
                paths=(path,),
                techniques=live,
                raw_labels=raw,
                label_notes=notes,
                host="synthetic",
                license="MIT (written for this repository)",
            )
        )
    return captures
