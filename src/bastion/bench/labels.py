"""Technique labels for EVTX-ATTACK-SAMPLES, from the author's mapping sheet.

The upstream repository labels files by tactic folder only; the technique
mapping lives in a Google Sheet linked from its README. Bastion commits a
dated snapshot of that sheet under ``bench/labels/sources/`` and derives
``bench/labels/evtx-attack-samples.csv`` from it with
:func:`build_label_table`. The bench reads only the committed table, never
the network, and resolves retired technique ids through ATT&CK's
``revoked-by`` links at run time (:func:`resolve_labels`).

Sheet conventions handled here: a row whose tactic, technique and id cells
are all empty continues the previous row (merged cells); ``NA`` means the
author assigned no technique; ids appear as ``T1134/005`` or on several
lines in one cell; file names appear inside free text and may contain
spaces, so matching is done by searching each known file name in the text.
"""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from bastion.attack import AttackData

_TECHNIQUE_RE = re.compile(r"T\d{4}(?:[./]\d{3})?")
_BOUNDARY = set("abcdefghijklmnopqrstuvwxyz0123456789_.-")


@dataclass(frozen=True)
class SheetRow:
    tactic: str
    technique_name: str
    technique_ids: tuple[str, ...]
    text: str
    row_number: int


@dataclass(frozen=True)
class LabelRow:
    """One corpus file with the technique ids the sheet assigns to it."""

    path: str
    tactic_folder: str
    technique_ids: tuple[str, ...]
    sheet_rows: tuple[int, ...]


def parse_sheet(text: str) -> list[SheetRow]:
    """Parse the sheet CSV, resolving merged-cell continuations."""
    rows: list[SheetRow] = []
    reader = csv.reader(io.StringIO(text))
    header_seen = False
    previous: SheetRow | None = None
    for number, raw in enumerate(reader, start=1):
        if not header_seen:
            header_seen = True
            continue
        cells = [cell.strip() for cell in raw] + [""] * (4 - len(raw))
        tactic, name, ids_cell, text_cell = cells[:4]
        if not tactic and not name and not ids_cell and previous is not None:
            tactic, name, ids = previous.tactic, previous.technique_name, previous.technique_ids
        else:
            ids = tuple(
                match.replace("/", ".") for match in _TECHNIQUE_RE.findall(ids_cell.upper())
            )
        row = SheetRow(tactic, name, ids, text_cell, number)
        rows.append(row)
        previous = row
    return rows


def _mentions(name_lower: str, text_lower: str) -> bool:
    start = text_lower.find(name_lower)
    while start != -1:
        before = text_lower[start - 1] if start > 0 else " "
        if before not in _BOUNDARY:
            return True
        start = text_lower.find(name_lower, start + 1)
    return False


def build_label_table(rows: Sequence[SheetRow], paths: Iterable[str]) -> list[LabelRow]:
    """Assign sheet technique ids to corpus files by file name mention.

    ``paths`` are corpus-relative POSIX paths whose first component is the
    tactic folder. Files the sheet never names get an empty id tuple and
    stay in the table, so the bench can report them as scanned-unlabelled.
    """
    table: list[LabelRow] = []
    for path in sorted(paths):
        name_lower = path.rsplit("/", 1)[-1].lower()
        ids: list[str] = []
        matched_rows: list[int] = []
        for row in rows:
            if _mentions(name_lower, row.text.lower()):
                matched_rows.append(row.row_number)
                for technique_id in row.technique_ids:
                    if technique_id not in ids:
                        ids.append(technique_id)
        folder = path.split("/", 1)[0] if "/" in path else ""
        table.append(LabelRow(path, folder, tuple(ids), tuple(matched_rows)))
    return table


def unmatched_mentions(rows: Sequence[SheetRow], paths: Iterable[str]) -> list[str]:
    """File names the sheet mentions that no corpus path carries (renames, typos)."""
    names = {p.rsplit("/", 1)[-1].lower() for p in paths}
    missing: list[str] = []
    for row in rows:
        for token in re.findall(r"[^\s,;\"()\[\]&|>]+\.evtx", row.text, flags=re.IGNORECASE):
            if token.lower() not in names and not any(
                _mentions(name, row.text.lower()) for name in names
            ):
                missing.append(token)
    return sorted(set(missing))


def write_label_table(table: Sequence[LabelRow], header_comment: str) -> str:
    """Serialize the table as CSV with a ``#`` provenance header."""
    out = io.StringIO()
    for line in header_comment.splitlines():
        out.write(f"# {line}\n")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["path", "tactic_folder", "technique_ids", "sheet_rows"])
    for row in table:
        writer.writerow(
            [
                row.path,
                row.tactic_folder,
                " ".join(row.technique_ids),
                " ".join(str(n) for n in row.sheet_rows),
            ]
        )
    return out.getvalue()


def read_label_table(text: str) -> dict[str, LabelRow]:
    """Parse a committed label table; keys are corpus-relative paths."""
    lines = [line for line in text.splitlines() if not line.startswith("#")]
    table: dict[str, LabelRow] = {}
    for record in csv.DictReader(io.StringIO("\n".join(lines))):
        ids = tuple(record["technique_ids"].split()) if record["technique_ids"] else ()
        rows = tuple(int(n) for n in record["sheet_rows"].split()) if record["sheet_rows"] else ()
        table[record["path"]] = LabelRow(record["path"], record["tactic_folder"], ids, rows)
    return table


def resolve_labels(
    raw_ids: Iterable[str], attack: AttackData
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Map corpus technique ids to live ids for the pinned ATT&CK release.

    Returns ``(live_ids, notes)``. A revoked id is followed through
    ``revoked-by`` and noted; a deprecated or unknown id is dropped and
    noted, so it never counts as a labelled positive for a technique that
    does not exist in the release.
    """
    live: list[str] = []
    notes: list[str] = []
    for raw in raw_ids:
        resolved, status = attack.resolve_retired(raw)
        if status == "live" and resolved is not None:
            if resolved not in live:
                live.append(resolved)
        elif status == "revoked" and resolved is not None:
            notes.append(f"{raw.upper()} revoked, remapped to {resolved}")
            if resolved not in live:
                live.append(resolved)
        else:
            notes.append(f"{raw.upper()} {status} in this ATT&CK release, excluded")
    return tuple(live), tuple(notes)
