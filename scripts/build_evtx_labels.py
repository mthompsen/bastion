"""Derive the committed EVTX-ATTACK-SAMPLES label table from the sheet snapshot.

Reads ``bench/labels/sources/<snapshot>.csv`` (a dated copy of the author's
mapping sheet) and the corpus file list from the cache, and writes
``bench/labels/evtx-attack-samples.csv``. Run from the repository root
after ``bastion bench fetch``:

    python scripts/build_evtx_labels.py
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from bastion.bench.cache import cache_root
from bastion.bench.corpora.evtx_samples import corpus_dir, sample_paths
from bastion.bench.labels import (
    build_label_table,
    parse_sheet,
    unmatched_mentions,
    write_label_table,
)
from bastion.pins import load_pins

SNAPSHOT = Path("bench/labels/sources/evtx-attack-samples-sheet-2026-09-26.csv")
OUTPUT = Path("bench/labels/evtx-attack-samples.csv")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=SNAPSHOT)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--cache-dir", type=Path, default=None)
    args = parser.parse_args(argv)

    pins = load_pins()["corpora"]["evtx_attack_samples"]
    raw = args.snapshot.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8")
    if digest != pins["labels_sha256"]:
        print(f"snapshot sha256 {digest} does not match PINS.toml labels_sha256", file=sys.stderr)
        return 1
    root = corpus_dir(args.cache_dir or cache_root())
    if not root.is_dir():
        print(f"corpus not fetched at {root}; run `bastion bench fetch` first", file=sys.stderr)
        return 1
    paths = sample_paths(root)
    rows = parse_sheet(text)
    table = build_label_table(rows, paths)
    labelled = sum(1 for row in table if row.technique_ids)
    header = (
        "EVTX-ATTACK-SAMPLES technique labels, derived from the author's mapping sheet.\n"
        f"Corpus: sbousseaden/EVTX-ATTACK-SAMPLES at {pins['commit']} (GPL-3.0).\n"
        f"Sheet: {pins['labels_source']}\n"
        f"Sheet retrieved {pins['labels_retrieved']}, sha256 {pins['labels_sha256']}.\n"
        "Technique ids are as the sheet wrote them; retired ids are resolved through ATT&CK\n"
        "revoked-by links at bench time. Empty technique_ids means the sheet names no technique\n"
        "for the file (scanned-unlabelled). Regenerate with scripts/build_evtx_labels.py."
    )
    args.output.write_text(write_label_table(table, header), encoding="utf-8")
    missing = unmatched_mentions(rows, paths)
    print(
        f"{len(table)} files, {labelled} labelled with a technique, "
        f"{len(table) - labelled} unlabelled"
    )
    print(f"{len(missing)} sheet file mentions match no corpus file: {', '.join(missing[:20])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
