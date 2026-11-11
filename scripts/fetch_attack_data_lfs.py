"""Select and pull Splunk attack_data Windows and Sysmon for Linux datasets with git LFS.

B3 addition 1. Works on a pointer-only clone of ``splunk/attack_data`` at the pinned
commit (``GIT_LFS_SKIP_SMUDGE=1``), so the size of every LFS object is known from its
pointer before anything is downloaded:

1. ``select``: every dataset YAML naming a Windows event log file (``XmlWinEventLog``
   sourcetype or source) or a Sysmon for Linux file (``sysmon:linux``) is sized from its
   pointers. A dataset is kept when its files of that family total at most ``--cap-mb``
   (a bench run-time bound, chosen by size alone, before any rule runs). The kept YAML
   paths are written to the packaged dataset lists, and every excluded dataset is written
   with its size to ``bench/labels/attack-data-excluded.csv`` so nothing is dropped
   silently.
2. ``pull``: ``git lfs pull --include`` for exactly the kept files, in batches, then each
   kept YAML and file is copied into the corpus cache layout
   (``<cache>/attack_data/<commit>/datasets/...``) that the loader reads.

Technique labels are never set here: the loader reads them from each dataset's own YAML
``mitre_technique``. Run from the repository root:

    python scripts/fetch_attack_data_lfs.py select --clone <clone> [--cap-mb 5]
    python scripts/fetch_attack_data_lfs.py pull --clone <clone> --cache <cache>
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from bastion.pins import load_pins

DATA_DIR = Path("src/bastion/data")
LISTS = {
    "windows": DATA_DIR / "attack_data_windows_datasets.txt",
    "sysmon_linux": DATA_DIR / "attack_data_sysmon_linux_datasets.txt",
}
EXCLUDED = Path("bench/labels/attack-data-excluded.csv")
UNAVAILABLE = Path("bench/labels/attack-data-unavailable.csv")
_POINTER_SIZE = re.compile(rb"^size (\d+)$", re.M)


def family(entry: dict[str, object]) -> str | None:
    """Which loader reads a dataset file: ``windows``, ``sysmon_linux`` or none."""
    sourcetype = str(entry.get("sourcetype", ""))
    source = str(entry.get("source", ""))
    if sourcetype.lower() == "sysmon:linux":
        return "sysmon_linux"
    if sourcetype.startswith("XmlWinEventLog") or source.startswith("XmlWinEventLog"):
        return "windows"
    return None


def object_size(path: Path) -> int:
    head = path.read_bytes()[:300]
    if head.startswith(b"version https://git-lfs"):
        found = _POINTER_SIZE.search(head)
        if found:
            return int(found.group(1))
    return path.stat().st_size


def pointer_size(clone: Path, relative: str) -> int | None:
    """The object size the committed LFS pointer names; None when the file is not in LFS."""
    blob = subprocess.run(
        ["git", "-C", str(clone), "show", f"HEAD:{relative}"], check=True, capture_output=True
    ).stdout
    if blob.startswith(b"version https://git-lfs"):
        found = _POINTER_SIZE.search(blob)
        if found:
            return int(found.group(1))
    return None


def datasets(clone: Path) -> list[tuple[str, str, list[str], int, list[str]]]:
    """(yaml path, family, file paths, total bytes, techniques) per dataset and family."""
    out: list[tuple[str, str, list[str], int, list[str]]] = []
    for yaml_path in sorted((clone / "datasets" / "attack_techniques").glob("*/*/*.yml")):
        try:
            doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        by_family: dict[str, list[str]] = {}
        for entry in doc.get("datasets") or []:
            kind = family(entry)
            relative = str(entry.get("path", "")).lstrip("/")
            if kind and relative and (clone / relative).is_file():
                by_family.setdefault(kind, []).append(relative)
        techniques = [str(t) for t in doc.get("mitre_technique") or []]
        for kind, files in by_family.items():
            size = sum(object_size(clone / f) for f in files)
            relative_yaml = yaml_path.relative_to(clone).as_posix()
            out.append((relative_yaml, kind, files, size, techniques))
    return out


def select(clone: Path, cap_mb: float) -> int:
    cap = int(cap_mb * 1_000_000)
    kept: dict[str, list[str]] = {kind: [] for kind in LISTS}
    excluded: list[tuple[str, str, int, str]] = []
    for yaml_path, kind, _files, size, techniques in datasets(clone):
        if size <= cap:
            kept[kind].append(yaml_path)
        else:
            excluded.append((yaml_path, kind, size, " ".join(techniques)))
    for kind, paths in kept.items():
        LISTS[kind].write_text("\n".join(sorted(set(paths))) + "\n", encoding="utf-8")
        print(f"{kind}: {len(set(paths))} datasets kept -> {LISTS[kind]}")
    with EXCLUDED.open("w", encoding="utf-8", newline="") as handle:
        handle.write(
            f"# attack_data datasets left out of the bench because their files of one family "
            f"total more than {cap_mb:g} MB (B3, bench run-time bound, by size only).\n"
        )
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["yaml", "family", "bytes", "mitre_technique"])
        for row in sorted(excluded):
            writer.writerow(row)
    print(f"excluded: {len(excluded)} -> {EXCLUDED}")
    return 0


def pull(clone: Path, cache: Path, batch: int = 40) -> int:
    commit = str(load_pins()["corpora"]["attack_data"]["commit"])
    head = subprocess.run(
        ["git", "-C", str(clone), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if head != commit:
        print(f"clone is at {head}, pinned commit is {commit}", file=sys.stderr)
        return 1
    wanted = {
        line.strip()
        for kind in LISTS
        for line in LISTS[kind].read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    files: list[tuple[str, list[str]]] = [
        (yaml_path, paths)
        for yaml_path, _kind, paths, _size, _t in datasets(clone)
        if yaml_path in wanted
    ]
    flat = sorted({f for _yaml, paths in files for f in paths})
    env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "0"}
    for start in range(0, len(flat), batch):
        chunk = flat[start : start + batch]
        subprocess.run(
            ["git", "-C", str(clone), "lfs", "pull", "--include", ",".join(chunk), "--exclude", ""],
            check=True,
            env=env,
        )
        print(f"pulled {min(start + batch, len(flat))} of {len(flat)} files")

    # Every pulled file must have exactly the size its committed pointer names; a pull can
    # leave an empty or stale working-tree file without failing, so mismatches are pulled again.
    def mismatched() -> list[str]:
        expected = {f: pointer_size(clone, f) for f in flat}
        return [
            f
            for f, size in expected.items()
            if size is not None
            and (not (clone / f).is_file() or (clone / f).stat().st_size != size)
        ]

    wrong = mismatched()
    if wrong:
        print(f"{len(wrong)} files do not match their pointer size; pulling them once more")
        for start in range(0, len(wrong), batch):
            chunk = wrong[start : start + batch]
            subprocess.run(
                ["git", "-C", str(clone), "lfs", "pull", "--include", ",".join(chunk)], env=env
            )
        wrong = mismatched()
    # A file the pull still cannot write (on Windows, antivirus quarantines some attack
    # telemetry as malware) makes its whole dataset unavailable: it is recorded, dropped from
    # the dataset lists and from the cache, and never becomes a partial capture.
    unavailable = {yaml_path for yaml_path, paths in files if set(paths) & set(wrong)}
    root = cache / "attack_data" / commit
    with UNAVAILABLE.open("w", encoding="utf-8", newline="") as handle:
        handle.write(
            "# attack_data datasets selected for the bench whose LFS objects could not be "
            "written locally (B3). Reason as git lfs reported it.\n"
        )
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["yaml", "file", "reason"])
        for yaml_path, paths in sorted(files):
            for relative in paths:
                if relative in wrong:
                    writer.writerow([yaml_path, relative, "LFS object not written (blocked)"])
    for list_path in LISTS.values():
        kept = [
            line.strip()
            for line in list_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and line.strip() not in unavailable
        ]
        list_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    for yaml_path, paths in files:
        if yaml_path in unavailable:
            for relative in (yaml_path, *paths):
                (root / relative).unlink(missing_ok=True)
    files = [(y, p) for y, p in files if y not in unavailable]
    print(f"{len(unavailable)} datasets unavailable -> {UNAVAILABLE}")
    for yaml_path, paths in files:
        for relative in (yaml_path, *paths):
            source = clone / relative
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    print(f"copied {len(files)} datasets into {root}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    select_parser = sub.add_parser("select")
    select_parser.add_argument("--clone", type=Path, required=True)
    select_parser.add_argument("--cap-mb", type=float, default=5.0)
    pull_parser = sub.add_parser("pull")
    pull_parser.add_argument("--clone", type=Path, required=True)
    pull_parser.add_argument("--cache", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "select":
        return select(args.clone, args.cap_mb)
    return pull(args.clone, args.cache)


if __name__ == "__main__":
    sys.exit(main())
