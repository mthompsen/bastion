"""The bench manifest: every capture, its corpus, hash, labels, and dev/test split.

The split is stratified by primary technique with a fixed seed: within each
technique, captures are shuffled and assigned test, dev, test, dev, ... so
every technique with two or more captures appears in both splits and a
technique with a single capture lands in the held-out split (the headline
needs evidence more than development does; the rule is stated here so it
is not re-decided per run). Corpora may force a split: Citadel's own-lab
captures are dev only. Benign, regression and fixture captures are their
own suites and carry no split. Unlabelled positive captures carry the
``unlabelled`` split and count in no rate.

The manifest is TOML written by a small emitter (strings, integers, string
arrays) and read back with the standard library, so no dependency is added.
It never holds absolute paths: paths are relative to the corpus cache root.
"""

from __future__ import annotations

import random
import re
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from bastion.bench.cache import sha256_files
from bastion.bench.captures import Capture

Split = str  # "test" | "dev" | "unlabelled" | "" (suites without a split)

#: The cohort of every capture the B1 manifest assigned. The B1 test split (130 labelled
#: captures) is frozen: later captures never change an existing dev or test assignment, and
#: the headline is reported on that frozen set beside the expanded test split.
FROZEN_COHORT = "b1"
#: The cohort recorded for captures first assigned by this version of the manifest.
CURRENT_COHORT = "b3"


@dataclass
class ManifestEntry:
    id: str
    corpus: str
    kind: str
    platform: str
    source_kind: str
    paths: list[str]
    sha256: str
    techniques: list[str]
    raw_labels: list[str]
    split: Split
    license: str
    host: str = ""
    label_notes: list[str] = field(default_factory=list)
    #: the milestone whose manifest first gave this capture its split (``b1`` is frozen)
    cohort: str = FROZEN_COHORT


def assign_splits(
    captures: Sequence[Capture], seed: int, forced: Mapping[str, Split] | None = None
) -> dict[str, Split]:
    """Stratified dev/test assignment for labelled positive captures."""
    forced = dict(forced or {})
    splits: dict[str, Split] = {}
    by_technique: dict[str, list[Capture]] = {}
    for capture in captures:
        if capture.kind != "positive":
            splits[capture.id] = ""
        elif capture.corpus in forced:
            splits[capture.id] = forced[capture.corpus]
        elif not capture.labelled:
            splits[capture.id] = "unlabelled"
        else:
            by_technique.setdefault(capture.techniques[0], []).append(capture)
    rng = random.Random(seed)
    for technique in sorted(by_technique):
        group = sorted(by_technique[technique], key=lambda c: c.id)
        rng.shuffle(group)
        for index, capture in enumerate(group):
            splits[capture.id] = "test" if index % 2 == 0 else "dev"
    return splits


def assign_splits_frozen(
    captures: Sequence[Capture],
    existing: Manifest,
    forced: Mapping[str, Split] | None = None,
    cohort: str = CURRENT_COHORT,
) -> tuple[dict[str, Split], dict[str, str]]:
    """Splits and cohorts for a regenerated manifest, keeping every existing assignment.

    A capture the existing manifest put in ``dev`` or ``test`` keeps that split and its
    cohort. Every other labelled positive capture (new, or unlabelled before and labelled
    now) is assigned by :func:`assign_splits` among those captures only, with the existing
    manifest's seed, and gets ``cohort``. Nothing here reads a rule outcome.
    """
    splits: dict[str, Split] = {}
    cohorts: dict[str, str] = {}
    fresh: list[Capture] = []
    for capture in captures:
        entry = existing.entries.get(capture.id)
        if entry is not None and entry.split in {"test", "dev"}:
            splits[capture.id] = entry.split
            cohorts[capture.id] = entry.cohort
        else:
            fresh.append(capture)
    for capture_id, split in assign_splits(fresh, existing.seed, forced).items():
        splits[capture_id] = split
        entry = existing.entries.get(capture_id)
        cohorts[capture_id] = (
            entry.cohort if entry is not None and split in {"", "unlabelled"} else cohort
        )
    return splits, cohorts


def build_entries(
    captures: Iterable[Capture],
    splits: Mapping[str, Split],
    cache_root: Path,
    cohorts: Mapping[str, str] | None = None,
) -> list[ManifestEntry]:
    entries: list[ManifestEntry] = []
    for capture in captures:
        relative = [_relative(p, cache_root) for p in capture.paths]
        entries.append(
            ManifestEntry(
                id=capture.id,
                corpus=capture.corpus,
                kind=capture.kind,
                platform=capture.platform,
                source_kind=capture.source_kind,
                paths=relative,
                sha256=sha256_files(capture.paths),
                techniques=list(capture.techniques),
                raw_labels=list(capture.raw_labels),
                split=splits.get(capture.id, ""),
                license=capture.license,
                host=capture.host,
                label_notes=list(capture.label_notes),
                cohort=(cohorts or {}).get(capture.id, FROZEN_COHORT),
            )
        )
    return sorted(entries, key=lambda e: e.id)


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()  # outside the cache (fixtures, Citadel): kept as given


_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")


def _toml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _toml_key(key: str) -> str:
    """Bare when TOML allows it, quoted otherwise (pins such as ``corpus:evtx_baseline``)."""
    return key if _BARE_KEY.match(key) else _toml_string(key)


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _toml_string(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    raise TypeError(f"unsupported manifest value: {type(value).__name__}")


def render_manifest(entries: Sequence[ManifestEntry], seed: int, pins: Mapping[str, str]) -> str:
    lines = [
        "# Bastion bench manifest. Generated by `bastion bench manifest`; do not edit by hand.",
        "# Paths are relative to the corpus cache root. Splits: test (held out), dev,",
        "# unlabelled (scanned, counted in no rate), empty (suite without a split).",
        "",
        f"seed = {seed}",
        "",
        "[pins]",
    ]
    lines.extend(f"{_toml_key(key)} = {_toml_string(value)}" for key, value in sorted(pins.items()))
    for entry in entries:
        lines.append("")
        lines.append("[[capture]]")
        for key, value in vars(entry).items():
            lines.append(f"{_toml_key(key)} = {_toml_value(value)}")
    return "\n".join(lines) + "\n"


def write_manifest(
    path: Path, entries: Sequence[ManifestEntry], seed: int, pins: Mapping[str, str]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_manifest(entries, seed, pins), encoding="utf-8")


@dataclass
class Manifest:
    seed: int
    pins: dict[str, str]
    entries: dict[str, ManifestEntry]

    def split_of(self, capture_id: str) -> Split | None:
        entry = self.entries.get(capture_id)
        return entry.split if entry else None

    def frozen_test_ids(self) -> set[str]:
        """The frozen held-out set: test captures of the frozen (B1) cohort."""
        return {
            e.id for e in self.entries.values() if e.split == "test" and e.cohort == FROZEN_COHORT
        }


def read_manifest(path: Path) -> Manifest:
    doc = tomllib.loads(path.read_text(encoding="utf-8"))
    entries = {
        str(raw["id"]): ManifestEntry(
            id=str(raw["id"]),
            corpus=str(raw["corpus"]),
            kind=str(raw["kind"]),
            platform=str(raw["platform"]),
            source_kind=str(raw["source_kind"]),
            paths=[str(p) for p in raw.get("paths", [])],
            sha256=str(raw.get("sha256", "")),
            techniques=[str(t) for t in raw.get("techniques", [])],
            raw_labels=[str(t) for t in raw.get("raw_labels", [])],
            split=str(raw.get("split", "")),
            license=str(raw.get("license", "")),
            host=str(raw.get("host", "")),
            label_notes=[str(n) for n in raw.get("label_notes", [])],
            cohort=str(raw.get("cohort", FROZEN_COHORT)),
        )
        for raw in doc.get("capture", [])
    }
    pins = {str(k): str(v) for k, v in dict(doc.get("pins", {})).items()}
    return Manifest(seed=int(doc.get("seed", 0)), pins=pins, entries=entries)
