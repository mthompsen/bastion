"""Tests for the manifest: stratified splits, hashing, TOML round trip."""

from __future__ import annotations

from pathlib import Path

from bastion.bench.captures import Capture
from bastion.bench.manifest import (
    Manifest,
    assign_splits,
    build_entries,
    read_manifest,
    render_manifest,
    write_manifest,
)


def _cap(
    cid: str, kind: str = "positive", techniques: tuple[str, ...] = ("T1059",), corpus: str = "c"
) -> Capture:
    return Capture(cid, corpus, kind, "windows", "evtx", (), techniques=techniques)  # type: ignore[arg-type]


def test_assign_splits_stratifies_and_alternates() -> None:
    captures = [_cap(f"a{i}", techniques=("T1059",)) for i in range(4)]
    captures += [_cap("single", techniques=("T1110",))]
    captures += [_cap("unl", techniques=())]
    captures += [_cap("benign", kind="benign", techniques=())]
    captures += [_cap("lab", corpus="citadel", techniques=("T1059",))]
    splits = assign_splits(captures, seed=7, forced={"citadel": "dev"})
    group = [splits[f"a{i}"] for i in range(4)]
    assert sorted(group) == ["dev", "dev", "test", "test"]
    assert splits["single"] == "test"  # a lone capture goes to the held-out split
    assert splits["unl"] == "unlabelled"
    assert splits["benign"] == ""
    assert splits["lab"] == "dev"
    # Deterministic for a fixed seed, and the seed matters.
    assert assign_splits(captures, seed=7, forced={"citadel": "dev"}) == splits
    assert any(assign_splits(captures, seed=s) != splits for s in range(1, 20))


def test_entries_and_toml_round_trip(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    (cache / "corp").mkdir(parents=True)
    file_a = cache / "corp" / "a.log"
    file_a.write_text("x", encoding="utf-8")
    outside = tmp_path / "elsewhere.log"
    outside.write_text("y", encoding="utf-8")
    captures = [
        Capture(
            "corp/a",
            "corp",
            "positive",
            "linux",
            "syslog",
            (file_a,),
            techniques=("T1110",),
            raw_labels=("T1110",),
            license='MIT "quoted" \\ back',
            host="h1",
            label_notes=("note",),
        ),
        Capture(
            "fx/out", "fixtures", "fixture", "linux", "syslog", (outside,), techniques=("T1003",)
        ),
    ]
    splits = assign_splits(captures, seed=3)
    entries = build_entries(captures, splits, cache)
    assert entries[0].paths == ["corp/a.log"]
    assert entries[1].paths[0].endswith("elsewhere.log")  # outside the cache: kept as given
    assert len(entries[0].sha256) == 64
    text = render_manifest(entries, 3, {"sigma": "r1"})
    assert "[[capture]]" in text and 'license = "MIT \\"quoted\\" \\\\ back"' in text
    path = tmp_path / "bench" / "manifest.toml"
    write_manifest(path, entries, 3, {"sigma": "r1"})
    manifest = read_manifest(path)
    assert manifest.seed == 3 and manifest.pins == {"sigma": "r1"}
    assert manifest.split_of("corp/a") == "test"
    assert manifest.split_of("fx/out") == ""
    assert manifest.split_of("missing") is None
    assert manifest.entries["corp/a"].label_notes == ["note"]
    assert manifest.entries["corp/a"].host == "h1"


def test_manifest_dataclass_defaults() -> None:
    manifest = Manifest(seed=1, pins={}, entries={})
    assert manifest.split_of("x") is None
