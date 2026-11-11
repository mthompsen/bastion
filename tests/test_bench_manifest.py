"""Tests for the manifest: stratified splits, hashing, TOML round trip."""

from __future__ import annotations

from pathlib import Path

from bastion.bench.captures import Capture
from bastion.bench.manifest import (
    Manifest,
    assign_splits,
    assign_splits_frozen,
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


def test_frozen_assignments_are_kept_and_new_captures_assigned() -> None:
    old = [_cap(f"a{i}") for i in range(4)] + [_cap("was_unlabelled", techniques=())]
    splits = assign_splits(old, seed=7)
    existing = Manifest(7, {}, {e.id: e for e in build_entries(old, splits, Path("."))})
    now = [_cap(f"a{i}") for i in range(4)]
    now += [_cap("was_unlabelled", techniques=("T1110",)), _cap("new", techniques=("T1110",))]
    now += [_cap("still_unlabelled", techniques=())]
    frozen, cohorts = assign_splits_frozen(now, existing)
    for i in range(4):
        assert frozen[f"a{i}"] == splits[f"a{i}"] and cohorts[f"a{i}"] == "b1"
    # The two newly labelled T1110 captures are stratified among themselves, seed 7.
    assert sorted([frozen["was_unlabelled"], frozen["new"]]) == ["dev", "test"]
    assert cohorts["was_unlabelled"] == cohorts["new"] == "b3"
    assert frozen["still_unlabelled"] == "unlabelled"
    assert frozen == assign_splits_frozen(now, existing)[0]  # deterministic
    entries = build_entries(now, frozen, Path("."), cohorts)
    manifest = Manifest(7, {}, {e.id: e for e in entries})
    assert manifest.frozen_test_ids() == {f"a{i}" for i in range(4) if splits[f"a{i}"] == "test"}


def test_cohort_round_trips_and_defaults_to_b1(tmp_path: Path) -> None:
    entries = build_entries([_cap("x")], {"x": "test"}, tmp_path, {"x": "b3"})
    path = tmp_path / "m.toml"
    write_manifest(path, entries, 7, {})
    assert read_manifest(path).entries["x"].cohort == "b3"
    path.write_text(path.read_text(encoding="utf-8").replace('cohort = "b3"\n', ""), "utf-8")
    assert read_manifest(path).entries["x"].cohort == "b1"
