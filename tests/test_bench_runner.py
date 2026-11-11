"""End-to-end tests for the bench runner and report over the fake corpus world."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from bastion.bench.captures import Capture
from bastion.bench.manifest import read_manifest
from bastion.bench.report import render_report
from bastion.bench.runner import (
    BenchConfig,
    bastion_commit,
    collect_captures,
    evaluate_capture,
    evaluation_source_hash,
    generate_manifest,
    load_attack,
    load_bench_toml,
    load_ruleset,
    resolve_manifest,
    run_bench,
)
from bastion.models import Event
from bench_world import WINDOWS_RULE_ID, World, build_world


@pytest.fixture
def world(tmp_path: Path) -> World:
    return build_world(tmp_path)


def _config(world: World, **overrides: object) -> BenchConfig:
    base: dict[str, object] = {
        "cache": world.cache,
        "repo_root": world.repo_root,
        "rules_dir": world.rules_dir,
        "attack_file": world.attack_file,
        "citadel_dir": world.citadel_dir,
        "seed": 1,
        "run_name": "test-run",
    }
    base.update(overrides)
    return BenchConfig(**base)  # type: ignore[arg-type]


def test_collect_captures_covers_every_corpus(world: World) -> None:
    config = _config(world)
    attack = load_attack(config)
    ruleset = load_ruleset(config)
    assert len(ruleset.rules) == 2 and ruleset.hunting_ids == set()
    collected = collect_captures(config, attack, ruleset)
    by_corpus: dict[str, int] = {}
    for capture in collected.captures:
        by_corpus[capture.corpus] = by_corpus.get(capture.corpus, 0) + 1
    assert by_corpus == {
        "regression_data": 2,
        "evtx_attack_samples": 3,
        "attack_data": 2,
        "citadel_captures": 2,
        "evtx_baseline": 2,
        "fixtures": 1,
    }
    assert collected.known_fps == {WINDOWS_RULE_ID: [".*"]}
    assert collected.regression_skipped == {
        "JSON sample needs a pySigma field-mapping pipeline (B3)": 1,
        "rule not in the loaded ruleset (rules-threat-hunting)": 1,
    }
    # The world builds only the first pinned Citadel capture; the others are noted, not fatal.
    assert collected.notes and all("no capture.json" in note for note in collected.notes)


def test_collect_notes_missing_corpora(tmp_path: Path, world: World) -> None:
    config = _config(world, cache=tmp_path / "empty-cache", citadel_dir=tmp_path / "no-citadel")
    collected = collect_captures(config, load_attack(config), load_ruleset(config))
    assert {c.corpus for c in collected.captures} == {"fixtures"}
    assert len(collected.notes) == 5


def test_run_bench_writes_summary_report_and_resumes(world: World) -> None:
    config = _config(world)
    messages: list[str] = []
    summary, run_dir = run_bench(config, progress=messages.append)
    assert run_dir == world.repo_root / "bench" / "results" / "test-run"
    assert (run_dir / "summary.json").is_file() and (run_dir / "report.md").is_file()
    assert (world.repo_root / "bench" / "results" / "LATEST").read_text().strip() == "test-run"
    assert summary["bastion"]["evaluation_source_hash"] == evaluation_source_hash()
    assert summary["rules"]["loaded"] == 2
    assert summary["captures"]["by_kind"] == {
        "regression": 2,
        "positive": 6,
        "benign": 3,
        "fixture": 1,
    }
    # The fixture auth log fires the SSH rule: T1110 is at least fixture-proven.
    assert summary["ladder"]["per_technique"]["T1110"] in {
        "fixture-proven",
        "held-out-proven",
        "sample-proven",
    }
    reg = summary["regression"]
    assert reg["pass_rate"]["numerator"] == 1 and reg["pass_rate"]["denominator"] == 2
    assert reg["failures"][0]["expected"] == 1 and reg["failures"][0]["actual"] == 0
    assert summary["benign"]["evtx_baseline"]["hosts"] == 1
    assert summary["benign"]["citadel_background"]["hosts"] == 1
    assert summary["captures"]["unlabelled_positive"] == 1
    assert any("no manifest" in note for note in summary["notes"])
    assert messages and messages[0].startswith("2 rules")
    lines_before = (run_dir / "outcomes.jsonl").read_text(encoding="utf-8").count("\n")
    # A second run reuses every outcome instead of re-evaluating.
    again, _ = run_bench(_config(world))
    assert (run_dir / "outcomes.jsonl").read_text(encoding="utf-8").count("\n") == lines_before
    assert again["captures"]["total"] == summary["captures"]["total"]
    # Without resume the file grows by one full set.
    run_bench(_config(world, resume=False))
    assert (run_dir / "outcomes.jsonl").read_text(encoding="utf-8").count("\n") == 2 * lines_before
    report = render_report(summary)
    for heading in (
        "## Rules",
        "## Coverage",
        "## Detection on labelled captures, test split",
        "## SigmaHQ regression suite",
        "## Benign replay",
        "## Evidence ladder",
        "## Captures",
    ):
        assert heading in report
    assert "Wilson 95% interval" in report
    # Split integrity: the frozen B1 set and the expanded test split side by side, per corpus.
    frozen = summary["rates"]["test_frozen_b1"]
    assert frozen["captures"] == summary["rates"]["test"]["captures"]  # no later cohort here
    assert len(frozen["capture_ids_sha256"]) == 64
    assert set(summary["rates_by_corpus"]) == {"test", "dev"}
    assert "## Headline sets side by side (held out)" in report
    assert "### Per corpus, test split" in report


def test_run_bench_honours_split_and_suite_selection(world: World) -> None:
    summary, run_dir = run_bench(
        _config(world, splits=("test",), suites=("positives",), run_name="only-test")
    )
    kinds = summary["captures"]["by_kind"]
    assert "regression" not in kinds and "fixture" not in kinds
    # A run without the benign suite must not claim LATEST (the budget gate reads it).
    assert not (world.repo_root / "bench" / "results" / "LATEST").exists()
    detail = [
        json.loads(line)
        for line in (run_dir / summary["captures"]["detail_file"]).read_text().splitlines()
    ]
    # The positives suite carries Citadel's own-lab background as its only benign captures.
    assert all(d["corpus"] == "citadel_captures" for d in detail if d["kind"] == "benign")
    assert all(d["split"] in {"test", "unlabelled"} for d in detail if d["kind"] == "positive")


def test_generate_and_resolve_manifest(world: World) -> None:
    config = _config(world)
    path = generate_manifest(config)
    manifest = read_manifest(path)
    assert manifest.seed == 1
    splits = {e.split for e in manifest.entries.values()}
    assert {"test", "unlabelled", ""} <= splits
    citadel_entries = [
        e
        for e in manifest.entries.values()
        if e.corpus == "citadel_captures" and e.kind == "positive"
    ]
    assert citadel_entries and all(e.split == "dev" for e in citadel_entries)
    attack = load_attack(config)
    ruleset = load_ruleset(config)
    collected = collect_captures(config, attack, ruleset)
    extra = Capture(
        "new/one", "evtx_attack_samples", "positive", "windows", "evtx", (), techniques=("T1110",)
    )
    resolved, notes = resolve_manifest(config, [*collected.captures, extra])
    assert resolved.split_of("new/one") in {"test", "dev"}
    assert notes and "not in manifest.toml" in notes[0]
    # With the manifest present the run reports no assignment note.
    summary, _ = run_bench(config)
    assert not any("no manifest" in note for note in summary["notes"])


def test_evaluate_capture_caps_events_and_records_failures(world: World) -> None:
    config = _config(world)
    attack = load_attack(config)
    ruleset = load_ruleset(config)
    events = [Event(platform="linux", source="s", fields={}, raw=f"line {i}") for i in range(5)]
    capture = Capture(
        "x",
        "c",
        "positive",
        "linux",
        "syslog",
        (),
        techniques=("T1110",),
        events_override=lambda: iter(events),
    )
    outcome = evaluate_capture(
        capture, ruleset.for_platform("linux"), attack, set(), "test", limit=3
    )
    assert outcome.events_scanned == 3 and outcome.notes["event_cap"] == "stopped after 3 events"
    assert outcome.first_ts is None

    def explode():  # type: ignore[no-untyped-def]
        raise OSError("disk gone")
        yield  # pragma: no cover

    broken = Capture(
        "b", "c", "positive", "linux", "syslog", (), techniques=("T1110",), events_override=explode
    )
    summary, _ = run_bench(_config(world, suites=("fixtures",), run_name="broken"))
    assert summary["captures"]["skipped"] == []
    # The runner's exception path is exercised through a capture that raises on parse.
    from bastion.bench import runner as runner_mod

    original = runner_mod.collect_captures

    def with_broken(*args, **kwargs):  # type: ignore[no-untyped-def]
        collected = original(*args, **kwargs)
        collected.captures.append(broken)
        return collected

    runner_mod.collect_captures = with_broken
    try:
        summary, _ = run_bench(_config(world, suites=("fixtures",), run_name="broken2"))
    finally:
        runner_mod.collect_captures = original
    assert summary["captures"]["skipped"] == [{"id": "b", "reason": "OSError: disk gone"}]


def test_bench_toml_and_commit_fallbacks(tmp_path: Path, world: World) -> None:
    assert load_bench_toml(tmp_path) == {}
    assert load_bench_toml(world.repo_root)["budget"]["alerts_per_host_day"] == 20.0
    assert isinstance(bastion_commit(Path(__file__).resolve().parents[1]), str)


def test_report_states_when_no_benign_captures_were_scanned(world: World) -> None:
    summary, _ = run_bench(_config(world, suites=("fixtures",), run_name="fx-only"))
    text = render_report(summary)
    assert "No captures scanned." in text
    trimmed = copy.deepcopy(summary)
    trimmed["rules"]["not_evaluable_by_reason"] = {"modifier:fieldref": 1}
    trimmed["rules"]["not_evaluable_files"] = ["x.yml"]
    trimmed["rules"]["local_rules_hunting"] = ["a"]
    trimmed["event_cap_per_capture"] = 5
    text = render_report(trimmed)
    assert (
        "modifier:fieldref 1" in text and "hunting class by status" in text and "Event cap" in text
    )
    assert json.dumps(summary)  # the summary is plain JSON throughout
