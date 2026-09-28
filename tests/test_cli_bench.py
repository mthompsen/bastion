"""CLI tests for the bench sub-app, over the fake corpus world."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from bastion.bench.corpora import attack_data, evtx_baseline, evtx_samples, regression
from bastion.cli import app
from bench_world import World, build_world

runner = CliRunner()


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    built = build_world(tmp_path)
    monkeypatch.chdir(built.repo_root)
    return built


def _flags(world: World) -> list[str]:
    return [
        "--cache-dir",
        str(world.cache),
        "--rules-dir",
        str(world.rules_dir),
        "--attack-file",
        str(world.attack_file),
    ]


def test_bench_help_lists_commands() -> None:
    result = runner.invoke(app, ["bench", "--help"])
    assert result.exit_code == 0
    for command in ("fetch", "manifest", "run"):
        assert command in result.output


def test_bench_manifest_and_run(world: World) -> None:
    result = runner.invoke(
        app, ["bench", "manifest", *_flags(world), "--citadel-captures", str(world.citadel_dir)]
    )
    assert result.exit_code == 0, result.output
    assert (world.repo_root / "bench" / "manifest.toml").is_file()
    result = runner.invoke(
        app,
        [
            "bench",
            "run",
            *_flags(world),
            "--citadel-captures",
            str(world.citadel_dir),
            "--run-name",
            "cli-run",
            "--splits",
            "test,dev",
            "--max-events-per-capture",
            "50",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "regression_pass_rate" in result.output and "Evidence ladder" in result.output
    assert (world.repo_root / "bench" / "results" / "cli-run" / "summary.json").is_file()


def test_bench_run_requires_fetched_data(world: World, tmp_path: Path) -> None:
    result = runner.invoke(app, ["bench", "run", "--attack-file", str(tmp_path / "missing.json")])
    assert result.exit_code == 1
    assert "bastion fetch" in " ".join(result.output.split())


def test_bench_fetch_delegates_to_each_fetcher(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def record(label: str):  # type: ignore[no-untyped-def]
        def fetch(cache: Path, *args: object, force: bool = False) -> Path:
            calls.append(str(args[0]) if args else label)
            return cache

        return fetch

    monkeypatch.setattr(regression, "fetch_regression", record("regression"))
    monkeypatch.setattr(evtx_samples, "fetch_evtx_samples", record("samples"))
    monkeypatch.setattr(attack_data, "fetch_attack_data", record("attack_data"))
    monkeypatch.setattr(evtx_baseline, "fetch_baseline_set", record("baseline"))
    result = runner.invoke(
        app, ["bench", "fetch", "--cache-dir", str(world.cache), "--baseline-set", "win7-x86"]
    )
    assert result.exit_code == 0, result.output
    assert calls == ["regression", "samples", "attack_data", "win7-x86"]
    calls.clear()
    result = runner.invoke(
        app, ["bench", "fetch", "--cache-dir", str(world.cache), "--corpus", "regression"]
    )
    assert result.exit_code == 0 and calls == ["regression"]


def test_bench_fetch_reports_failures(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    def failing(cache: Path, force: bool = False) -> Path:
        raise ValueError("pinned size mismatch")

    monkeypatch.setattr(regression, "fetch_regression", failing)
    result = runner.invoke(
        app, ["bench", "fetch", "--cache-dir", str(world.cache), "--corpus", "regression"]
    )
    assert result.exit_code == 1
    assert "Fetch failed" in result.output
