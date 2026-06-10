"""Tests for the Typer CLI skeleton."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from bastion import __version__
from bastion.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"
AUTH_LOG = FIXTURES / "auth_sample.log"
MINI_ATTACK = FIXTURES / "mini_attack.json"
DATA_FLAGS = [
    "--rules-dir",
    str(FIXTURES / "rules"),
    "--attack-file",
    str(MINI_ATTACK),
]


def test_help_lists_all_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("fetch", "scan", "coverage", "report", "rules"):
        assert command in result.output


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_scan_detects_ssh_brute_force_in_fixture_log() -> None:
    result = runner.invoke(app, ["scan", str(AUTH_LOG), *DATA_FLAGS])
    assert result.exit_code == 0
    assert "SSH Failed Login" in result.output
    assert "T1110" in result.output
    assert "7 events" in result.output


def test_scan_accepts_platform_override() -> None:
    result = runner.invoke(app, ["scan", str(AUTH_LOG), "--platform", "linux", *DATA_FLAGS])
    assert result.exit_code == 0


def test_scan_clean_log_reports_no_detections(tmp_path: Path) -> None:
    clean = tmp_path / "clean.log"
    clean.write_text(
        "Jun 10 06:12:01 web01 systemd-logind: New session 1 of user bob.\n", encoding="utf-8"
    )
    result = runner.invoke(app, ["scan", str(clean), *DATA_FLAGS])
    assert result.exit_code == 0
    assert "No detections" in result.output


def test_scan_missing_file_exits_nonzero() -> None:
    result = runner.invoke(app, ["scan", "no-such-file.log", *DATA_FLAGS])
    assert result.exit_code != 0


def test_scan_without_fetched_data_exits_nonzero(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(AUTH_LOG), "--rules-dir", str(tmp_path / "missing")]
    )
    assert result.exit_code == 1
    assert "bastion fetch" in result.output


def test_coverage_reports_covered_and_blind_spots() -> None:
    result = runner.invoke(app, ["coverage", *DATA_FLAGS])
    assert result.exit_code == 0
    assert "2" in result.output and "3" in result.output
    assert "no detection rule" in result.output


def test_coverage_full_lists_uncovered_technique() -> None:
    result = runner.invoke(app, ["coverage", "--full", *DATA_FLAGS])
    assert result.exit_code == 0
    assert "T1059" in result.output
    assert "Command and Scripting Interpreter" in result.output


def test_report_writes_artifacts(tmp_path: Path) -> None:
    outdir = tmp_path / "out"
    result = runner.invoke(app, ["report", str(AUTH_LOG), "-o", str(outdir), *DATA_FLAGS])
    assert result.exit_code == 0
    assert (outdir / "report.md").exists()
    assert (outdir / "result.json").exists()
    assert (outdir / "dashboard.html").exists()
    markdown = (outdir / "report.md").read_text(encoding="utf-8")
    assert "SSH Failed Login For Invalid User" in markdown


def test_fetch_reports_cached_datasets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bundle = tmp_path / "enterprise-attack.json"
    bundle.write_text('{"type": "bundle", "objects": []}', encoding="utf-8")
    rules_dir = tmp_path / "rules"
    (rules_dir / "windows").mkdir(parents=True)
    (rules_dir / "windows" / "rule.yml").write_text("title: x\n", encoding="utf-8")

    def fake_fetch_attack(data_dir: Path, force: bool) -> Path:
        assert force is True
        return bundle

    def fake_fetch_sigma(data_dir: Path, force: bool) -> Path:
        return rules_dir

    monkeypatch.setattr("bastion.cli.fetch_attack", fake_fetch_attack)
    monkeypatch.setattr("bastion.cli.fetch_sigma", fake_fetch_sigma)
    result = runner.invoke(app, ["fetch", "--force", "--data-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "ATT&CK" in result.output
    assert "Sigma" in result.output


def test_fetch_failure_exits_nonzero(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def failing_fetch(data_dir: Path, force: bool) -> Path:
        raise ValueError("downloaded file is not valid JSON")

    monkeypatch.setattr("bastion.cli.fetch_attack", failing_fetch)
    result = runner.invoke(app, ["fetch", "--data-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "Fetch failed" in result.output


RULES_DIR = Path(__file__).parent / "fixtures" / "rules"


def test_rules_list_shows_loaded_rules() -> None:
    result = runner.invoke(app, ["rules", "list", "--rules-dir", str(RULES_DIR)])
    assert result.exit_code == 0
    assert "2" in result.output
    assert "T1059.001" in result.output


def test_rules_list_platform_filter() -> None:
    result = runner.invoke(
        app, ["rules", "list", "--rules-dir", str(RULES_DIR), "--platform", "linux"]
    )
    assert result.exit_code == 0
    assert "SSH Failed Login" in result.output
    assert "PowerShell" not in result.output


def test_rules_list_without_fetched_rules_exits_nonzero(tmp_path: Path) -> None:
    result = runner.invoke(app, ["rules", "list", "--rules-dir", str(tmp_path / "none")])
    assert result.exit_code == 1
    assert "bastion fetch" in result.output
