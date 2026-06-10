"""Tests for the Typer CLI skeleton."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from bastion import __version__
from bastion.cli import app

runner = CliRunner()
AUTH_LOG = Path(__file__).parent / "fixtures" / "auth_sample.log"


def test_help_lists_all_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("fetch", "scan", "coverage", "report", "rules"):
        assert command in result.output


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_scan_parses_fixture_log() -> None:
    result = runner.invoke(app, ["scan", str(AUTH_LOG)])
    assert result.exit_code == 0
    assert "7" in result.output  # 7 well-formed events in the fixture


def test_scan_accepts_platform_override() -> None:
    result = runner.invoke(app, ["scan", str(AUTH_LOG), "--platform", "linux"])
    assert result.exit_code == 0


def test_scan_missing_file_exits_nonzero() -> None:
    result = runner.invoke(app, ["scan", "no-such-file.log"])
    assert result.exit_code != 0


def test_unimplemented_commands_exit_nonzero() -> None:
    assert runner.invoke(app, ["fetch"]).exit_code == 2
    assert runner.invoke(app, ["coverage"]).exit_code == 2
    assert runner.invoke(app, ["report", str(AUTH_LOG)]).exit_code == 2
    assert runner.invoke(app, ["rules", "list"]).exit_code == 2
