"""Tests for Sigma filter documents: loading, scoping, suppression, and fail-open."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bastion.attack import load_attack
from bastion.cli import app
from bastion.engine import scan
from bastion.models import Event
from bastion.sigma.filters import SigmaFilter, load_filters
from bastion.sigma.loader import load_rules

FIXTURES = Path(__file__).parent / "fixtures"
ATTACK = load_attack(FIXTURES / "mini_attack.json")
RULES = load_rules(FIXTURES / "rules")
SSH_RULE_ID = "22222222-2222-4222-8222-222222222222"
PS_RULE_ID = "11111111-1111-4111-8111-111111111111"

SSH_EVENT = Event(
    platform="linux",
    source="auth.log",
    fields={
        "process": "sshd",
        "message": "Failed password for invalid user admin",
        "host": "web01",
    },
    raw="Jun 10 06:13:44 web01 sshd[498]: Failed password for invalid user admin",
)
PS_EVENT = Event(
    platform="windows",
    source="x.evtx",
    fields={
        "EventID": 1,
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -enc SQBFAFgA",
        "User": "adm_alice",
    },
    raw="<Event/>",
)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    directory = tmp_path / "filters"
    directory.mkdir(exist_ok=True)
    (directory / name).write_text(text, encoding="utf-8")
    return directory


SSH_FILTER = f"""title: Ignore the scanner host
id: aaaaaaaa-0000-4000-8000-000000000001
justification: web01 is the authorized scanner; measured on the 2026 replay.
logsource:
    product: linux
    service: auth
filter:
    rules:
        - {SSH_RULE_ID}
    selection:
        host: web01
    condition: selection
"""


def test_load_filters_parses_documents_and_skips_others(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    directory = _write(tmp_path, "ssh.yml", SSH_FILTER)
    (directory / "rule.yml").write_text("title: A Rule\ndetection:\n  s: {a: 1}\n  condition: s\n")
    (directory / "norules.yml").write_text(
        "title: X\nfilter:\n  selection: {a: 1}\n  condition: selection\n"
    )
    (directory / "broken.yml").write_text("filter: [unclosed\n")
    with caplog.at_level(logging.WARNING):
        filters = load_filters(directory)
    assert [f.id for f in filters] == ["aaaaaaaa-0000-4000-8000-000000000001"]
    sigma_filter = filters[0]
    assert sigma_filter.rule_ids == (SSH_RULE_ID,)
    assert sigma_filter.logsource == {"product": "linux", "service": "auth"}
    assert sigma_filter.detection == {"selection": {"host": "web01"}, "condition": "selection"}
    assert "authorized scanner" in sigma_filter.justification
    assert sigma_filter.as_rule().detection["condition"] == "selection"
    messages = " ".join(r.message for r in caplog.records)
    assert "without a filter block" in messages and "without rules or condition" in messages
    assert "unparseable" in messages
    assert load_filters(tmp_path / "missing") == []


def test_filter_scope_by_product_category_and_service() -> None:
    sigma_filter = SigmaFilter(
        "f", "f", (SSH_RULE_ID,), {"product": "linux", "service": "auth"}, {"condition": "s"}
    )
    ssh_rule = next(r for r in RULES if r.id == SSH_RULE_ID)
    ps_rule = next(r for r in RULES if r.id == PS_RULE_ID)
    assert sigma_filter.applies_to_source(SSH_EVENT, ssh_rule)
    assert not sigma_filter.applies_to_source(PS_EVENT, ps_rule)  # product differs
    other_service = SigmaFilter("g", "g", (SSH_RULE_ID,), {"service": "sshd"}, {"condition": "s"})
    assert not other_service.applies_to_source(SSH_EVENT, ssh_rule)  # service differs
    unscoped = SigmaFilter("h", "h", (SSH_RULE_ID,), {}, {"condition": "s"})
    assert unscoped.applies_to_source(SSH_EVENT, ssh_rule)


def test_matching_filter_suppresses_and_is_counted(tmp_path: Path) -> None:
    filters = load_filters(_write(tmp_path, "ssh.yml", SSH_FILTER))
    outcome = scan([SSH_EVENT, PS_EVENT], RULES, ATTACK, filters)
    assert [d.rule_id for d in outcome.detections] == [PS_RULE_ID]
    assert outcome.filtered == {SSH_RULE_ID: 1}
    assert outcome.filter_hits == {"aaaaaaaa-0000-4000-8000-000000000001": 1}
    assert outcome.filter_errors == {}


def test_non_matching_filter_keeps_the_detection(tmp_path: Path) -> None:
    filters = load_filters(
        _write(tmp_path, "ssh.yml", SSH_FILTER.replace("host: web01", "host: other"))
    )
    outcome = scan([SSH_EVENT], RULES, ATTACK, filters)
    assert [d.rule_id for d in outcome.detections] == [SSH_RULE_ID]
    assert outcome.filtered == {}


def test_broken_filter_fails_open(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    broken = SSH_FILTER.replace("host: web01", "host|fieldref: other")
    filters = load_filters(_write(tmp_path, "ssh.yml", broken))
    with caplog.at_level(logging.WARNING):
        outcome = scan([SSH_EVENT, SSH_EVENT], RULES, ATTACK, filters)
    assert len(outcome.detections) == 2
    assert "aaaaaaaa-0000-4000-8000-000000000001" in outcome.filter_errors
    assert outcome.filtered == {}
    assert any("failed" in r.message for r in caplog.records)


def test_cli_applies_filters_dir_and_discloses_suppression(tmp_path: Path) -> None:
    directory = _write(tmp_path, "ssh.yml", SSH_FILTER)
    runner = CliRunner()
    flags = [
        "--rules-dir",
        str(FIXTURES / "rules"),
        "--attack-file",
        str(FIXTURES / "mini_attack.json"),
    ]
    result = runner.invoke(
        app, ["scan", str(FIXTURES / "auth_sample.log"), *flags, "--filters-dir", str(directory)]
    )
    assert result.exit_code == 0, result.output
    text = " ".join(result.output.split())
    assert "suppressed by 1 filter document" in text
    assert "No detections" in text or "SSH Failed Login" not in text
    result = runner.invoke(
        app,
        [
            "report",
            str(FIXTURES / "auth_sample.log"),
            *flags,
            "--filters-dir",
            str(directory),
            "-o",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 0, result.output
    written = (tmp_path / "out" / "result.json").read_text(encoding="utf-8")
    assert '"filtered_detections"' in written and SSH_RULE_ID in written
    assert "aaaaaaaa-0000-4000-8000-000000000001" in written
