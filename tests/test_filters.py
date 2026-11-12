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


# --- shipped filter: System Shutdown/Reboot - Linux, init branch (B4 lever b) -------------

SHUTDOWN_RULE = """title: System Shutdown/Reboot - Linux (detection as in SigmaHQ r2026-07-01)
id: 4cb57c2f-1f29-41f8-893d-8bed8e1c1d2f
status: test
logsource:
    product: linux
    service: auditd
detection:
    execve:
        type: 'EXECVE'
    shutdowncmd:
        - 'shutdown'
        - 'reboot'
        - 'halt'
        - 'poweroff'
    init:
        - 'init'
        - 'telinit'
    initselection:
        - 0
        - 6
    condition: execve and (shutdowncmd or (init and initselection))
level: informational
tags:
    - attack.t1529
"""


def _audit_event(serial: int, comm: str, args: list[str]) -> str:
    argv = " ".join(f'a{i}="{arg}"' for i, arg in enumerate(args))
    stamp = f"msg=audit(1731340000.{serial:03d}:{serial})"
    return (
        f"type=SYSCALL {stamp}: arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid={serial} "
        f'auid=1000 uid=0 comm="{comm}" exe="/usr/bin/{comm}" key=(null)\n'
        f"type=EXECVE {stamp}: argc={len(args)} {argv}\n"
    )


def test_shipped_shutdown_filter_keeps_real_commands_and_drops_stray_init(
    tmp_path: Path,
) -> None:
    from bastion.ingest.auditd import AuditdSource

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "shutdown.yml").write_text(SHUTDOWN_RULE, encoding="utf-8")
    rules = load_rules(rules_dir)
    log = tmp_path / "audit.log"
    log.write_text(
        _audit_event(101, "sh", ["sh", "-c", "echo initialised 0"])  # stray init and 0
        + _audit_event(102, "logger", ["logger", "init done 6"])  # stray init and 6
        + _audit_event(103, "init", ["init", "0"])  # the init branch as intended
        + _audit_event(104, "telinit", ["/sbin/telinit", "6"])
        + _audit_event(105, "shutdown", ["shutdown", "-P", "now"])  # shutdowncmd branch
        + _audit_event(106, "systemctl", ["systemctl", "reboot"]),
        encoding="utf-8",
    )
    events = list(AuditdSource().parse(log))
    shipped = load_filters(Path(__file__).parent.parent / "filters")
    unfiltered = scan(events, rules, ATTACK, [])
    filtered = scan(events, rules, ATTACK, shipped)
    assert len(unfiltered.detections) == 6
    kept = sorted(str(d.event.fields.get("a0")) for d in filtered.detections)
    assert kept == ["/sbin/telinit", "init", "shutdown", "systemctl"]
    assert filtered.filtered == {"4cb57c2f-1f29-41f8-893d-8bed8e1c1d2f": 2}
    assert filtered.filter_errors == {}
