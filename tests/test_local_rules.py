"""Tests for the hand-written rule pack shipped under rules/."""

from __future__ import annotations

from pathlib import Path

import pytest

from bastion.models import Event, FieldValue
from bastion.sigma.correlation import load_correlations
from bastion.sigma.loader import load_rules
from bastion.sigma.matcher import match

LOCAL_RULES_DIR = Path(__file__).parent.parent / "rules"
LOCAL_RULES = load_rules(LOCAL_RULES_DIR)


def make_event(platform: str, **fields: FieldValue) -> Event:
    return Event(
        platform=platform,  # type: ignore[arg-type]
        source="test",
        fields=dict(fields),
        raw=" ".join(str(v) for v in fields.values() if v is not None),
    )


def test_every_rule_file_loads() -> None:
    """Single-event rules load as rules; correlation files load through the correlation loader."""
    rule_files = list(LOCAL_RULES_DIR.rglob("*.yml"))
    correlations = load_correlations(LOCAL_RULES_DIR)
    assert not correlations.errors and not correlations.unsupported
    assert len(LOCAL_RULES) + len(correlations.rules) == len(rule_files)
    assert len(LOCAL_RULES) >= 8


def test_every_rule_has_required_metadata() -> None:
    for rule in LOCAL_RULES:
        assert rule.attack_techniques, f"{rule.title} has no technique tag"
        assert rule.attack_tactics, f"{rule.title} has no tactic tag"
        assert rule.logsource.get("product") in ("linux", "windows"), rule.title
        assert rule.description, f"{rule.title} has no description"


def test_every_rule_is_evaluable() -> None:
    """No rule in our own pack may use grammar the matcher cannot evaluate."""
    linux_event = make_event("linux", process="sudo", message="benign activity")
    windows_event = make_event("windows", EventID=1, Image="C:\\x.exe", CommandLine="benign")
    for rule in LOCAL_RULES:
        event = windows_event if rule.logsource.get("product") == "windows" else linux_event
        match(rule, event)  # raises UnsupportedRuleError on grammar problems


@pytest.mark.parametrize(
    ("title", "message"),
    [
        (
            "Shadow File Read Attempt",
            "  alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        ),
        (
            "Systemd Timer Unit Creation Or Activation",
            "  bob : USER=root ; COMMAND=/usr/bin/systemctl enable evil-backup.timer",
        ),
        (
            "SSH Authorized Keys File Modification",
            "shell command executed by alice: echo ssh-rsa AAAA... >> /root/.ssh/authorized_keys",
        ),
        (
            "PAM Configuration Modification",
            "shell command executed by alice: sed -i 's/sufficient/required/' /etc/pam.d/sshd",
        ),
        (
            "Crypto Miner Indicators In Logs",
            "shell command executed by alice: ./xmrig -o stratum+tcp://pool.example:3333",
        ),
        (
            "Host Log Enumeration",
            "shell command executed by alice: utmpdump /var/log/wtmp",
        ),
    ],
)
def test_linux_rules_fire_on_attack_traces(title: str, message: str) -> None:
    rules = {rule.title: rule for rule in LOCAL_RULES}
    event = make_event("linux", process="sudo", message=message)
    result = match(rules[title], event)
    assert result.matched, f"{title} did not fire on: {message}"
    assert result.matched_fields


def test_linux_rules_stay_quiet_on_benign_lines() -> None:
    benign = make_event(
        "linux",
        process="sshd",
        message="Accepted password for alice from 10.0.0.5 port 51022 ssh2",
    )
    for rule in LOCAL_RULES:
        if rule.logsource.get("product") == "linux":
            assert not match(rule, benign).matched, f"{rule.title} fired on a benign login"


@pytest.mark.parametrize(
    ("title", "image", "command_line"),
    [
        (
            "Wi-Fi Profile Enumeration Via Netsh",
            "C:\\Windows\\System32\\netsh.exe",
            "netsh wlan show profile name=corp key=clear",
        ),
        (
            "System Language And Location Discovery",
            "C:\\Windows\\System32\\reg.exe",
            "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language",
        ),
        (
            "System Language And Location Discovery",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell -c Get-WinHomeLocation",
        ),
    ],
)
def test_windows_rules_fire_on_attack_traces(title: str, image: str, command_line: str) -> None:
    rules = {rule.title: rule for rule in LOCAL_RULES}
    event = make_event("windows", EventID=1, Image=image, CommandLine=command_line)
    assert match(rules[title], event).matched


def test_windows_rules_stay_quiet_on_benign_process() -> None:
    benign = make_event(
        "windows",
        EventID=1,
        Image="C:\\Windows\\System32\\notepad.exe",
        CommandLine="notepad.exe C:\\notes.txt",
    )
    for rule in LOCAL_RULES:
        if rule.logsource.get("product") == "windows":
            assert not match(rule, benign).matched, f"{rule.title} fired on notepad"
