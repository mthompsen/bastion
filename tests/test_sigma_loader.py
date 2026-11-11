"""Tests for Sigma rule loading from a fixture rules tree."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from bastion.sigma.loader import load_rules

RULES_DIR = Path(__file__).parent / "fixtures" / "rules"


def test_loads_valid_rules_and_skips_broken_files(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        rules = load_rules(RULES_DIR)
    assert sorted(rule.title for rule in rules) == [
        "SSH Failed Login For Invalid User",
        "Suspicious Encoded PowerShell Command",
    ]
    warnings = [record.message for record in caplog.records]
    assert any("unparseable" in message for message in warnings)
    assert any("without a detection block" in message for message in warnings)


def test_rule_fields_are_extracted() -> None:
    rules = {rule.title: rule for rule in load_rules(RULES_DIR)}
    ps = rules["Suspicious Encoded PowerShell Command"]
    assert ps.id == "11111111-1111-4111-8111-111111111111"
    assert ps.level == "high"
    assert ps.status == "test"
    assert ps.logsource == {"product": "windows", "category": "process_creation"}
    assert "selection_img" in ps.detection
    assert ps.detection["condition"] == "selection_img and selection_cli and not filter_legit"
    assert ps.file_path.endswith("win_powershell_encoded.yml")


def test_attack_tags_are_parsed_and_normalized() -> None:
    rules = {rule.title: rule for rule in load_rules(RULES_DIR)}
    ps = rules["Suspicious Encoded PowerShell Command"]
    assert ps.attack_techniques == ["T1059.001"]
    # attack.defense_evasion (underscore form) is normalized to hyphens.
    assert ps.attack_tactics == ["execution", "defense-evasion"]
    ssh = rules["SSH Failed Login For Invalid User"]
    assert ssh.attack_techniques == ["T1110"]
    assert ssh.attack_tactics == ["credential-access"]


def test_platform_filter_skips_other_platforms() -> None:
    windows_rules = load_rules(RULES_DIR, platform="windows")
    assert [rule.title for rule in windows_rules] == ["Suspicious Encoded PowerShell Command"]
    linux_rules = load_rules(RULES_DIR, platform="linux")
    assert [rule.title for rule in linux_rules] == ["SSH Failed Login For Invalid User"]


def test_rule_without_product_is_kept_for_any_platform(tmp_path: Path) -> None:
    (tmp_path / "generic.yml").write_text(
        "title: Generic Webserver Rule\n"
        "logsource:\n    category: webserver\n"
        "detection:\n    keywords:\n        - 'etc/passwd'\n    condition: keywords\n",
        encoding="utf-8",
    )
    assert len(load_rules(tmp_path, platform="windows")) == 1
    assert len(load_rules(tmp_path, platform="linux")) == 1


def test_unknown_level_falls_back_to_medium(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    (tmp_path / "weird_level.yml").write_text(
        "title: Weird Level\nlevel: catastrophic\n"
        "detection:\n    s:\n        EventID: 1\n    condition: s\n",
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        rules = load_rules(tmp_path)
    assert rules[0].level == "medium"
    assert any("unknown level" in record.message for record in caplog.records)


def test_missing_id_falls_back_to_file_stem(tmp_path: Path) -> None:
    (tmp_path / "no_id.yml").write_text(
        "title: No Id Rule\ndetection:\n    s:\n        EventID: 1\n    condition: s\n",
        encoding="utf-8",
    )
    assert load_rules(tmp_path)[0].id == "no_id"


def test_missing_status_is_empty_and_status_is_lowercased(tmp_path: Path) -> None:
    (tmp_path / "no_status.yml").write_text(
        "title: No Status\ndetection:\n    s:\n        EventID: 1\n    condition: s\n",
        encoding="utf-8",
    )
    (tmp_path / "upper_status.yml").write_text(
        "title: Upper Status\nstatus: Experimental\n"
        "detection:\n    s:\n        EventID: 1\n    condition: s\n",
        encoding="utf-8",
    )
    by_title = {rule.title: rule for rule in load_rules(tmp_path)}
    assert by_title["No Status"].status == ""
    assert by_title["Upper Status"].status == "experimental"


def test_v19_tactic_tags_are_kept(tmp_path: Path) -> None:
    (tmp_path / "r.yml").write_text(
        "title: t\nid: 1\nlogsource: {product: windows}\n"
        "detection: {s: {a: 1}, condition: s}\n"
        "tags: [attack.stealth, attack.defense_impairment, attack.t1685]\n",
        encoding="utf-8",
    )
    [rule] = load_rules(tmp_path)
    assert rule.attack_tactics == ["stealth", "defense-impairment"]
    assert rule.attack_techniques == ["T1685"]
