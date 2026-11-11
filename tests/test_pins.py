"""Tests for the packaged pins."""

from __future__ import annotations

from bastion.pins import data_file_text, load_pins, pin_summary


def test_pins_carry_every_source() -> None:
    pins = load_pins()
    assert pins["sigma"]["tag"] == "r2026-04-01"
    assert pins["attack"]["version"] == "20.1"
    for corpus in (
        "regression_data",
        "evtx_attack_samples",
        "evtx_baseline",
        "attack_data",
        "citadel_captures",
    ):
        assert "license" in pins["corpora"][corpus], corpus


def test_pin_summary_is_flat_strings() -> None:
    summary = pin_summary()
    assert summary["sigma"] == "r2026-04-01" and summary["attack"] == "20.1"
    assert summary["corpus:evtx_baseline"] == "v0.8.5"
    assert all(isinstance(v, str) for v in summary.values())


def test_data_file_lists_attack_data_datasets() -> None:
    lines = data_file_text("attack_data_auditd_datasets.txt").splitlines()
    assert len(lines) == 66 and all(line.endswith(".yml") for line in lines)
