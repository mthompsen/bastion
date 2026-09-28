"""CI gate: the committed baseline must show every local rule inside the benign replay budget.

Reads the run named in ``bench/results/LATEST``. A local rule that has never been through a
benign replay fails here, so adding a rule without re-running ``bastion bench run`` fails CI.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bastion.sigma.loader import load_rules

REPO = Path(__file__).resolve().parents[1]
RESULTS = REPO / "bench" / "results"


def _latest_summary() -> dict[str, object]:
    pointer = RESULTS / "LATEST"
    assert pointer.is_file(), (
        "no committed bench run: run `bastion bench run` and commit its summary"
    )
    run_dir = RESULTS / pointer.read_text(encoding="utf-8").strip()
    summary_path = run_dir / "summary.json"
    assert summary_path.is_file(), f"{summary_path} is missing"
    data: dict[str, object] = json.loads(summary_path.read_text(encoding="utf-8"))
    return data


@pytest.fixture(scope="module")
def summary() -> dict[str, object]:
    return _latest_summary()


def test_every_local_rule_went_through_benign_replay(summary: dict[str, object]) -> None:
    local_rules = load_rules(REPO / "rules")
    benign = summary["benign"]
    assert isinstance(benign, dict)
    evaluated: set[str] = set()
    for corpus in benign.values():
        assert isinstance(corpus, dict)
        evaluated.update(corpus["evaluated_rule_ids"])
    missing = sorted(r.id for r in local_rules if r.id not in evaluated)
    assert missing == [], (
        f"local rules without a benign replay result: {missing}; run `bastion bench run` and commit"
    )


def test_local_rules_are_within_the_benign_budget(summary: dict[str, object]) -> None:
    local_ids = {r.id for r in load_rules(REPO / "rules")}
    benign = summary["benign"]
    assert isinstance(benign, dict)
    budget = float(summary["budget_alerts_per_host_day"])  # type: ignore[arg-type]
    over: list[str] = []
    for name, corpus in benign.items():
        assert isinstance(corpus, dict)
        for entry in corpus["per_rule"]:
            rate = entry["per_host_day"]
            if entry["rule_id"] in local_ids and rate is not None and rate > budget:
                over.append(f"{name}: {entry['title']} at {rate:.2f}/host-day")
    assert over == [], f"local rules over the benign budget of {budget}: {over}"


def test_summary_carries_basis_and_pins(summary: dict[str, object]) -> None:
    pins = summary["pins"]
    assert isinstance(pins, dict) and pins["sigma"] and pins["attack"]
    bastion = summary["bastion"]
    assert isinstance(bastion, dict) and bastion["commit"] and bastion["evaluation_source_hash"]
    coverage = summary["coverage"]
    assert isinstance(coverage, dict)
    for rate in coverage.values():
        assert isinstance(rate, dict) and rate["basis"] and rate["denominator"] > 0
