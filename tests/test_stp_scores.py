"""bench/stp-scores.csv: every local rule is scored, and every score is well formed (B4)."""

from __future__ import annotations

from pathlib import Path

import yaml

from bastion.bench.runner import load_stp_scores

REPO = Path(__file__).resolve().parent.parent


def _local_header_ids() -> set[str]:
    ids: set[str] = set()
    for path in sorted((REPO / "rules").rglob("*.yml")):
        docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
        headers = [d for d in docs if "correlation" in d] or docs[:1]
        ids.update(str(d["id"]) for d in headers)
    return ids


def test_every_local_rule_has_a_score() -> None:
    scores = load_stp_scores(REPO)
    missing = _local_header_ids() - set(scores)
    assert not missing, f"local rules without a Summiting the Pyramid score: {sorted(missing)}"


def test_scores_are_levels_one_to_five() -> None:
    scores = load_stp_scores(REPO)
    assert scores and set(scores.values()) <= {f"level-{n}" for n in range(1, 6)}


def test_missing_file_means_nothing_scored(tmp_path: Path) -> None:
    assert load_stp_scores(tmp_path) == {}
