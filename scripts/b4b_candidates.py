"""List B4b candidates: dev captures of techniques whose rules exist but miss them (Mason, B4b).

A candidate is a labelled **dev** positive capture that the headline does not detect, whose
label technique already has at least one alerting-class rule tagged to it (parent-aware, as the
headline counts). These are procedure variants: the technique is claimed, this procedure is
missed.

Priority is how many held-out captures **on the dev capture's platform** carry the technique's
label (exact, parent or sub-technique, as the headline matches), taken from the **manifest
labels only**; the exact-label and frozen-130 counts are listed beside it. No test
outcome is read, so the ranking cannot steer towards test captures that are currently missed.
The held-out count is also split by corpus, because gains are reported on captures from a
corpus other than the dev capture's. Each dev capture carries a miss reason from its own
outcome record. Only "evaluated, no alerting firing" is B4b material: when an alerting rule
fires but is tagged to another technique, the miss is a tag dispute (B2: no retagging), and a
local rule written for it would be a retag by duplicate.

usage: python scripts/b4b_candidates.py <run name> <out.csv>
"""

from __future__ import annotations

import csv
import json
import sys
import tomllib
from collections import defaultdict
from pathlib import Path
from typing import Any

from bastion.attack import load_attack_data
from bastion.bench.metrics import is_alerting, tagged_to
from bastion.bench.runner import BenchConfig, load_ruleset


def main(run: str, out: Path) -> None:
    repo = Path.cwd()
    settings = tomllib.loads((repo / "bench" / "bench.toml").read_text(encoding="utf-8"))
    trees = tuple(settings.get("rules", {}).get("sigma_trees", []))
    ruleset = load_ruleset(BenchConfig(cache=repo, repo_root=repo, sigma_trees=trees))
    attack = load_attack_data(repo / "data" / "attack" / "enterprise-attack.json")
    alerting_tags = {t.upper() for r in ruleset.rules if is_alerting(r) for t in r.technique_ids()}
    manifest_doc = tomllib.loads((repo / "bench" / "manifest.toml").read_text(encoding="utf-8"))
    manifest = {e["id"]: e for e in manifest_doc["capture"]}

    by_id = {r.id: r for r in ruleset.rules}

    def headline_hit(fired: list[dict[str, Any]], labels: list[str], classes: str) -> bool:
        for f in fired:
            hunting = bool(f.get("hunting") or f.get("emerging"))
            if (classes == "alerting") == hunting:
                continue
            if any(tagged_to(f.get("techniques", []), t) for t in labels):
                return True
        return False

    def miss_reason(outcome: dict[str, Any], labels: list[str]) -> str:
        if outcome.get("skipped") or not outcome.get("events_scanned"):
            return "no events scanned"
        if headline_hit(outcome["fired"], labels, "other"):
            return "hunting or emerging rule fires"
        tagged_ne = [
            rid
            for rid in outcome.get("not_evaluable", {})
            if rid in by_id
            and is_alerting(by_id[rid])
            and any(tagged_to(by_id[rid].technique_ids(), t) for t in labels)
        ]
        if tagged_ne:
            return f"tagged rule not evaluable ({len(tagged_ne)})"
        if any(not (f.get("hunting") or f.get("emerging")) for f in outcome["fired"]):
            return "alerting rule fires, tagged elsewhere"
        return "evaluated, no alerting firing"

    missed: dict[str, str] = {}
    outcomes = (repo / "bench" / "results" / run / "outcomes.jsonl").read_text(encoding="utf-8")
    for line in outcomes.splitlines():
        outcome = json.loads(line)["outcome"]
        entry = manifest.get(outcome["capture_id"])
        if entry is None or entry["split"] != "dev" or entry["kind"] != "positive":
            continue  # never read a test outcome
        if not headline_hit(outcome["fired"], entry["techniques"], "alerting"):
            missed[outcome["capture_id"]] = miss_reason(outcome, entry["techniques"])

    tests = [e for e in manifest.values() if e["split"] == "test" and e["kind"] == "positive"]

    def held_out(technique: str, platform: str) -> dict[str, object]:
        same = [t for t in tests if t.get("platform", "") == platform]
        parent = [t for t in same if any(tagged_to([technique], lab) for lab in t["techniques"])]
        exact = [t for t in same if technique in t["techniques"]]
        corpora: dict[str, int] = defaultdict(int)
        for t in parent:
            corpora[t["corpus"]] += 1
        return {
            "parent": parent,
            "exact": len(exact),
            "frozen": sum(1 for t in parent if t.get("cohort") == "b1"),
            "by_corpus": dict(corpora),
        }

    rows = []
    for cid, entry in sorted(manifest.items()):
        if cid not in missed:
            continue
        platform = entry.get("platform", "")
        for technique in entry["techniques"]:
            if technique not in attack.techniques:
                continue
            if not any(tagged_to([tag], technique) for tag in alerting_tags):
                continue  # a writable gap (lever a in B4), not a procedure variant
            h = held_out(technique, platform)
            by_corpus = h["by_corpus"]
            assert isinstance(by_corpus, dict)
            other = sum(n for corpus, n in by_corpus.items() if corpus != entry["corpus"])
            rows.append(
                {
                    "technique": technique,
                    "name": attack.techniques[technique].name,
                    "platform": platform,
                    "held_out_other_corpus": other,
                    "held_out_same_platform": len(h["parent"]),  # type: ignore[arg-type]
                    "held_out_exact_label": h["exact"],
                    "held_out_frozen_130": h["frozen"],
                    "held_out_by_corpus": ";".join(
                        f"{c}:{n}" for c, n in sorted(by_corpus.items())
                    ),
                    "dev_capture": cid,
                    "dev_corpus": entry["corpus"],
                    "miss_reason": missed[cid],
                }
            )
    rows.sort(
        key=lambda r: (
            -int(r["held_out_other_corpus"]),
            -int(r["held_out_same_platform"]),
            r["technique"],
            r["dev_capture"],
        )
    )
    with out.open("w", encoding="utf-8", newline="") as sink:
        writer = csv.DictWriter(sink, fieldnames=list(rows[0]) if rows else ["technique"])
        writer.writeheader()
        writer.writerows(rows)
    techniques = len({r["technique"] for r in rows})
    print(f"{len(rows)} candidate dev captures over {techniques} techniques -> {out}")


if __name__ == "__main__":
    main(sys.argv[1], Path(sys.argv[2]))
