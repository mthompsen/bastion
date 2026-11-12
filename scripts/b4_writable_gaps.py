"""List lever a candidates: dev captures of writable-gap techniques (B4, START_PROMPT lever 7).

A writable gap is a technique that (1) ATT&CK places on a Windows or Linux host, (2) ATT&CK's
detection strategies map to a log source Bastion reads, and (3) no alerting-class rule is
tagged to (parent-aware, as the headline counts). A candidate is a labelled **dev** capture of
such a technique. Only the manifest, ATT&CK, the loaded rules and one run's dev outcomes are
read; no test capture and no log content is read, so the list cannot be steered by held-out
results.

usage: python scripts/b4_writable_gaps.py <run name> <out.csv>
"""

from __future__ import annotations

import csv
import json
import sys
import tomllib
from collections import defaultdict
from pathlib import Path

from bastion.attack import load_attack_data
from bastion.bench.metrics import is_alerting, tagged_to
from bastion.bench.runner import BenchConfig, load_ruleset
from bastion.coverage import host_relevant, telemetry_readable


def main(run: str, out: Path) -> None:
    repo = Path.cwd()
    settings = tomllib.load(open(repo / "bench" / "bench.toml", "rb"))
    trees = tuple(settings.get("rules", {}).get("sigma_trees", []))
    config = BenchConfig(cache=repo, repo_root=repo, sigma_trees=trees)
    ruleset = load_ruleset(config)
    attack = load_attack_data(repo / "data" / "attack" / "enterprise-attack.json")
    alerting_tags = {t.upper() for r in ruleset.rules if is_alerting(r) for t in r.technique_ids()}
    manifest = {
        e["id"]: e for e in tomllib.load(open(repo / "bench" / "manifest.toml", "rb"))["capture"]
    }
    fired: dict[str, int] = {}
    for line in open(repo / "bench" / "results" / run / "outcomes.jsonl", encoding="utf-8"):
        outcome = json.loads(line)["outcome"]
        entry = manifest.get(outcome["capture_id"])
        if entry is None or entry["split"] != "dev":
            continue  # never read a test outcome
        fired[outcome["capture_id"]] = sum(f["count"] for f in outcome["fired"])
    by_technique: dict[str, list[str]] = defaultdict(list)
    for cid, entry in sorted(manifest.items()):
        if entry["split"] != "dev" or entry["kind"] != "positive":
            continue
        for technique in entry["techniques"]:
            by_technique[technique].append(cid)
    rows = []
    for technique, captures in sorted(by_technique.items()):
        ref = attack.techniques.get(technique)
        if ref is None:
            continue
        claimed = any(tagged_to([tag], technique) for tag in alerting_tags)
        if claimed or not host_relevant(ref) or not telemetry_readable(ref):
            continue
        rows.append(
            {
                "technique": technique,
                "name": ref.name,
                "platforms": ";".join(ref.platforms),
                "log_sources": ";".join(ref.log_sources[:6]),
                "dev_captures": ";".join(captures),
                "dev_capture_alerts": ";".join(str(fired.get(c, "")) for c in captures),
            }
        )
    with out.open("w", encoding="utf-8", newline="") as sink:
        writer = csv.DictWriter(sink, fieldnames=list(rows[0]) if rows else ["technique"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"{len(rows)} writable-gap techniques with dev captures -> {out}")


if __name__ == "__main__":
    main(sys.argv[1], Path(sys.argv[2]))
