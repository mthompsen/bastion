"""A small fake corpus world for runner and CLI tests: every corpus, all offline.

Builds, under a temporary directory, a repository root (fixture logs, label
tables, bench.toml) and a corpus cache laid out exactly as the fetchers would
leave it, using the repository's own fixture logs and example EVTX files.
"""

from __future__ import annotations

import gzip
import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from bastion.bench.corpora import attack_data, citadel, evtx_baseline, evtx_samples, regression
from bastion.pins import load_pins

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests" / "fixtures"
EVTX_A = REPO / "examples" / "logs" / "sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx"
EVTX_B = REPO / "examples" / "logs" / "Sysmon_13_1_UACBypass_SDCLTBypass.evtx"
WINDOWS_RULE_ID = "11111111-1111-4111-8111-111111111111"
AUDIT_LINES = (FIXTURES / "audit_sample.log").read_text(encoding="utf-8").splitlines()


@dataclass
class World:
    repo_root: Path
    cache: Path
    citadel_dir: Path
    rules_dir: Path = FIXTURES / "rules"
    attack_file: Path = FIXTURES / "mini_attack.json"


def build_world(tmp_path: Path) -> World:
    repo_root = tmp_path / "repo"
    cache = tmp_path / "cache"
    (repo_root / "examples" / "logs").mkdir(parents=True)
    (repo_root / "bench" / "labels").mkdir(parents=True)
    shutil.copy(FIXTURES / "auth_sample.log", repo_root / "examples" / "logs" / "auth_sample.log")
    (repo_root / "bench" / "labels" / "fixtures.csv").write_text(
        "path,source_kind,platform,technique_ids\n"
        "examples/logs/auth_sample.log,syslog,linux,T1110\n"
        "examples/logs/missing.log,syslog,linux,T1110\n",
        encoding="utf-8",
    )
    (repo_root / "bench" / "bench.toml").write_text(
        "[budget]\nalerts_per_host_day = 20.0\n\n"
        '[split]\nseed = 1\ndev_only = ["citadel_captures"]\n',
        encoding="utf-8",
    )

    # regression_data: one passing case (expected 0 matches) and one failing (expected 1).
    release = regression.release_dir(cache)
    case_dir = release / "regression_data" / "rules" / "windows" / "process_creation" / "case"
    case_dir.mkdir(parents=True)
    sample = case_dir / f"{WINDOWS_RULE_ID}.evtx"
    shutil.copy(EVTX_A, sample)
    rel = sample.relative_to(release).as_posix()
    (case_dir / "info.yml").write_text(
        json.dumps(
            {
                "rule_metadata": [{"id": WINDOWS_RULE_ID, "title": "Encoded PowerShell"}],
                "regression_tests_info": [
                    {"type": "evtx", "match_count": 0, "path": rel, "name": "negative"},
                    {"type": "evtx", "match_count": 1, "path": rel, "name": "positive"},
                    {"type": "json", "match_count": 1, "path": rel},
                ],
            }
        ),
        encoding="utf-8",
    )
    other_dir = release / "regression_data" / "rules-threat-hunting" / "x"
    other_dir.mkdir(parents=True)
    (other_dir / "info.yml").write_text(
        json.dumps(
            {
                "rule_metadata": [{"id": "not-loaded-rule", "title": "Elsewhere"}],
                "regression_tests_info": [{"type": "evtx", "match_count": 1, "path": rel}],
            }
        ),
        encoding="utf-8",
    )
    (release / ".github" / "workflows").mkdir(parents=True)
    (release / ".github" / "workflows" / "known-FPs.csv").write_text(
        f"RuleId;RuleName;MatchString\n{WINDOWS_RULE_ID};Encoded PowerShell;.*\n", encoding="utf-8"
    )

    # EVTX-ATTACK-SAMPLES: two files, one labelled (through a revoked id) and one unlabelled.
    samples = evtx_samples.corpus_dir(cache)
    (samples / "Execution").mkdir(parents=True)
    (samples / "Other").mkdir(parents=True)
    shutil.copy(EVTX_A, samples / "Execution" / "labelled.evtx")
    shutil.copy(EVTX_B, samples / "Other" / "unlabelled.evtx")
    shutil.copy(EVTX_B, samples / "Execution" / "second.evtx")
    (repo_root / "bench" / "labels" / "evtx-attack-samples.csv").write_text(
        "# test table\npath,tactic_folder,technique_ids,sheet_rows\n"
        "Execution/labelled.evtx,Execution,T9001,3\n"
        "Execution/second.evtx,Execution,T1059.001,4\n"
        "Other/unlabelled.evtx,Other,,\n",
        encoding="utf-8",
    )

    # evtx-baseline: one host set with two channels.
    baseline = evtx_baseline.set_dir(cache, "win2022-evtx")
    (baseline / "win2022-evtx").mkdir(parents=True)
    shutil.copy(EVTX_A, baseline / "win2022-evtx" / "Security.evtx")
    shutil.copy(EVTX_B, baseline / "win2022-evtx" / "Microsoft-Windows-Sysmon%4Operational.evtx")

    # attack_data: a real manifest path from the pinned list, with fake auditd and secure logs.
    ad_root = attack_data.corpus_dir(cache)
    manifest = attack_data.dataset_manifests()[0]
    dataset_dir = (ad_root / manifest).parent
    dataset_dir.mkdir(parents=True)
    (dataset_dir / "audit.log").write_text("\n".join(AUDIT_LINES) + "\n", encoding="utf-8")
    shutil.copy(FIXTURES / "auth_sample.log", dataset_dir / "secure.log")
    prefix = "/" + dataset_dir.relative_to(ad_root).as_posix()
    (ad_root / manifest).write_text(
        json.dumps(
            {
                "mitre_technique": ["T1110"],
                "datasets": [
                    {"path": f"{prefix}/audit.log", "sourcetype": "auditd"},
                    {"path": f"{prefix}/secure.log", "sourcetype": "linux_secure"},
                ],
            }
        ),
        encoding="utf-8",
    )

    # Citadel: one version 1 capture with one run.
    citadel_dir = tmp_path / "citadel" / "captures"
    capture = citadel_dir / citadel.default_capture_names()[0]
    capture.mkdir(parents=True)
    with gzip.open(capture / "audit.log.gz", "wt", encoding="utf-8") as out:
        out.write("\n".join(AUDIT_LINES) + "\n")
    base = datetime.fromtimestamp(1780000000, tz=UTC)
    (capture / "capture.json").write_text(
        json.dumps(
            {
                "version": 1,
                "clock": {"seconds": 0.0, "uncertainty": 0.05},
                "failures": {},
                "runs": [
                    {
                        "identifier": "T1110/run",
                        "technique": "T1110",
                        "started_at": base.isoformat(),
                        "finished_at": base.replace(microsecond=150000).isoformat(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert load_pins()["sigma"]["tag"] in str(release)
    return World(repo_root=repo_root, cache=cache, citadel_dir=citadel_dir)
