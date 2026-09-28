"""SigmaHQ ``regression_data``: per-rule labelled captures with expected match counts.

The data ships inside the same release archive as the rules, so the pins
agree by construction. Each rule directory holds an ``info.yml`` whose
``regression_tests_info`` entries name a sample (EVTX or JSON) and the
number of times the rule must fire on it. EVTX samples are evaluated with
Bastion's own ingester; JSON samples need a pySigma field-mapping pipeline
Bastion does not have yet, so they are recorded as skipped with that reason
rather than dropped.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import yaml

from bastion.bench.cache import download, extract_zip
from bastion.bench.captures import Capture
from bastion.pins import load_pins

KNOWN_FPS_MEMBER = ".github/workflows/known-FPs.csv"
JSON_SKIP_REASON = "JSON sample needs a pySigma field-mapping pipeline (B3)"


def release_dir(cache: Path) -> Path:
    return cache / "sigma" / str(load_pins()["sigma"]["tag"])


def fetch_regression(cache: Path, client: httpx.Client | None = None, force: bool = False) -> Path:
    """Download the pinned release zip and extract ``regression_data/`` and the known-FPs list."""
    sigma = load_pins()["sigma"]
    archive = download(
        str(sigma["url"]), cache / "sigma" / f"{sigma['tag']}.zip", client, force=force
    )

    def select(name: str) -> Path | None:
        parts = name.split("/", 1)
        if len(parts) < 2:
            return None
        relative = parts[1]
        if relative.startswith("regression_data/") or relative == KNOWN_FPS_MEMBER:
            return Path(relative)
        return None

    root = release_dir(cache)
    extract_zip(archive, root, select, force=force)
    return root


@dataclass
class RegressionCase:
    """One ``regression_tests_info`` entry."""

    rule_id: str
    rule_title: str
    tree: str
    info_path: Path
    sample_type: str
    sample_path: Path | None
    match_count: int | None
    name: str = ""
    skip_reason: str | None = None
    #: rule metadata the bench fills in once the ruleset is loaded
    notes: dict[str, str] = field(default_factory=dict)


def load_regression_cases(root: Path) -> list[RegressionCase]:
    """Every case under ``root/regression_data``, skipped ones included with a reason."""
    cases: list[RegressionCase] = []
    data_dir = root / "regression_data"
    for info_path in sorted(data_dir.rglob("info.yml")):
        try:
            doc = yaml.safe_load(info_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            cases.append(
                RegressionCase(
                    "",
                    "",
                    _tree(info_path, data_dir),
                    info_path,
                    "",
                    None,
                    None,
                    skip_reason=f"info.yml does not parse: {exc}",
                )
            )
            continue
        metadata = doc.get("rule_metadata") or [{}]
        rule_id = str(metadata[0].get("id", "")) if isinstance(metadata, list) else ""
        rule_title = str(metadata[0].get("title", "")) if isinstance(metadata, list) else ""
        tree = _tree(info_path, data_dir)
        for entry in doc.get("regression_tests_info") or []:
            sample_type = str(entry.get("type", "")).lower()
            raw_count = entry.get("match_count")
            match_count = int(raw_count) if isinstance(raw_count, int) else None
            sample = root / str(entry.get("path", "")) if entry.get("path") else None
            case = RegressionCase(
                rule_id,
                rule_title,
                tree,
                info_path,
                sample_type,
                sample,
                match_count,
                name=str(entry.get("name", "")),
            )
            if not rule_id:
                case.skip_reason = "info.yml names no rule id"
            elif sample_type != "evtx":
                case.skip_reason = (
                    JSON_SKIP_REASON
                    if sample_type in {"json", "ndjson", "jsonl"}
                    else f"unknown sample type {sample_type!r}"
                )
            elif sample is None or not sample.is_file():
                case.skip_reason = "sample file missing from the archive"
            cases.append(case)
    return cases


def _tree(info_path: Path, data_dir: Path) -> str:
    relative = info_path.relative_to(data_dir)
    return relative.parts[0] if relative.parts else ""


def regression_captures(cases: list[RegressionCase]) -> list[Capture]:
    """One capture per evaluable EVTX case, expected count attached."""
    captures: list[Capture] = []
    per_rule: dict[str, int] = {}
    for case in cases:
        if case.skip_reason or case.sample_path is None:
            continue
        index = per_rule.get(case.rule_id, 0)
        per_rule[case.rule_id] = index + 1
        captures.append(
            Capture(
                id=f"regression/{case.tree}/{case.rule_id}/{index}",
                corpus="regression_data",
                kind="regression",
                platform="windows",
                source_kind="evtx",
                paths=(case.sample_path,),
                license=str(load_pins()["corpora"]["regression_data"]["license"]),
                expected_matches={case.rule_id: case.match_count},
                notes={"tree": case.tree, "rule_title": case.rule_title, "case": case.name},
            )
        )
    return captures


def known_false_positives(root: Path) -> dict[str, list[str]]:
    """SigmaHQ's ``known-FPs.csv``: rule id -> match patterns (``.*`` means any event)."""
    path = root / KNOWN_FPS_MEMBER
    if not path.is_file():
        return {}
    allow: dict[str, list[str]] = {}
    with path.open(encoding="utf-8", newline="") as handle:
        for record in csv.DictReader(handle, delimiter=";"):
            rule_id = (record.get("RuleId") or "").strip()
            if rule_id:
                allow.setdefault(rule_id, []).append((record.get("MatchString") or "").strip())
    return allow
