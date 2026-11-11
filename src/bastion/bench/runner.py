"""The bench runner: collect captures, evaluate them, write resumable results.

One run writes ``bench/results/<date>-<shortsha>/``:

* ``outcomes.jsonl`` (gitignored): one :class:`CaptureOutcome` per capture as
  each finishes, so a run that dies keeps everything before the failure and
  ``--resume`` skips what is already done for the same rules, ATT&CK and
  Bastion commit;
* ``summary.json`` (committed): every section 4 metric with its basis, the
  pins, and per-capture counts without per-event detail;
* ``report.md`` (committed): the same numbers rendered for reading.

The runner changes no detection logic. It calls :func:`bastion.engine.scan`
exactly as the CLI does, with the rules narrowed to the capture's platform.
"""

from __future__ import annotations

import json
import subprocess
import tomllib
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from bastion import __version__, engine
from bastion.attack import AttackData, TagResolution, load_attack_data, resolve_rule_tags
from bastion.bench.captures import Capture, aware
from bastion.bench.corpora import attack_data, citadel, evtx_baseline, evtx_samples, regression
from bastion.bench.corpora.fixtures import fixture_captures
from bastion.bench.evaluability import EvaluabilityReport, check_rules
from bastion.bench.labels import read_label_table, read_supplement
from bastion.bench.manifest import (
    Manifest,
    assign_splits,
    assign_splits_frozen,
    build_entries,
    read_manifest,
    write_manifest,
)
from bastion.bench.metrics import (
    CaptureOutcome,
    Fired,
    benign_volume,
    blind_spot_split,
    claimed_coverage,
    cross_firing,
    detection_rates,
    evidence_ladder,
    is_hunting,
    ladder_distribution,
    not_evaluable_summary,
    regression_pass_rate,
    robustness,
    validated_coverage,
)
from bastion.fetch import attack_bundle_path, sigma_rules_path
from bastion.models import Event, SigmaRule
from bastion.pins import pin_summary
from bastion.sigma import load_rules
from bastion.sigma.filters import SigmaFilter, load_filters

DEFAULT_SEED = 20260926
DEFAULT_BUDGET = 20.0
SUITES = ("positives", "regression", "benign", "fixtures")


@dataclass
class BenchConfig:
    cache: Path
    repo_root: Path = field(default_factory=Path.cwd)
    results_root: Path | None = None
    manifest_path: Path | None = None
    rules_dir: Path | None = None
    attack_file: Path | None = None
    seed: int = DEFAULT_SEED
    budget: float = DEFAULT_BUDGET
    splits: tuple[str, ...] = ("test", "dev")
    suites: tuple[str, ...] = SUITES
    baseline_sets: tuple[str, ...] = ()
    channels: tuple[str, ...] | None = None
    citadel_dir: Path | None = None
    filters_dir: Path | None = None
    resume: bool = True
    max_events_per_capture: int | None = None
    run_name: str | None = None
    dev_only_corpora: tuple[str, ...] = ("citadel_captures",)

    def results_dir_root(self) -> Path:
        return self.results_root or self.repo_root / "bench" / "results"

    def manifest(self) -> Path:
        return self.manifest_path or self.repo_root / "bench" / "manifest.toml"


def load_bench_toml(repo_root: Path) -> dict[str, Any]:
    path = repo_root / "bench" / "bench.toml"
    if not path.is_file():
        return {}
    return tomllib.loads(path.read_text(encoding="utf-8"))


EVALUATION_MODULES = (
    "attack.py",
    "coverage.py",
    "engine.py",
    "models.py",
    "ingest",
    "sigma",
)
"""Source files whose content decides what the engine produces on a capture.

Outcomes are keyed on a hash of these (plus the rule and ATT&CK pins) rather
than on the git commit, so committing documentation or bench code does not
invalidate a long benign replay, while any change to parsing or matching does.
"""


def evaluation_source_hash() -> str:
    import hashlib

    root = Path(__file__).resolve().parent.parent
    digest = hashlib.sha256()
    for name in EVALUATION_MODULES:
        target = root / name
        files = sorted(target.rglob("*.py")) if target.is_dir() else [target]
        for path in files:
            digest.update(path.name.encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


def bastion_commit(repo_root: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return out.stdout.strip() or "unknown"


@dataclass
class RuleSet:
    rules: list[SigmaRule]
    by_id: dict[str, SigmaRule]
    evaluability: EvaluabilityReport
    hunting_ids: set[str]
    filters: list[SigmaFilter] = field(default_factory=list)
    tag_resolution: TagResolution = field(default_factory=TagResolution)

    def for_platform(self, platform: str) -> list[SigmaRule]:
        return [r for r in self.rules if r.logsource.get("product", "").lower() in {platform, ""}]


def load_ruleset(config: BenchConfig) -> RuleSet:
    rules_dir = config.rules_dir or sigma_rules_path(config.repo_root / "data")
    rules = load_rules(rules_dir)
    local = config.repo_root / "rules"
    if config.rules_dir is None and local.is_dir():
        rules += load_rules(local)
    by_id: dict[str, SigmaRule] = {}
    for rule in rules:
        by_id.setdefault(rule.id, rule)
    report = check_rules(rules)
    hunting = {r.id for r in rules if is_hunting(r)}
    filters = load_filters(config.filters_dir or config.repo_root / "filters")
    return RuleSet(rules, by_id, report, hunting, filters)


def load_attack(config: BenchConfig) -> AttackData:
    return load_attack_data(config.attack_file or attack_bundle_path(config.repo_root / "data"))


# --- capture collection -------------------------------------------------------------------


@dataclass
class Collected:
    captures: list[Capture]
    notes: list[str]
    known_fps: dict[str, list[str]]
    regression_skipped: dict[str, int]


def collect_captures(config: BenchConfig, attack: AttackData, ruleset: RuleSet) -> Collected:
    captures: list[Capture] = []
    notes: list[str] = []
    known_fps: dict[str, list[str]] = {}
    regression_skipped: Counter[str] = Counter()

    if "regression" in config.suites:
        root = regression.release_dir(config.cache)
        if (root / "regression_data").is_dir():
            cases = regression.load_regression_cases(root)
            for case in cases:
                if case.skip_reason:
                    regression_skipped[case.skip_reason] += 1
                elif case.rule_id not in ruleset.by_id:
                    case.skip_reason = f"rule not in the loaded ruleset ({case.tree})"
                    regression_skipped[case.skip_reason] += 1
            captures += regression.regression_captures(cases)
            known_fps = regression.known_false_positives(root)
        else:
            notes.append(f"regression_data not fetched at {root}")

    if "positives" in config.suites:
        samples_root = evtx_samples.corpus_dir(config.cache)
        labels_file = config.repo_root / "bench" / "labels" / "evtx-attack-samples.csv"
        if samples_root.is_dir() and labels_file.is_file():
            labels = read_label_table(labels_file.read_text(encoding="utf-8"))
            supplement_file = labels_file.with_name("evtx-attack-samples-supplement.csv")
            supplement = (
                read_supplement(supplement_file.read_text(encoding="utf-8"))
                if supplement_file.is_file()
                else {}
            )
            captures += evtx_samples.evtx_sample_captures(samples_root, labels, attack, supplement)
        else:
            notes.append(f"EVTX-ATTACK-SAMPLES not fetched at {samples_root} or labels missing")
        ad_root = attack_data.corpus_dir(config.cache)
        if ad_root.is_dir():
            captures += attack_data.attack_data_captures(ad_root, attack)
        else:
            notes.append(f"attack_data not fetched at {ad_root}")
        citadel_dir = config.citadel_dir or citadel.default_captures_dir()
        if citadel_dir.is_dir():
            found, skipped = citadel.citadel_captures(citadel_dir, config.cache, attack)
            captures += found
            notes += skipped
        else:
            notes.append(f"Citadel captures not found at {citadel_dir}")

    if "benign" in config.suites:
        sets = config.baseline_sets or tuple(evtx_baseline.default_sets())
        for name in sets:
            root = evtx_baseline.set_dir(config.cache, name)
            if root.is_dir():
                captures += evtx_baseline.baseline_captures(root, name, config.channels)
            else:
                notes.append(f"evtx-baseline set {name} not fetched at {root}")

    if "fixtures" in config.suites:
        labels_file = config.repo_root / "bench" / "labels" / "fixtures.csv"
        if labels_file.is_file():
            captures += fixture_captures(config.repo_root, labels_file, attack)

    return Collected(captures, notes, known_fps, dict(regression_skipped))


def resolve_manifest(
    config: BenchConfig, captures: Sequence[Capture]
) -> tuple[Manifest, list[str]]:
    """Read the committed manifest; captures it does not know get a split by the same rule."""
    path = config.manifest()
    notes: list[str] = []
    forced = dict.fromkeys(config.dev_only_corpora, "dev")
    if path.is_file():
        manifest = read_manifest(path)
        unknown = [c for c in captures if c.id not in manifest.entries]
        if unknown:
            notes.append(
                f"{len(unknown)} captures are not in {path.name}; split assigned at run time "
                "(run `bastion bench manifest` to record them)"
            )
            extra = assign_splits(unknown, manifest.seed, forced)
            for entry in build_entries(unknown, extra, config.cache):
                manifest.entries[entry.id] = entry
        return manifest, notes
    notes.append(f"no manifest at {path}; splits assigned at run time with seed {config.seed}")
    splits = assign_splits(captures, config.seed, forced)
    entries = build_entries(captures, splits, config.cache)
    return Manifest(config.seed, pin_summary(), {e.id: e for e in entries}), notes


def generate_manifest(config: BenchConfig) -> Path:
    """Build and write ``bench/manifest.toml`` from the fetched corpora."""
    attack = load_attack(config)
    ruleset = load_ruleset(config)
    ruleset.tag_resolution = resolve_rule_tags(ruleset.rules, attack)
    collected = collect_captures(config, attack, ruleset)
    forced = dict.fromkeys(config.dev_only_corpora, "dev")
    path = config.manifest()
    if path.is_file():
        # Split integrity (B3): existing dev and test assignments are frozen; only new or
        # newly labelled captures are assigned, with the existing seed.
        existing = read_manifest(path)
        splits, cohorts = assign_splits_frozen(collected.captures, existing, forced)
        entries = build_entries(collected.captures, splits, config.cache, cohorts)
        write_manifest(path, entries, existing.seed, pin_summary())
        return path
    splits = assign_splits(collected.captures, config.seed, forced)
    entries = build_entries(collected.captures, splits, config.cache)
    write_manifest(path, entries, config.seed, pin_summary())
    return path


# --- evaluation -----------------------------------------------------------------------------


def _limited(events: Iterator[Event], limit: int | None) -> Iterator[Event]:
    if limit is None:
        yield from events
        return
    for index, event in enumerate(events):
        if index >= limit:
            return
        yield event


def evaluate_capture(
    capture: Capture,
    rules: Sequence[SigmaRule],
    attack: AttackData,
    hunting_ids: set[str],
    split: str,
    limit: int | None = None,
    filters: Sequence[SigmaFilter] = (),
) -> CaptureOutcome:
    """Run the engine over one capture exactly as ``bastion scan`` would."""
    first: datetime | None = None
    last: datetime | None = None
    seen = 0

    def tracked() -> Iterator[Event]:
        nonlocal first, last, seen
        for event in _limited(capture.events(), limit):
            seen += 1
            if event.timestamp is not None:
                when = aware(event.timestamp)
                first = when if first is None or when < first else first
                last = when if last is None or when > last else last
            yield event

    outcome = engine.scan(tracked(), rules, attack.techniques, filters)
    counts: Counter[str] = Counter(d.rule_id for d in outcome.detections)
    by_rule = {r.id: r for r in rules}
    fired = [
        Fired(
            rule_id=rule_id,
            title=by_rule[rule_id].title if rule_id in by_rule else "",
            level=by_rule[rule_id].level if rule_id in by_rule else "",
            hunting=rule_id in hunting_ids,
            techniques=list(by_rule[rule_id].technique_ids()) if rule_id in by_rule else [],
            count=count,
        )
        for rule_id, count in sorted(counts.items())
    ]
    notes = dict(capture.notes)
    if limit is not None and seen >= limit:
        notes["event_cap"] = f"stopped after {limit} events"
    return CaptureOutcome(
        capture_id=capture.id,
        corpus=capture.corpus,
        kind=capture.kind,
        split=split,
        platform=capture.platform,
        techniques=list(capture.techniques),
        raw_labels=list(capture.raw_labels),
        host=capture.host,
        events_scanned=seen,
        fired=fired,
        first_ts=first.isoformat() if first else None,
        last_ts=last.isoformat() if last else None,
        unsupported_rules=len(outcome.unsupported_rules),
        rule_errors=len(outcome.rule_errors),
        expected_matches=dict(capture.expected_matches),
        notes=notes,
        filtered=dict(outcome.filtered),
        not_evaluable=dict(outcome.not_evaluable),
        not_evaluable_fields=dict(outcome.not_evaluable_fields),
        outside_source=dict(outcome.outside_source),
    )


@dataclass
class RunContext:
    run_dir: Path
    run_key: str
    outcomes_path: Path
    existing: dict[str, CaptureOutcome]


def open_run(config: BenchConfig, rules_label: str) -> RunContext:
    commit = bastion_commit(config.repo_root)
    name = config.run_name or f"{datetime.now(UTC).strftime('%Y-%m-%d')}-{commit}"
    run_dir = config.results_dir_root() / name
    run_dir.mkdir(parents=True, exist_ok=True)
    run_key = f"eval {evaluation_source_hash()}|{rules_label}"
    outcomes_path = run_dir / "outcomes.jsonl"
    existing: dict[str, CaptureOutcome] = {}
    if config.resume and outcomes_path.is_file():
        for line in outcomes_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("run_key") == run_key:
                outcome = CaptureOutcome.from_dict(record["outcome"])
                existing[outcome.capture_id] = outcome
    return RunContext(run_dir, run_key, outcomes_path, existing)


def run_bench(
    config: BenchConfig, progress: Callable[[str], None] | None = None
) -> tuple[dict[str, Any], Path]:
    """Evaluate every selected capture and write summary.json and report.md."""
    say = progress or (lambda _message: None)
    attack = load_attack(config)
    ruleset = load_ruleset(config)
    ruleset.tag_resolution = resolve_rule_tags(ruleset.rules, attack)
    pins = pin_summary()
    rules_label = f"sigma {pins['sigma']} attack {pins['attack']} rules {len(ruleset.rules)}"
    collected = collect_captures(config, attack, ruleset)
    manifest, manifest_notes = resolve_manifest(config, collected.captures)
    context = open_run(config, rules_label)
    say(
        f"{len(ruleset.rules)} rules, {len(collected.captures)} captures, "
        f"run {context.run_dir.name}"
    )

    selected: list[tuple[Capture, str]] = []
    for capture in collected.captures:
        split = manifest.split_of(capture.id) or ""
        if capture.kind == "positive" and split not in config.splits and split != "unlabelled":
            continue
        selected.append((capture, split))

    outcomes: list[CaptureOutcome] = []
    rules_by_platform = {p: ruleset.for_platform(p) for p in ("windows", "linux")}
    with context.outcomes_path.open("a", encoding="utf-8") as sink:
        for index, (capture, split) in enumerate(selected, start=1):
            cached = context.existing.get(capture.id)
            if cached is not None:
                outcomes.append(cached)
                continue
            if capture.kind == "regression":
                rules = [ruleset.by_id[r] for r in capture.expected_matches if r in ruleset.by_id]
            else:
                rules = rules_by_platform[capture.platform]
            say(f"[{index}/{len(selected)}] {capture.id}")
            try:
                outcome = evaluate_capture(
                    capture,
                    rules,
                    attack,
                    ruleset.hunting_ids,
                    split,
                    config.max_events_per_capture,
                    ruleset.filters,
                )
            except Exception as exc:  # a broken file must not end the run
                outcome = CaptureOutcome(
                    capture.id,
                    capture.corpus,
                    capture.kind,
                    split,
                    capture.platform,
                    list(capture.techniques),
                    list(capture.raw_labels),
                    capture.host,
                    0,
                    [],
                    expected_matches=dict(capture.expected_matches),
                    notes=dict(capture.notes),
                    skipped=f"{type(exc).__name__}: {exc}",
                )
            outcomes.append(outcome)
            sink.write(
                json.dumps({"run_key": context.run_key, "outcome": outcome.as_dict()}) + "\n"
            )
            sink.flush()

    summary = summarize(config, attack, ruleset, collected, manifest, outcomes, context)
    summary["notes"] = collected.notes + manifest_notes
    (context.run_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=False), encoding="utf-8"
    )
    from bastion.bench.report import render_report  # local import: report depends on summary shape

    (context.run_dir / "report.md").write_text(render_report(summary), encoding="utf-8")
    if "benign" in config.suites:
        # LATEST is what the CI budget gate reads, so only a run that replayed goodware may
        # claim it; a positives-only run must not hide the last benign figures.
        latest = config.results_dir_root() / "LATEST"
        latest.write_text(context.run_dir.name + "\n", encoding="utf-8")
    return summary, context.run_dir


def summarize(
    config: BenchConfig,
    attack: AttackData,
    ruleset: RuleSet,
    collected: Collected,
    manifest: Manifest,
    outcomes: Sequence[CaptureOutcome],
    context: RunContext,
) -> dict[str, Any]:
    pins = pin_summary()
    pins_label = f"Sigma {pins['sigma']}, ATT&CK {pins['attack']}"
    evaluable = ruleset.evaluability.evaluable_map(ruleset.rules)
    local_rules = [
        r
        for r in ruleset.rules
        if "rules-threat-hunting" not in r.file_path
        and r.file_path.replace("\\", "/").startswith(
            str(config.repo_root / "rules").replace("\\", "/")
        )
    ]
    rates: dict[str, Any] = {}
    for split in ("test", "dev"):
        detection = detection_rates(outcomes, attack, split, pins_label)
        validated = validated_coverage(outcomes, attack, split, pins_label)
        rates[split] = {
            "captures": detection.captures,
            "detection_rate": detection.overall.as_dict(),
            "detection_rate_strict": detection.strict.as_dict(),
            "any_alert_rate": detection.any_alert.as_dict(),
            "hierarchical_hits": detection.hierarchical_hits,
            "validated_coverage_over_labelled": validated.over_labelled.as_dict(),
            "validated_coverage_strict_over_labelled": validated.strict_over_labelled.as_dict(),
            "validated_coverage_over_matrix": validated.over_matrix.as_dict(),
            "validated_techniques": sorted(validated.validated),
            "validated_techniques_strict": sorted(validated.validated_strict),
            "per_technique": {t: r.as_dict() for t, r in detection.per_technique.items()},
            "per_tactic": {t: r.as_dict() for t, r in detection.per_tactic.items()},
            "cross_firing": cross_firing(outcomes, split),
        }
    coverage = claimed_coverage(ruleset.rules, attack, evaluable)
    regression_summary = regression_pass_rate(
        outcomes, collected.regression_skipped, ruleset.by_id, pins_label
    )
    baseline_volume = benign_volume(
        outcomes,
        collected.known_fps,
        config.budget,
        [r.id for r in ruleset.for_platform("windows")],
        corpus="evtx_baseline",
    )
    lab_volume = benign_volume(
        outcomes,
        collected.known_fps,
        config.budget,
        [r.id for r in ruleset.for_platform("linux")],
        corpus="citadel_captures",
    )
    ladder = evidence_ladder(outcomes, ruleset.rules, attack)
    unlabelled = [o for o in outcomes if o.kind == "positive" and not o.techniques]
    skipped = [o for o in outcomes if o.skipped]
    per_capture = [
        {
            "id": o.capture_id,
            "corpus": o.corpus,
            "kind": o.kind,
            "split": o.split,
            "techniques": o.techniques,
            "events": o.events_scanned,
            "alerting_rules_fired": sum(1 for f in o.fired if not f.hunting),
            "hunting_rules_fired": sum(1 for f in o.fired if f.hunting),
            "skipped": o.skipped,
            **({"notes": o.notes} if o.notes else {}),
        }
        for o in outcomes
    ]
    summary_out: dict[str, Any] = {
        "bastion": {
            "version": __version__,
            "commit": bastion_commit(config.repo_root),
            "evaluation_source_hash": evaluation_source_hash(),
        },
        "run": context.run_dir.name,
        "pins": pins,
        "seed": manifest.seed,
        "budget_alerts_per_host_day": config.budget,
        "splits_evaluated": list(config.splits),
        "event_cap_per_capture": config.max_events_per_capture,
        "rules": {
            "loaded": len(ruleset.rules),
            "alerting": sum(1 for r in ruleset.rules if r.id not in ruleset.hunting_ids),
            "hunting": len(ruleset.hunting_ids),
            "not_evaluable": len(ruleset.evaluability.unsupported),
            "not_evaluable_by_reason": ruleset.evaluability.by_reason,
            "not_evaluable_files": [
                Path(u.file_path).name for u in ruleset.evaluability.unsupported
            ],
            "tag_resolution": ruleset.tag_resolution.as_dict(),
            "local_rule_ids": sorted(r.id for r in local_rules),
            "local_rules_hunting": sorted(r.id for r in local_rules if r.id in ruleset.hunting_ids),
            "filters_loaded": sorted(f.id for f in ruleset.filters),
            "suppressed_by_filters": dict(
                sorted(
                    Counter(
                        {
                            rule_id: sum(o.filtered.get(rule_id, 0) for o in outcomes)
                            for o in outcomes
                            for rule_id in o.filtered
                        }
                    ).items()
                )
            ),
        },
        "coverage": {name: rate.as_dict() for name, rate in coverage.items()},
        "blind_spots_alerting_class": blind_spot_split(ruleset.rules, attack),
        "rates": rates,
        "regression": {
            "pass_rate": regression_summary.passed.as_dict(),
            "pass_rate_strict": regression_summary.passed_strict.as_dict(),
            "more_than_expected": regression_summary.more_than_expected,
            "failed": regression_summary.failed,
            "skipped_by_reason": regression_summary.skipped_by_reason,
            "by_logsource": regression_summary.by_logsource,
            "failures": regression_summary.failures,
            "over_count": regression_summary.over_count,
        },
        "benign": {
            "evtx_baseline": _volume_dict(baseline_volume),
            "citadel_background": _volume_dict(lab_volume),
        },
        "ladder": {"distribution": ladder_distribution(ladder), "per_technique": ladder},
        "robustness": robustness(ruleset.rules, {}),
        "not_evaluable": not_evaluable_summary(outcomes, ruleset.by_id),
        "captures": {
            "total": len(outcomes),
            "by_kind": dict(Counter(o.kind for o in outcomes)),
            "by_corpus": dict(Counter(o.corpus for o in outcomes)),
            "unlabelled_positive": len(unlabelled),
            "skipped": [{"id": o.capture_id, "reason": o.skipped} for o in skipped],
            "detail_file": "captures.jsonl",
        },
    }
    # Per-capture detail is a line per capture in its own file (gitignored like outcomes.jsonl)
    # so the committed summary stays small; the counts above are what the summary carries.
    with (context.run_dir / "captures.jsonl").open("w", encoding="utf-8") as sink:
        for record in per_capture:
            sink.write(json.dumps(record) + "\n")
    return summary_out


def _volume_dict(volume: Any) -> dict[str, Any]:
    data = dict(vars(volume))
    data["per_rule"] = data["per_rule"][:50]
    return data


def iter_outcomes(path: Path) -> Iterable[CaptureOutcome]:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield CaptureOutcome.from_dict(json.loads(line)["outcome"])
