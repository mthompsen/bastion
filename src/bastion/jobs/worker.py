"""Run one job to its end, in this process (the dispatcher starts a process per job)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from bastion.bench.captures import Capture
from bastion.models import Event
from bastion.store import Store

#: A scan checks for a cancel request and reports progress every this many events.
CHECK_EVERY = 1000


class JobCancelled(Exception):
    """The job's cancel was requested and the worker stopped."""


def bench_results_root(store: Store) -> Path:
    """Where bench jobs write their results: beside the store, never in the repository, so
    a job cannot touch the tracked ``bench/results`` or its ``LATEST``."""
    return store.path.parent / "bench-results"


def run_job(store: Store, job_id: str, *, repo_root: Path) -> str:
    """Run ``job_id`` and record how it ended; returns the final status."""
    job = store.get_job(job_id)
    try:
        if job["kind"] == "scan":
            ref = _scan(store, job_id, job["params"])
        else:
            ref = _bench(store, job_id, job["params"], repo_root)
    except JobCancelled as exc:
        store.finish_job(job_id, "cancelled", error=str(exc))
        return "cancelled"
    except Exception as exc:
        store.finish_job(job_id, "failed", error=f"{type(exc).__name__}: {exc}")
        return "failed"
    store.finish_job(job_id, "done", result_ref=ref)
    return "done"


def _path(params: dict[str, Any], key: str) -> Path | None:
    """Optional path parameters (``rules_dir``, ``attack_file``, ``cache_dir``,
    ``citadel_dir``). The API does not accept them; tests and the CLI defaults use them."""
    value = params.get(key)
    return Path(value) if value else None


def _scan(store: Store, job_id: str, params: dict[str, Any]) -> str:
    from bastion.cli import PlatformOption, _run_scan, _sigma_version
    from bastion.fetch import sigma_rules_path

    logfile = Path(params["path"])
    label = logfile.name

    def watched(events: Iterator[Event]) -> Iterator[Event]:
        count = 0
        for count, event in enumerate(events, start=1):
            if count % CHECK_EVERY == 0:
                if store.cancel_requested(job_id):
                    raise JobCancelled(f"stopped after {count} events of {label}")
                store.set_progress(job_id, count, None, label, "events")
            yield event
        store.set_progress(job_id, count, count, label, "events")

    platform = params.get("platform")
    rules_dir = _path(params, "rules_dir")
    result, _outcome, _summary, attack_version, log_platform = _run_scan(
        logfile,
        PlatformOption(platform) if platform else None,
        rules_dir,
        _path(params, "attack_file"),
        wrap_events=watched,
    )
    return store.add_scan(
        result,
        logfile=str(logfile),
        platform=log_platform,
        sigma_version=_sigma_version(rules_dir or sigma_rules_path()),
        attack_version=attack_version,
    )


def _bench(store: Store, job_id: str, params: dict[str, Any], repo_root: Path) -> str:
    from bastion.bench import runner as bench_runner
    from bastion.cli import _bench_config

    config = _bench_config(
        _path(params, "cache_dir"),
        _path(params, "rules_dir"),
        _path(params, "attack_file"),
        baseline_set=params.get("baseline_sets"),
        channel=params.get("channels"),
        citadel_dir=_path(params, "citadel_dir"),
        splits=",".join(params.get("splits", ["test", "dev"])),
        suites=",".join(params.get("suites", list(bench_runner.SUITES))),
        max_events=params.get("max_events_per_capture"),
        resume=True,
        run_name=params["run_name"],
        repo_root=repo_root,
        results_root=bench_results_root(store),
    )

    seen = {"total": 0}

    def on_capture(done: int, total: int, capture: Capture) -> None:
        seen["total"] = total
        store.set_progress(job_id, done, total, capture.corpus, "captures")

    try:
        _summary, run_dir = bench_runner.run_bench(
            config,
            on_capture=on_capture,
            should_stop=lambda: store.cancel_requested(job_id),
        )
    except bench_runner.BenchCancelled as exc:
        raise JobCancelled(str(exc)) from exc
    store.set_progress(job_id, seen["total"], seen["total"], "", "captures")
    return store.import_bench_run(run_dir)
