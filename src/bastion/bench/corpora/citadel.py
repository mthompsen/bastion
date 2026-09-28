"""Citadel Arena captures: own-lab auditd telemetry from Atomic runs, dev split only.

A capture directory holds ``capture.json`` (runs with host-clock windows, a
guest clock offset, failures) and the guest's ``audit.log.gz`` and
``journal.json.gz``. Version 1 keeps one segment beside the manifest;
version 2 lists ``segments`` each with its own ``logs`` directory.

Attribution follows Citadel's own rules: a run window is stamped on the host
and shifted onto the guest clock (guest = host + ``clock.seconds``), widened
by the offset's uncertainty at both ends; the run's cleanup span is excluded
so the harness's own commands earn no detection; runs listed in
``failures`` are skipped; a segment with no clock offset cannot place its
windows and is skipped with that reason. Events outside every run window
form one benign capture per segment, labelled as own-lab background.
"""

from __future__ import annotations

import gzip
import json
import shutil
from collections.abc import Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from bastion.attack import AttackData
from bastion.bench.captures import Capture, Window
from bastion.bench.labels import resolve_labels
from bastion.pins import load_pins

CORPUS = "citadel_captures"
HOST = "citadel-lab"


def default_captures_dir() -> Path:
    return Path(str(load_pins()["corpora"][CORPUS]["default_path"]))


def default_capture_names() -> list[str]:
    return [str(name) for name in load_pins()["corpora"][CORPUS]["captures"]]


def _time(value: object) -> datetime:
    return datetime.fromisoformat(str(value))


def _decompress(source: Path, dest: Path) -> Path:
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(source, "rb") as packed, dest.open("wb") as out:
            shutil.copyfileobj(packed, out)
    return dest


def _segments(manifest: dict[str, Any], directory: Path) -> list[tuple[dict[str, Any], Path]]:
    if manifest.get("version", 1) == 1:
        return [(manifest, directory)]
    return [(seg, directory / str(seg["logs"])) for seg in manifest.get("segments", [])]


def citadel_captures(
    captures_dir: Path,
    cache: Path,
    attack: AttackData,
    names: Sequence[str] | None = None,
) -> tuple[list[Capture], list[str]]:
    """Positive captures per run and one benign capture per segment, plus skip notes."""
    license_text = str(load_pins()["corpora"][CORPUS]["license"])
    captures: list[Capture] = []
    skipped: list[str] = []
    for name in names or default_capture_names():
        directory = captures_dir / name
        manifest_path = directory / "capture.json"
        if not manifest_path.is_file():
            skipped.append(f"{name}: no capture.json at {directory}")
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for index, (segment, logs_dir) in enumerate(_segments(manifest, directory)):
            audit_gz = logs_dir / "audit.log.gz"
            if not audit_gz.is_file():
                skipped.append(f"{name}/{index}: no audit.log.gz")
                continue
            clock = segment.get("clock")
            if not isinstance(clock, dict) or "seconds" not in clock:
                skipped.append(f"{name}/{index}: no clock offset, windows cannot be placed")
                continue
            offset = timedelta(seconds=float(clock["seconds"]))
            slack = timedelta(seconds=float(clock.get("uncertainty", 0.0)))
            audit_log = _decompress(audit_gz, cache / "citadel" / name / str(index) / "audit.log")
            failures = set(segment.get("failures", {}))
            run_windows: list[Window] = []
            cleanups: list[Window] = []
            for run in segment.get("runs", []):
                identifier = str(run.get("identifier", ""))
                if identifier in failures:
                    skipped.append(f"{name}/{identifier}: run failed in the lab")
                    continue
                window: Window = (
                    _time(run["started_at"]) + offset - slack,
                    _time(run["finished_at"]) + offset + slack,
                )
                excludes: list[Window] = []
                if run.get("cleanup_started_at") and run.get("cleanup_finished_at"):
                    cleanup: Window = (
                        _time(run["cleanup_started_at"]) + offset,
                        _time(run["cleanup_finished_at"]) + offset,
                    )
                    excludes.append(cleanup)
                    cleanups.append(cleanup)
                run_windows.append(window)
                raw = (str(run.get("technique", "")).upper(),)
                live, notes = resolve_labels(raw, attack)
                captures.append(
                    Capture(
                        id=f"{CORPUS}/{name}/{identifier}",
                        corpus=CORPUS,
                        kind="positive",
                        platform="linux",
                        source_kind="auditd",
                        paths=(audit_log,),
                        techniques=live,
                        raw_labels=raw,
                        label_notes=notes,
                        host=HOST,
                        license=license_text,
                        window=window,
                        exclude_windows=tuple(excludes),
                        notes={"split": "dev", "label": "own-lab capture"},
                    )
                )
            captures.append(
                Capture(
                    id=f"{CORPUS}/{name}/{index}/benign",
                    corpus=CORPUS,
                    kind="benign",
                    platform="linux",
                    source_kind="auditd",
                    paths=(audit_log,),
                    host=f"{HOST}/{name}",
                    license=license_text,
                    exclude_windows=tuple(run_windows + cleanups),
                    notes={"label": "own-lab background outside every run window"},
                )
            )
    return captures, skipped
