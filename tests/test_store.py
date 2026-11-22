"""Tests for the local SQLite store (B6)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from bastion.attack import load_attack
from bastion.coverage import summarize_coverage
from bastion.engine import scan
from bastion.models import Event, ScanResult
from bastion.normalize.ocsf import finding_uid
from bastion.sigma.loader import load_rules
from bastion.store import SCHEMA_VERSION, STORE_ENV, Store, StoreError, default_store_path
from bastion.store.db import parse_dispute_ledger

FIXTURES = Path(__file__).parent / "fixtures"
REPO = Path(__file__).parent.parent
ATTACK = load_attack(FIXTURES / "mini_attack.json")
RULES = load_rules(FIXTURES / "rules")

PS_EVENT = Event(
    platform="windows",
    source="sample.evtx",
    fields={
        "EventID": 1,
        "Computer": "ws01.corp.internal",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
    },
    raw="<Event><EventData>powershell -enc evil</EventData></Event>",
)


def scan_result() -> ScanResult:
    outcome = scan([PS_EVENT], RULES, ATTACK)
    summary = summarize_coverage(RULES, ATTACK)
    return ScanResult(
        detections=outcome.detections,
        events_scanned=outcome.events_scanned,
        rules_loaded=len(RULES),
        coverage=summary.entries,
        not_evaluable={"rule-x": 2},
    )


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "ws" / "store.sqlite3")


def add(store: Store) -> str:
    return store.add_scan(
        scan_result(),
        logfile="sample.evtx",
        platform="windows",
        sigma_version="r2026-07-01",
        attack_version="20.1",
    )


def test_default_store_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(STORE_ENV, str(tmp_path / "x.sqlite3"))
    assert default_store_path() == tmp_path / "x.sqlite3"
    monkeypatch.delenv(STORE_ENV)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert default_store_path("nt") == tmp_path / "bastion" / "store.sqlite3"
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert default_store_path("posix") == tmp_path / "xdg" / "bastion" / "store.sqlite3"
    monkeypatch.delenv("XDG_DATA_HOME")
    assert default_store_path("posix") == Path.home() / ".local/share/bastion/store.sqlite3"


def test_schema_wal_and_reopen(store: Store) -> None:
    assert store.schema_version() == SCHEMA_VERSION
    with sqlite3.connect(store.path) as db:
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert Store(store.path).schema_version() == SCHEMA_VERSION


def test_newer_schema_refused(store: Store) -> None:
    with sqlite3.connect(store.path) as db:
        db.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
    with pytest.raises(StoreError, match="schema"):
        Store(store.path)


def test_scan_and_detections(store: Store) -> None:
    uid = add(store)
    scans = store.list_scans()
    assert [s["uid"] for s in scans] == [uid]
    assert scans[0]["detection_count"] >= 1
    record = store.get_scan(uid)
    assert record["summary"]["not_evaluable"] == {"rule-x": 2}
    assert record["summary"]["coverage"]["total"] > 0
    assert "detections" not in record["summary"]

    total, page = store.list_detections(scan_uid=uid)
    assert total == scans[0]["detection_count"]
    first = page[0]
    assert first["host"] == "ws01.corp.internal"
    assert first["triage_status"] == "new"
    assert first["finding_uid"] == finding_uid(scan_result().detections[0])
    detail = store.get_detection(first["id"])
    assert detail["event"]["raw"] == PS_EVENT.raw
    assert Event.model_validate(detail["event"]).fields["Image"] == PS_EVENT.fields["Image"]

    assert store.list_detections(level=["critical"])[0] in (0, total)
    assert store.list_detections(rule_id="nope")[0] == 0
    assert store.list_detections(host="other")[0] == 0
    assert store.list_detections(limit=1, offset=total)[1] == []
    with pytest.raises(StoreError):
        store.get_scan("missing")
    with pytest.raises(StoreError):
        store.get_detection(10_000)


def test_triage_survives_rescan_and_delete(store: Store) -> None:
    uid = add(store)
    finding = store.list_detections(scan_uid=uid)[1][0]["finding_uid"]
    store.set_triage(finding, "needs_follow_up", "check the parent")
    store.set_triage(finding, "false_positive", "admin script")
    assert [h["status"] for h in store.triage_history(finding)] == [
        "needs_follow_up",
        "false_positive",
    ]
    assert store.list_detections(triage=["false_positive"])[0] >= 1
    assert all(d["finding_uid"] != finding for d in store.list_detections(triage=["new"])[1])

    store.delete_scan(uid)
    again = add(store)
    row = next(d for d in store.list_detections(scan_uid=again)[1] if d["finding_uid"] == finding)
    assert (row["triage_status"], row["triage_note"]) == ("false_positive", "admin script")
    with pytest.raises(StoreError):
        store.delete_scan(uid)


def test_triage_refusals(store: Store) -> None:
    add(store)
    with pytest.raises(StoreError, match="status"):
        store.set_triage("x", "closed")
    with pytest.raises(StoreError, match="no detection"):
        store.set_triage("0" * 32, "reviewed")


def test_bench_runs(store: Store, tmp_path: Path) -> None:
    root = tmp_path / "results"
    (root / "r1").mkdir(parents=True)
    (root / "r1" / "summary.json").write_text(
        json.dumps(
            {
                "run": "r1",
                "bastion": {"commit": "abc", "evaluation_source_hash": "h"},
                "pins": {"sigma": "r2026-07-01"},
            }
        ),
        encoding="utf-8",
    )
    (root / "empty").mkdir()
    assert store.import_bench_results(root) == ["r1"]
    assert store.import_bench_results(tmp_path / "none") == []
    runs = store.list_bench_runs()
    assert runs[0]["pins"] == {"sigma": "r2026-07-01"}
    assert runs[0]["bastion_commit"] == "abc"
    assert store.get_bench_run("r1")["summary"]["run"] == "r1"
    assert store.import_bench_run(root / "r1") == "r1"
    assert len(store.list_bench_runs()) == 1
    with pytest.raises(StoreError):
        store.import_bench_run(root / "empty")
    with pytest.raises(StoreError):
        store.get_bench_run("r2")


def test_committed_bench_run_records(store: Store) -> None:
    names = store.import_bench_results(REPO / "bench" / "results")
    assert "b5" in names
    assert store.get_bench_run("b5")["pins"]["attack"] == "20.1"


def test_filter_documents(store: Store, tmp_path: Path) -> None:
    assert store.sync_filters(REPO / "filters") == [
        f["id"] for f in sorted(store.list_filters(), key=lambda f: f["id"])
    ]
    one = store.list_filters()[0]
    assert one["path"].startswith("linux/")
    assert "filter:" in store.get_filter(one["id"])["text"]

    other = tmp_path / "filters"
    other.mkdir()
    (other / "not-a-filter.yml").write_text("title: rule\ndetection: {}\n", encoding="utf-8")
    (other / "f.yml").write_text("id: f1\ntitle: F\nfilter: {}\n", encoding="utf-8")
    assert store.sync_filters(other) == ["f1"]
    assert [f["id"] for f in store.list_filters()] == ["f1"]
    assert store.sync_filters(tmp_path / "missing") == []
    with pytest.raises(StoreError):
        store.get_filter("f1")


def test_dispute_ledger_parse() -> None:
    entries = parse_dispute_ledger(REPO / "docs" / "tag-disputes.md")
    assert len(entries) == 4
    assert entries[0]["capture"].endswith(".evtx")
    assert {e["status"] for e in entries} <= {"open", "reported upstream", "resolved", "withdrawn"}


def test_tag_disputes(store: Store, tmp_path: Path) -> None:
    assert store.sync_tag_disputes(REPO / "docs" / "tag-disputes.md") == 4
    assert store.sync_tag_disputes(REPO / "docs" / "tag-disputes.md") == 4
    assert len(store.list_tag_disputes()) == 4
    assert {d["origin"] for d in store.list_tag_disputes()} == {"ledger"}

    local = store.add_tag_dispute(
        rule="Some Rule", tag_carried="T1059", evidence_points_at="T1218", note="one capture"
    )
    assert (local["origin"], local["status"]) == ("local", "open")
    with pytest.raises(StoreError, match="exists"):
        store.add_tag_dispute(rule="Some Rule", tag_carried="T1059", evidence_points_at="x")
    moved = store.update_tag_dispute(local["id"], status="withdrawn")
    assert (moved["status"], moved["note"]) == ("withdrawn", "one capture")
    assert store.update_tag_dispute(local["id"], note="n")["status"] == "withdrawn"
    with pytest.raises(StoreError, match="status"):
        store.update_tag_dispute(local["id"], status="closed")
    with pytest.raises(StoreError):
        store.get_tag_dispute(999)

    ledger = tmp_path / "ledger.md"
    ledger.write_text(
        "intro\n\n| Rule | Tag carried | Evidence points at | Capture | Status |\n"
        "|:-|:-|:-|:-|:-|\n| R | T1 | T2 | `c.evtx` (labelled T2) | resolved |\n"
        "| short | row |\n| R2 | T3 | T4 |  | someday |\n\nafter\n| x | y | z | w | open |\n",
        encoding="utf-8",
    )
    parsed = parse_dispute_ledger(ledger)
    assert [(e["rule"], e["capture"], e["status"]) for e in parsed] == [
        ("R", "c.evtx", "resolved"),
        ("R2", "", "open"),
    ]
    assert store.sync_tag_disputes(tmp_path / "missing.md") == 0
