"""Tests for jobs (B6): the job table, the worker, the dispatcher and the jobs API."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from bastion.api import create_app
from bastion.bench import runner as bench_runner
from bastion.jobs import CHECK_EVERY, Dispatcher, bench_results_root, pid_alive, run_job
from bastion.jobs import __main__ as job_main
from bastion.jobs import dispatcher as dispatcher_module
from bastion.jobs import worker as worker_module
from bastion.store import NotFoundError, Store, StoreError
from bench_world import World, build_world

REPO = Path(__file__).parent.parent
FIXTURES = REPO / "tests" / "fixtures"
EVTX = REPO / "examples" / "logs" / "sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx"
SCAN = {
    "path": str(EVTX),
    "rules_dir": str(FIXTURES / "rules"),
    "attack_file": str(FIXTURES / "mini_attack.json"),
}


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "ws" / "store.sqlite3")


@pytest.fixture
def world(tmp_path: Path) -> World:
    return build_world(tmp_path)


def bench_params(world: World, **extra: Any) -> dict[str, Any]:
    return {
        "run_name": "job-run",
        "cache_dir": str(world.cache),
        "rules_dir": str(world.rules_dir),
        "attack_file": str(world.attack_file),
        "citadel_dir": str(world.citadel_dir),
        **extra,
    }


# --- the job table ---------------------------------------------------------------------------


def test_job_lifecycle(store: Store) -> None:
    job = store.create_job("scan", {"path": "x"})
    assert (job["status"], job["attempts"], job["cancel_requested"]) == ("queued", 0, False)
    assert store.next_queued() == job["id"]
    assert store.running_job() is None
    assert store.claim_job(job["id"], 4242)
    assert not store.claim_job(job["id"], 4243)
    running = store.running_job()
    assert running is not None and running["worker_pid"] == 4242
    store.set_progress(job["id"], 3, 10, "evtx_baseline", "captures")
    progressed = store.get_job(job["id"])
    assert (progressed["progress_done"], progressed["progress_total"]) == (3, 10)
    assert progressed["progress_label"] == "evtx_baseline"
    store.finish_job(job["id"], "done", result_ref="r")
    assert store.get_job(job["id"])["result_ref"] == "r"
    assert [j["id"] for j in store.list_jobs(["done"])] == [job["id"]]
    assert store.list_jobs(["queued"]) == []
    with pytest.raises(StoreError, match="kind"):
        store.create_job("export", {})
    with pytest.raises(StoreError, match="finishes"):
        store.finish_job(job["id"], "running")
    with pytest.raises(NotFoundError):
        store.get_job("missing")


def test_cancel_queued_running_and_finished(store: Store) -> None:
    queued = store.create_job("scan", {})
    assert store.request_cancel(queued["id"])["status"] == "cancelled"
    running = store.create_job("scan", {})
    store.claim_job(running["id"], 1)
    after = store.request_cancel(running["id"])
    assert (after["status"], after["cancel_requested"]) == ("running", True)
    assert store.cancel_requested(running["id"])
    store.finish_job(running["id"], "cancelled")
    with pytest.raises(StoreError, match="only queued or running"):
        store.request_cancel(running["id"])
    assert not store.cancel_requested("missing")


def test_requeue_orphans(store: Store) -> None:
    gone = store.create_job("bench", {"run_name": "r"})
    store.claim_job(gone["id"], 111)
    live = store.create_job("bench", {"run_name": "s"})
    store.claim_job(live["id"], 222)
    stopping = store.create_job("scan", {})
    store.claim_job(stopping["id"], 333)
    store.request_cancel(stopping["id"])
    moved = store.requeue_orphans(lambda pid: pid == 222)
    assert moved == [gone["id"]]
    again = store.get_job(gone["id"])
    assert (again["status"], again["worker_pid"], again["attempts"]) == ("queued", None, 1)
    assert store.get_job(live["id"])["status"] == "running"
    assert store.get_job(stopping["id"])["status"] == "cancelled"


# --- the worker -------------------------------------------------------------------------------


def test_scan_job_records_the_scan(store: Store) -> None:
    job = store.create_job("scan", SCAN)
    assert run_job(store, job["id"], repo_root=REPO) == "done"
    done = store.get_job(job["id"])
    scan = store.get_scan(done["result_ref"])
    assert scan["logfile"] == str(EVTX)
    assert done["progress_unit"] == "events"
    assert done["progress_done"] == done["progress_total"] == scan["events_scanned"]


def test_scan_job_cancels_between_events(store: Store, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker_module, "CHECK_EVERY", 1)
    job = store.create_job("scan", SCAN)
    store.claim_job(job["id"], os.getpid())
    store.request_cancel(job["id"])
    assert run_job(store, job["id"], repo_root=REPO) == "cancelled"
    assert "stopped after 1 events" in (store.get_job(job["id"])["error"] or "")
    assert store.list_scans() == []
    assert CHECK_EVERY == 1000


def test_failed_job_records_the_error(store: Store) -> None:
    job = store.create_job("scan", {**SCAN, "path": str(REPO / "missing.evtx")})
    assert run_job(store, job["id"], repo_root=REPO) == "failed"
    assert store.get_job(job["id"])["error"]


def test_bench_job_runs_resumes_and_stays_out_of_the_repo(store: Store, world: World) -> None:
    job = store.create_job("bench", bench_params(world))
    assert run_job(store, job["id"], repo_root=world.repo_root) == "done"
    done = store.get_job(job["id"])
    assert done["result_ref"] == "job-run"
    assert done["progress_unit"] == "captures"
    assert done["progress_done"] == done["progress_total"] > 0
    run_dir = bench_results_root(store) / "job-run"
    assert (run_dir / "summary.json").is_file()
    assert not (world.repo_root / "bench" / "results").exists()
    assert store.get_bench_run("job-run")["source_path"] == str(run_dir)

    # Resume: a second job of the same run name reuses every outcome written so far,
    # and a truncated last line (a worker killed mid-write) is skipped, not fatal.
    outcomes = run_dir / "outcomes.jsonl"
    lines = outcomes.read_text(encoding="utf-8").count("\n")
    with outcomes.open("a", encoding="utf-8") as sink:
        sink.write('{"run_key": "eval')
    again = store.create_job("bench", bench_params(world))
    assert run_job(store, again["id"], repo_root=world.repo_root) == "done"
    assert outcomes.read_text(encoding="utf-8").count("\n") == lines + 1
    assert store.get_job(again["id"])["progress_done"] == done["progress_done"]


def test_bench_job_cancels_between_captures(store: Store, world: World) -> None:
    job = store.create_job("bench", bench_params(world, run_name="stop"))
    store.claim_job(job["id"], os.getpid())
    store.request_cancel(job["id"])
    assert run_job(store, job["id"], repo_root=world.repo_root) == "cancelled"
    assert "stopped before capture 1" in (store.get_job(job["id"])["error"] or "")


def test_run_bench_hooks(world: World) -> None:
    seen: list[tuple[int, int, str]] = []
    config = bench_runner.BenchConfig(
        cache=world.cache,
        repo_root=world.repo_root,
        rules_dir=world.rules_dir,
        attack_file=world.attack_file,
        citadel_dir=world.citadel_dir,
        seed=1,
        run_name="hooks",
        suites=("fixtures",),
    )
    bench_runner.run_bench(config, on_capture=lambda d, t, c: seen.append((d, t, c.corpus)))
    assert seen and seen[0][0] == 0 and seen[-1][0] == seen[-1][1] - 1
    with pytest.raises(bench_runner.BenchCancelled):
        bench_runner.run_bench(config, should_stop=lambda: True)


def test_worker_main(store: Store) -> None:
    job = store.create_job("scan", SCAN)
    assert job_main.main(["bastion.jobs", str(store.path), job["id"], str(REPO)]) == 0
    bad = store.create_job("scan", {**SCAN, "path": "missing"})
    assert job_main.main(["bastion.jobs", str(store.path), bad["id"], str(REPO)]) == 1


# --- the dispatcher ---------------------------------------------------------------------------


class FakeProcess:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.code: int | None = None
        self.terminated = False

    def poll(self) -> int | None:
        return self.code

    def terminate(self) -> None:
        self.terminated = True
        self.code = -15

    def wait(self) -> int | None:
        return self.code


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def dispatcher(store: Store, processes: list[FakeProcess], clock: Clock) -> Dispatcher:
    def spawn(argv: list[str]) -> subprocess.Popen[bytes]:
        assert argv[1:3] == ["-m", "bastion.jobs"]
        process = FakeProcess(1000 + len(processes))
        processes.append(process)
        return process  # type: ignore[return-value]

    return Dispatcher(store, REPO, spawn=spawn, alive=lambda pid: False, clock=clock)


def test_dispatcher_runs_one_job_at_a_time(store: Store) -> None:
    processes: list[FakeProcess] = []
    clock = Clock()
    d = dispatcher(store, processes, clock)
    first = store.create_job("scan", {})
    second = store.create_job("scan", {})
    d.tick()
    assert store.get_job(first["id"])["status"] == "running"
    d.tick()
    assert len(processes) == 1 and store.get_job(second["id"])["status"] == "queued"

    # The worker records its own end; the dispatcher then starts the next job.
    store.finish_job(first["id"], "done")
    processes[0].code = 0
    d.tick()
    assert store.get_job(second["id"])["status"] == "running"
    # A worker that dies without recording an end is marked failed.
    processes[1].code = 3
    d.tick()
    failed = store.get_job(second["id"])
    assert failed["status"] == "failed" and "code 3" in (failed["error"] or "")
    d.tick()
    assert len(processes) == 2


def test_dispatcher_terminates_a_worker_that_ignores_cancel(store: Store) -> None:
    processes: list[FakeProcess] = []
    clock = Clock()
    d = dispatcher(store, processes, clock)
    job = store.create_job("bench", {"run_name": "r"})
    d.tick()
    d.tick()  # no cancel requested: nothing happens
    store.request_cancel(job["id"])
    d.tick()
    clock.now = dispatcher_module.CANCEL_GRACE / 2
    d.tick()
    assert not processes[0].terminated
    clock.now = dispatcher_module.CANCEL_GRACE + 1
    d.tick()
    assert processes[0].terminated
    assert store.get_job(job["id"])["status"] == "cancelled"


def test_dispatcher_waits_for_a_job_running_elsewhere_and_recovers(store: Store) -> None:
    processes: list[FakeProcess] = []
    d = dispatcher(store, processes, Clock())
    held = store.create_job("scan", {})
    store.claim_job(held["id"], 999)
    store.create_job("scan", {})
    d.tick()
    assert processes == []
    assert d.recover() == [held["id"]]
    d.tick()
    assert len(processes) == 1


def test_dispatcher_thread_starts_and_stops(store: Store) -> None:
    processes: list[FakeProcess] = []
    d = dispatcher(store, processes, Clock())
    d.poll = 0.01
    d.start()
    d.stop()
    d.stop()


def test_pid_alive() -> None:
    assert pid_alive(os.getpid())
    assert not pid_alive(0)
    assert not pid_alive(2**22 + 12345)


# --- the jobs API -----------------------------------------------------------------------------


def test_jobs_api(store: Store) -> None:
    client = TestClient(create_app(store, port=8765), base_url="http://127.0.0.1:8765")
    scan = client.post("/api/jobs", json={"kind": "scan", "scan": {"path": str(EVTX)}})
    assert scan.status_code == 202
    body = scan.json()
    assert body["status"] == "queued"
    assert body["progress"] == {"done": 0, "total": None, "unit": "", "label": ""}
    missing = client.post("/api/jobs", json={"kind": "scan", "scan": {"path": "nope.evtx"}})
    assert missing.status_code == 400
    assert client.post("/api/jobs", json={"kind": "scan"}).status_code == 400
    smuggled = client.post(
        "/api/jobs", json={"kind": "scan", "scan": {"path": str(EVTX), "rules_dir": "x"}}
    )
    assert "rules_dir" not in smuggled.json()["params"]

    bench = client.post("/api/jobs", json={"kind": "bench"}).json()
    assert bench["params"]["run_name"].startswith("gui-")
    assert bench["params"]["suites"] == ["positives", "regression", "benign", "fixtures"]
    named = client.post("/api/jobs", json={"kind": "bench", "bench": {"run_name": "mine"}})
    assert named.json()["params"]["run_name"] == "mine"
    bad_name = client.post("/api/jobs", json={"kind": "bench", "bench": {"run_name": "../x"}})
    assert bad_name.status_code == 422

    assert len(client.get("/api/jobs").json()) == 4
    assert client.get("/api/jobs", params={"status": "done"}).json() == []
    assert client.get(f"/api/jobs/{body['id']}").json()["id"] == body["id"]
    assert client.get("/api/jobs/none").status_code == 404
    cancelled = client.post(f"/api/jobs/{body['id']}/cancel", json={})
    assert cancelled.json()["status"] == "cancelled"
    assert client.post(f"/api/jobs/{body['id']}/cancel", json={}).status_code == 400
    assert client.post("/api/jobs/none/cancel", json={}).status_code == 404
