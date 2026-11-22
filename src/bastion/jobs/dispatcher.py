"""Start queued jobs one at a time, each in its own worker process, and watch them."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

from bastion.store import Store

#: Seconds a worker has to stop after a cancel request before it is terminated.
CANCEL_GRACE = 30.0

Spawn = Callable[[list[str]], "subprocess.Popen[bytes]"]


def pid_alive(pid: int) -> bool:
    """Is process ``pid`` running? (Never signals it: on Windows ``os.kill`` terminates.)"""
    if pid <= 0:
        return False
    if os.name == "nt":
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined,unused-ignore]
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        try:
            ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        finally:
            kernel32.CloseHandle(handle)
        return bool(ok) and code.value == 259  # STILL_ACTIVE
    try:  # pragma: no cover - POSIX branch, exercised on Linux CI
        os.kill(pid, 0)
    except ProcessLookupError:  # pragma: no cover
        return False
    except PermissionError:  # pragma: no cover
        return True
    return True  # pragma: no cover


class Dispatcher:
    """Runs the job queue of ``store``: one job at a time, one worker process per job."""

    def __init__(
        self,
        store: Store,
        repo_root: Path,
        *,
        poll: float = 1.0,
        spawn: Spawn | None = None,
        alive: Callable[[int], bool] = pid_alive,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.store = store
        self.repo_root = repo_root
        self.poll = poll
        self.spawn: Spawn = spawn or (lambda argv: subprocess.Popen(argv, cwd=repo_root))
        self.alive = alive
        self.clock = clock
        self.process: subprocess.Popen[bytes] | None = None
        self.job_id: str | None = None
        self.cancel_seen_at: float | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def recover(self) -> list[str]:
        """Jobs left ``running`` by a worker that is gone go back to ``queued``."""
        return self.store.requeue_orphans(self.alive)

    def tick(self) -> None:
        """One step: watch the running worker, or start the next queued job."""
        if self.process is not None and self.job_id is not None:
            code = self.process.poll()
            if code is None:
                self._enforce_cancel()
                return
            job = self.store.get_job(self.job_id)
            if job["status"] == "running":
                self.store.finish_job(
                    self.job_id, "failed", error=f"worker exited with code {code} unrecorded"
                )
            self.process = None
            self.job_id = None
            self.cancel_seen_at = None
        if self.store.running_job() is not None:
            return  # another dispatcher's worker (or one being recovered) holds the queue
        job_id = self.store.next_queued()
        if job_id is None:
            return
        argv = [
            sys.executable,
            "-m",
            "bastion.jobs",
            str(self.store.path),
            job_id,
            str(self.repo_root),
        ]
        process = self.spawn(argv)
        if not self.store.claim_job(job_id, process.pid):
            process.terminate()  # pragma: no cover - lost a race with another dispatcher
            return  # pragma: no cover
        self.process = process
        self.job_id = job_id

    def _enforce_cancel(self) -> None:
        assert self.process is not None and self.job_id is not None
        if not self.store.cancel_requested(self.job_id):
            return
        if self.cancel_seen_at is None:
            self.cancel_seen_at = self.clock()
        elif self.clock() - self.cancel_seen_at > CANCEL_GRACE:
            self.process.terminate()
            self.process.wait()
            self.store.finish_job(
                self.job_id, "cancelled", error="terminated: did not stop within the grace"
            )
            self.process = None
            self.job_id = None
            self.cancel_seen_at = None

    def _loop(self) -> None:
        self.recover()
        while not self._stop.is_set():
            self.tick()
            self._stop.wait(self.poll)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="bastion-jobs", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop dispatching. A running worker is left to finish; on the next start a job
        whose worker is gone is queued again (resume after restart)."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
