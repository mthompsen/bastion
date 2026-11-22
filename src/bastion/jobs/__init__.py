"""Jobs for long scans and bench runs (B6).

A job is a row in the store: ``queued``, ``running``, ``done``, ``failed`` or ``cancelled``,
with progress (done of total, in captures for a bench run and events for a scan, and the
current corpus or file). The :class:`Dispatcher` in the API process runs one job at a time,
each in its own worker process (``python -m bastion.jobs STORE JOB``), so a long bench run
never blocks the API and a cancel can always end it.

Cancel is cooperative: the worker checks between captures (bench) or every
:data:`CHECK_EVERY` events (scan); a worker that does not stop within the grace period is
terminated. Resume after restart: a ``running`` job whose worker is gone (the API or the
machine stopped) goes back to ``queued``. A bench job keeps its run name, so the rerun
reuses every capture outcome already written; a scan job starts its file again.
"""

from bastion.jobs.dispatcher import Dispatcher, pid_alive
from bastion.jobs.worker import CHECK_EVERY, JobCancelled, bench_results_root, run_job

__all__ = [
    "CHECK_EVERY",
    "Dispatcher",
    "JobCancelled",
    "bench_results_root",
    "pid_alive",
    "run_job",
]
