"""Worker entry point: ``python -m bastion.jobs STORE JOB REPO_ROOT``."""

from __future__ import annotations

import sys
from pathlib import Path

from bastion.jobs.worker import run_job
from bastion.store import Store


def main(argv: list[str]) -> int:
    store_path, job_id, repo_root = argv[1:4]
    status = run_job(Store(Path(store_path)), job_id, repo_root=Path(repo_root))
    return 0 if status == "done" else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv))
