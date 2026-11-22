"""Tests for ``bastion gui`` (B6): binds 127.0.0.1, syncs the store, runs the dispatcher."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from bastion import cli
from bastion.api import API_HOST, DEFAULT_PORT
from bastion.api.app import PLACEHOLDER
from bastion.jobs import Dispatcher
from bastion.store import Store

runner = CliRunner()


def test_gui_port_matches_the_api_default() -> None:
    assert cli.GUI_PORT == DEFAULT_PORT


@pytest.mark.parametrize("open_flag", ["--open", "--no-open"])
def test_gui_serves_on_loopback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, open_flag: str
) -> None:
    served: dict[str, Any] = {}
    opened: list[str] = []

    def fake_run(app: FastAPI, *, host: str, port: int, log_level: str) -> None:
        served.update(host=host, port=port)
        client = TestClient(app, base_url=f"http://{host}:{port}")
        served["page"] = client.get("/").text
        served["runs"] = [r["name"] for r in client.get("/api/bench-runs").json()]

    class NowTimer:
        def __init__(self, _delay: float, call: Any, args: tuple[str]) -> None:
            self.call, self.args = call, args

        def start(self) -> None:
            self.call(*self.args)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setattr(threading, "Timer", NowTimer)
    monkeypatch.setattr("webbrowser.open", opened.append)
    started: list[bool] = []
    monkeypatch.setattr(Dispatcher, "start", lambda self: started.append(True))
    store_file = tmp_path / "store.sqlite3"
    # A job a previous stop left running, whose worker is gone, is queued again.
    store = Store(store_file)
    left = store.create_job("scan", {"path": "x"})
    store.claim_job(left["id"], 2**22 + 777)

    result = runner.invoke(
        cli.app, ["gui", "--store", str(store_file), "--port", "8799", open_flag]
    )
    assert result.exit_code == 0, result.output
    assert served["host"] == API_HOST == "127.0.0.1"
    assert served["port"] == 8799
    assert served["page"] == PLACEHOLDER
    assert "b5" in served["runs"]
    assert "queued again" in result.output
    assert opened == (["http://127.0.0.1:8799/"] if open_flag == "--open" else [])
    assert store.get_job(left["id"])["status"] == "queued"
    assert started == [True]


def test_gui_has_no_host_option() -> None:
    result = runner.invoke(cli.app, ["gui", "--host", "0.0.0.0"])
    assert result.exit_code != 0
