"""Tests for the local API (B6): routes, the loopback guard, and the committed contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from bastion.api import API_HOST, create_app, openapi_document
from bastion.api.app import PLACEHOLDER, sync_repository
from bastion.store import Store
from test_store import add

REPO = Path(__file__).parent.parent
PORT = 8765
BASE = f"http://{API_HOST}:{PORT}"


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "store.sqlite3")


@pytest.fixture
def client(store: Store) -> TestClient:
    return TestClient(create_app(store, port=PORT, repo_root=REPO), base_url=BASE)


def test_committed_openapi_matches_code(store: Store) -> None:
    committed = (REPO / "docs" / "api" / "openapi.json").read_text(encoding="utf-8")
    assert committed == openapi_document(create_app(store)), (
        "docs/api/openapi.json is stale; run python scripts/build_openapi.py"
    )


def test_build_openapi_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(REPO / "scripts"))
    import build_openapi

    out = tmp_path / "openapi.json"
    assert build_openapi.main(["x", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["info"]["title"] == "Bastion local API"


def test_placeholder_health_and_pins(client: TestClient, store: Store) -> None:
    page = client.get("/")
    assert page.status_code == 200
    assert page.text == PLACEHOLDER
    health = client.get("/api/health").json()
    assert health["status"] == "ok"
    assert health["store"] == str(store.path)
    pins = client.get("/api/pins").json()
    assert pins["bench"]["attack"] == "20.1"
    assert "ocsf" in pins["standards"]
    assert client.get("/docs").status_code == 404


def test_host_guard(store: Store) -> None:
    app = create_app(store, port=PORT)
    for host in ("evil.example", f"{API_HOST}:9999", "attacker.test:8765"):
        response = TestClient(app, base_url=f"http://{host}").get("/api/health")
        assert response.status_code == 403, host
    assert TestClient(app, base_url=f"http://localhost:{PORT}").get("/").status_code == 200


def test_write_guard(client: TestClient, store: Store) -> None:
    add(store)
    finding = store.list_detections()[1][0]["finding_uid"]
    body = {"status": "reviewed"}
    url = f"/api/triage/{finding}"
    assert client.put(url, json=body, headers={"Origin": "http://evil.example"}).status_code == 403
    assert client.put(url, json=body, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    form = client.put(url, content="status=reviewed", headers={"Content-Type": "text/plain"})
    assert form.status_code == 415
    ok = client.put(
        url,
        json=body,
        headers={"Origin": f"http://localhost:{PORT}", "Sec-Fetch-Site": "same-origin"},
    )
    assert ok.status_code == 200
    # No CORS: a preflight from another origin gets no allow header.
    preflight = client.options(
        url, headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "PUT"}
    )
    assert "access-control-allow-origin" not in preflight.headers


def test_scans_detections_and_triage(client: TestClient, store: Store) -> None:
    uid = add(store)
    assert [s["uid"] for s in client.get("/api/scans").json()] == [uid]
    assert client.get(f"/api/scans/{uid}").json()["summary"]["coverage"]["total"] > 0
    assert client.get("/api/scans/nope").status_code == 404

    page = client.get("/api/detections", params={"scan_uid": uid, "limit": 5}).json()
    assert page["total"] >= 1
    item = page["items"][0]
    assert item["triage_status"] == "new"
    detail = client.get(f"/api/detections/{item['id']}").json()
    assert detail["views"]["ocsf"]["metadata"]["version"] == "1.9.0"
    assert detail["views"]["ecs"]["ecs"]["version"] == "9.5.0"
    assert detail["views"]["raw"] == detail["event"]["raw"]
    finding = client.get(f"/api/detections/{item['id']}/finding").json()
    assert finding["class_uid"] == 2004
    assert finding["finding_info"]["analytic"]["uid"] == item["rule_id"]
    assert client.get("/api/detections/99999").status_code == 404
    assert client.get("/api/detections/99999/finding").status_code == 404
    assert client.get("/api/detections", params={"limit": 0}).status_code == 422
    assert client.get("/api/detections", params={"level": "severe"}).status_code == 422

    put = client.put(
        f"/api/triage/{item['finding_uid']}", json={"status": "needs_follow_up", "note": "n"}
    )
    assert put.json()["status"] == "needs_follow_up"
    assert client.put("/api/triage/" + "0" * 32, json={"status": "reviewed"}).status_code == 404
    assert client.put(f"/api/triage/{item['finding_uid']}", json={"status": "x"}).status_code == 422
    history = client.get(f"/api/triage/{item['finding_uid']}/history").json()
    assert [h["status"] for h in history] == ["needs_follow_up"]
    filtered = client.get("/api/detections", params={"triage": ["needs_follow_up"]}).json()
    assert filtered["total"] == 1
    for name in ("level", "rule_id", "host"):
        value = item[name] if name != "level" else item["level"]
        assert client.get("/api/detections", params={name: value}).json()["total"] >= 1

    assert (
        client.delete(f"/api/scans/{uid}", headers={"Content-Type": "application/json"}).status_code
        == 204
    )
    assert (
        client.delete(f"/api/scans/{uid}", headers={"Content-Type": "application/json"}).status_code
        == 404
    )


def test_sync_bench_filters_disputes(client: TestClient, store: Store) -> None:
    report = client.post("/api/sync", json={}).json()
    assert "b5" in report["bench_runs"]
    assert report["tag_disputes"] == 4
    runs = client.get("/api/bench-runs").json()
    assert any(r["name"] == "b5" for r in runs)
    assert client.get("/api/bench-runs/b5").json()["summary"]["run"] == "b5"
    assert client.get("/api/bench-runs/none").status_code == 404

    filters = client.get("/api/filters").json()
    assert filters == [] or "text" in client.get(f"/api/filters/{filters[0]['id']}").json()
    assert client.get("/api/filters/none").status_code == 404

    disputes = client.get("/api/tag-disputes").json()
    assert len(disputes) == 4
    new = client.post(
        "/api/tag-disputes",
        json={"rule": "R", "tag_carried": "T1059", "evidence_points_at": "T1218"},
    )
    assert new.status_code == 201
    dispute = new.json()
    assert dispute["origin"] == "local"
    again = client.post(
        "/api/tag-disputes",
        json={"rule": "R", "tag_carried": "T1059", "evidence_points_at": "T1218"},
    )
    assert again.status_code == 400
    patched = client.patch(f"/api/tag-disputes/{dispute['id']}", json={"status": "withdrawn"})
    assert patched.json()["status"] == "withdrawn"
    assert client.patch("/api/tag-disputes/999", json={"note": "x"}).status_code == 404
    bad = client.patch(f"/api/tag-disputes/{dispute['id']}", json={"status": "closed"})
    assert bad.status_code == 422


def test_sync_without_repo(store: Store) -> None:
    client = TestClient(create_app(store, port=PORT), base_url=BASE)
    assert client.post("/api/sync", json={}).status_code == 400
    assert sync_repository(store, REPO).tag_disputes == 4
