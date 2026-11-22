"""The FastAPI application.

Bound to 127.0.0.1 only: :data:`API_HOST` is fixed and ``bastion gui`` offers no host option.
A loopback bind is not enough for an API a browser can reach, so every request is also
checked here (no CORS is configured, so other origins also fail the browser's preflight):

- the ``Host`` header must name this loopback address and port (defeats DNS rebinding);
- a state-changing request must not come from another origin (``Origin`` and
  ``Sec-Fetch-Site`` are checked when present) and must send ``application/json``, which
  an HTML form cannot.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.middleware.base import RequestResponseEndpoint

from bastion import __version__
from bastion.models import Detection, Event, TechniqueRef
from bastion.normalize import to_ecs, to_ocsf
from bastion.normalize.ocsf import detection_finding
from bastion.pins import pin_summary, standards_pin_summary
from bastion.store import NotFoundError, Store, StoreError

API_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
#: The placeholder page served at / until the B7 GUI replaces it.
PLACEHOLDER = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Bastion</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="font-family: 'Segoe UI', 'Noto Sans', system-ui, sans-serif; margin: 2rem;">
<h1>Bastion</h1>
<p>The Bastion GUI is not built yet; it arrives in milestone B7.</p>
<p>The local JSON API is running. Its contract is at
<a href="/api/openapi.json">/api/openapi.json</a>.</p>
</body></html>
"""

TriageStatus = Literal["new", "reviewed", "false_positive", "needs_follow_up"]
DisputeStatus = Literal["open", "reported upstream", "resolved", "withdrawn"]
Level = Literal["informational", "low", "medium", "high", "critical"]
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


# --- schemas ---------------------------------------------------------------------------------


class Health(BaseModel):
    status: Literal["ok"]
    version: str
    store: str
    schema_version: int


class Pins(BaseModel):
    bench: dict[str, str] = Field(description="Pins bench results record (Sigma, ATT&CK, corpora)")
    standards: dict[str, str] = Field(description="B5 standards pins (OCSF, ECS, D3FEND, ...)")


class ScanItem(BaseModel):
    uid: str
    created_at: str
    logfile: str
    platform: str
    events_scanned: int
    rules_loaded: int
    detection_count: int
    sigma_version: str | None
    attack_version: str | None


class ScanDetail(ScanItem):
    summary: dict[str, Any] = Field(
        description="The scan result without its detections: not-evaluable and outside-source "
        "counts, filters, tag resolution, and tagged coverage as covered of total"
    )


class DetectionItem(BaseModel):
    id: int
    scan_uid: str
    finding_uid: str = Field(description="Stable id (rule id and raw record); triage key")
    rule_id: str
    rule_title: str
    level: Level
    host: str | None
    event_time: str | None
    source: str
    techniques: list[dict[str, Any]]
    matched_fields: dict[str, str]
    triage_status: TriageStatus
    triage_note: str


class DetectionPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[DetectionItem]


class DetectionViews(BaseModel):
    raw: str
    ocsf: dict[str, Any] = Field(description="OCSF 1.9.0 view of the event (host profile)")
    ecs: dict[str, Any] = Field(description="ECS 9.5.0 view of the event")


class DetectionDetail(DetectionItem):
    event: dict[str, Any]
    views: DetectionViews


class TriageIn(BaseModel):
    status: TriageStatus
    note: str = ""


class TriageOut(BaseModel):
    finding_uid: str
    status: TriageStatus
    note: str
    updated_at: str


class TriageEntry(BaseModel):
    status: TriageStatus
    note: str
    at: str


class BenchRunItem(BaseModel):
    name: str
    imported_at: str
    source_path: str
    bastion_commit: str | None
    evaluation_source_hash: str | None
    pins: dict[str, str]


class BenchRunDetail(BenchRunItem):
    summary: dict[str, Any] = Field(description="The run's summary.json, as written")


class FilterItem(BaseModel):
    id: str
    title: str
    path: str = Field(description="Path under the filters directory")
    sha256: str
    imported_at: str


class FilterDetail(FilterItem):
    text: str


class TagDispute(BaseModel):
    id: int
    rule: str
    tag_carried: str
    evidence_points_at: str
    capture: str
    status: DisputeStatus
    note: str
    origin: Literal["ledger", "local"]
    created_at: str
    updated_at: str


class TagDisputeIn(BaseModel):
    rule: str = Field(min_length=1)
    tag_carried: str = Field(min_length=1)
    evidence_points_at: str = Field(min_length=1)
    capture: str = ""
    note: str = ""


class TagDisputeUpdate(BaseModel):
    status: DisputeStatus | None = None
    note: str | None = None


JobStatus = Literal["queued", "running", "done", "failed", "cancelled"]


class ScanJobParams(BaseModel):
    path: str = Field(description="Log file to scan, on this machine")
    platform: Literal["windows", "linux"] | None = Field(
        default=None, description="Override source auto-detection"
    )


class BenchJobParams(BaseModel):
    run_name: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9._-]{1,64}$",
        description="Results directory name; kept with the job so a resumed run reuses its "
        "outcomes. Default: gui-<UTC date>-<job id prefix>",
    )
    splits: list[Literal["test", "dev"]] = ["test", "dev"]
    suites: list[Literal["positives", "regression", "benign", "fixtures"]] = [
        "positives",
        "regression",
        "benign",
        "fixtures",
    ]
    max_events_per_capture: int | None = Field(default=None, ge=1)
    baseline_sets: list[str] | None = None
    channels: list[str] | None = None


class JobIn(BaseModel):
    kind: Literal["scan", "bench"]
    scan: ScanJobParams | None = None
    bench: BenchJobParams | None = None


class JobProgress(BaseModel):
    done: int
    total: int | None = Field(description="Unknown (null) while a scan reads its file")
    unit: Literal["", "captures", "events"]
    label: str = Field(description="Current corpus (bench) or file (scan)")


class Job(BaseModel):
    id: str
    kind: Literal["scan", "bench"]
    params: dict[str, Any]
    status: JobStatus
    created_at: str
    started_at: str | None
    finished_at: str | None
    attempts: int = Field(description="Times a worker started it; above 1 after a resume")
    progress: JobProgress
    cancel_requested: bool
    error: str | None
    result_ref: str | None = Field(
        description="Scan uid (scan job) or bench run name (bench job) when done"
    )


class SyncReport(BaseModel):
    bench_runs: list[str]
    filters: list[str]
    tag_disputes: int


class Problem(BaseModel):
    detail: str


_ERRORS: dict[int | str, dict[str, Any]] = {
    404: {"model": Problem, "description": "Not found"},
    400: {"model": Problem, "description": "Refused"},
}


# --- workspace sync --------------------------------------------------------------------------


def sync_repository(store: Store, repo_root: Path) -> SyncReport:
    """Record the repository's bench runs, filter documents and tag dispute ledger."""
    return SyncReport(
        bench_runs=store.import_bench_results(repo_root / "bench" / "results"),
        filters=store.sync_filters(repo_root / "filters"),
        tag_disputes=store.sync_tag_disputes(repo_root / "docs" / "tag-disputes.md"),
    )


# --- application -----------------------------------------------------------------------------


def _local_guard(port: int) -> Any:
    hosts = {f"{API_HOST}:{port}", f"localhost:{port}"}
    origins = {f"http://{host}" for host in hosts}

    async def guard(request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.headers.get("host", "") not in hosts:
            return JSONResponse({"detail": "host not allowed"}, status_code=403)
        if request.method in _WRITE_METHODS:
            origin = request.headers.get("origin")
            site = request.headers.get("sec-fetch-site")
            if (origin is not None and origin not in origins) or site not in (
                None,
                "same-origin",
                "none",
            ):
                return JSONResponse({"detail": "cross-origin write refused"}, status_code=403)
            kind = request.headers.get("content-type", "").split(";")[0].strip().lower()
            if kind != "application/json":
                return JSONResponse(
                    {"detail": "writes must send application/json"}, status_code=415
                )
        return await call_next(request)

    return guard


def create_app(store: Store, *, port: int = DEFAULT_PORT, repo_root: Path | None = None) -> FastAPI:
    """The API over ``store``. ``repo_root`` enables ``POST /api/sync``."""
    app = FastAPI(
        title="Bastion local API",
        version=__version__,
        description=(
            "Local JSON API of Bastion, served on 127.0.0.1 only. Records scans, detections, "
            "bench run summaries, triage state, filter documents and tag disputes. Nothing "
            "here changes detection logic: filter documents and disputes are records; the "
            "engine reads filters from the filters directory. Long scans and bench runs are "
            "jobs: queued, run one at a time, cancellable, and resumed after a restart."
        ),
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.middleware("http")(_local_guard(port))

    def found(call: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return call(*args, **kwargs)
        except NotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        except StoreError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def placeholder() -> str:
        return PLACEHOLDER

    @app.get("/api/health", response_model=Health, tags=["meta"])
    def health() -> Health:
        return Health(
            status="ok",
            version=__version__,
            store=str(store.path),
            schema_version=store.schema_version(),
        )

    @app.get("/api/pins", response_model=Pins, tags=["meta"])
    def pins() -> Pins:
        return Pins(bench=pin_summary(), standards=standards_pin_summary())

    @app.post("/api/sync", response_model=SyncReport, tags=["meta"], responses=_ERRORS)
    def sync() -> SyncReport:
        if repo_root is None:
            raise HTTPException(400, "no repository root configured")
        return sync_repository(store, repo_root)

    @app.get("/api/scans", response_model=list[ScanItem], tags=["scans"])
    def scans() -> list[dict[str, Any]]:
        return store.list_scans()

    @app.get("/api/scans/{uid}", response_model=ScanDetail, tags=["scans"], responses=_ERRORS)
    def scan(uid: str) -> dict[str, Any]:
        return dict(found(store.get_scan, uid))

    @app.delete("/api/scans/{uid}", status_code=204, tags=["scans"], responses=_ERRORS)
    def delete_scan(uid: str) -> Response:
        found(store.delete_scan, uid)
        return Response(status_code=204)

    @app.get("/api/detections", response_model=DetectionPage, tags=["detections"])
    def detections(
        scan_uid: str | None = None,
        level: Annotated[list[Level] | None, Query()] = None,
        rule_id: str | None = None,
        host: str | None = None,
        triage: Annotated[list[TriageStatus] | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> DetectionPage:
        total, items = store.list_detections(
            scan_uid=scan_uid,
            level=level or (),
            rule_id=rule_id,
            host=host,
            triage=triage or (),
            limit=limit,
            offset=offset,
        )
        return DetectionPage(
            total=total,
            limit=limit,
            offset=offset,
            items=[DetectionItem.model_validate(item) for item in items],
        )

    @app.get(
        "/api/detections/{detection_id}",
        response_model=DetectionDetail,
        tags=["detections"],
        responses=_ERRORS,
    )
    def detection(detection_id: int) -> DetectionDetail:
        record = found(store.get_detection, detection_id)
        event = Event.model_validate(record["event"])
        return DetectionDetail.model_validate(
            {
                **record,
                "views": {"raw": event.raw, "ocsf": to_ocsf(event), "ecs": to_ecs(event)},
            }
        )

    @app.get(
        "/api/detections/{detection_id}/finding",
        tags=["detections"],
        responses=_ERRORS,
        summary="The detection as an OCSF 1.9.0 Detection Finding",
    )
    def finding(detection_id: int) -> dict[str, Any]:
        record = found(store.get_detection, detection_id)
        scan = found(store.get_scan, record["scan_uid"])
        detection = Detection(
            rule_id=record["rule_id"],
            rule_title=record["rule_title"],
            level=record["level"],
            event=Event.model_validate(record["event"]),
            matched_fields=record["matched_fields"],
            techniques=[TechniqueRef.model_validate(t) for t in record["techniques"]],
        )
        return detection_finding(
            detection,
            attack_version=scan["attack_version"],
            sigma_version=scan["sigma_version"],
        )

    @app.put(
        "/api/triage/{finding_uid}", response_model=TriageOut, tags=["triage"], responses=_ERRORS
    )
    def set_triage(finding_uid: str, body: TriageIn) -> dict[str, Any]:
        return dict(found(store.set_triage, finding_uid, body.status, body.note))

    @app.get("/api/triage/{finding_uid}/history", response_model=list[TriageEntry], tags=["triage"])
    def triage_history(finding_uid: str) -> list[dict[str, Any]]:
        return store.triage_history(finding_uid)

    @app.get("/api/bench-runs", response_model=list[BenchRunItem], tags=["bench"])
    def bench_runs() -> list[dict[str, Any]]:
        return store.list_bench_runs()

    @app.get(
        "/api/bench-runs/{name}", response_model=BenchRunDetail, tags=["bench"], responses=_ERRORS
    )
    def bench_run(name: str) -> dict[str, Any]:
        return dict(found(store.get_bench_run, name))

    @app.get("/api/filters", response_model=list[FilterItem], tags=["filters"])
    def filters() -> list[dict[str, Any]]:
        return store.list_filters()

    @app.get("/api/filters/{fid}", response_model=FilterDetail, tags=["filters"], responses=_ERRORS)
    def filter_document(fid: str) -> dict[str, Any]:
        return dict(found(store.get_filter, fid))

    @app.get("/api/tag-disputes", response_model=list[TagDispute], tags=["tag disputes"])
    def tag_disputes() -> list[dict[str, Any]]:
        return store.list_tag_disputes()

    @app.post(
        "/api/tag-disputes",
        response_model=TagDispute,
        status_code=201,
        tags=["tag disputes"],
        responses=_ERRORS,
    )
    def add_tag_dispute(body: TagDisputeIn) -> dict[str, Any]:
        return dict(found(store.add_tag_dispute, **body.model_dump()))

    @app.patch(
        "/api/tag-disputes/{dispute_id}",
        response_model=TagDispute,
        tags=["tag disputes"],
        responses=_ERRORS,
    )
    def update_tag_dispute(dispute_id: int, body: TagDisputeUpdate) -> dict[str, Any]:
        return dict(found(store.update_tag_dispute, dispute_id, status=body.status, note=body.note))

    @app.get("/api/jobs", response_model=list[Job], tags=["jobs"])
    def jobs(status: Annotated[list[JobStatus] | None, Query()] = None) -> list[Job]:
        return [_job(j) for j in store.list_jobs(status or ())]

    @app.post("/api/jobs", response_model=Job, status_code=202, tags=["jobs"], responses=_ERRORS)
    def create_job(body: JobIn) -> Job:
        params: dict[str, Any]
        if body.kind == "scan":
            if body.scan is None or not Path(body.scan.path).is_file():
                raise HTTPException(400, "a scan job needs scan.path naming an existing file")
            params = body.scan.model_dump()
        else:
            bench = body.bench or BenchJobParams()
            params = bench.model_dump()
            if not params.get("run_name"):
                stamp = datetime.now(UTC).strftime("%Y-%m-%d")
                params["run_name"] = f"gui-{stamp}-{uuid.uuid4().hex[:8]}"
        return _job(store.create_job(body.kind, params))

    @app.get("/api/jobs/{job_id}", response_model=Job, tags=["jobs"], responses=_ERRORS)
    def job(job_id: str) -> Job:
        return _job(found(store.get_job, job_id))

    @app.post("/api/jobs/{job_id}/cancel", response_model=Job, tags=["jobs"], responses=_ERRORS)
    def cancel_job(job_id: str) -> Job:
        return _job(found(store.request_cancel, job_id))

    return app


def _job(record: dict[str, Any]) -> Job:
    return Job(
        id=record["id"],
        kind=record["kind"],
        params=record["params"],
        status=record["status"],
        created_at=record["created_at"],
        started_at=record["started_at"],
        finished_at=record["finished_at"],
        attempts=record["attempts"],
        progress=JobProgress(
            done=record["progress_done"],
            total=record["progress_total"],
            unit=record["progress_unit"],
            label=record["progress_label"],
        ),
        cancel_requested=record["cancel_requested"],
        error=record["error"],
        result_ref=record["result_ref"],
    )


def openapi_document(app: FastAPI) -> str:
    """The OpenAPI document as committed in ``docs/api/openapi.json``."""
    return json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"
