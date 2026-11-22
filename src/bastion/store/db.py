"""The SQLite store itself: schema, migrations and typed accessors."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from bastion.models import Detection, ScanResult
from bastion.normalize.ocsf import finding_uid

STORE_ENV = "BASTION_STORE"

#: Triage states (START_PROMPT 9.3, Detections). ``new`` is the state of a detection no one
#: has triaged; it is never written as a row of its own until someone sets it.
TRIAGE_STATUSES = ("new", "reviewed", "false_positive", "needs_follow_up")
#: Tag dispute states, as in ``docs/tag-disputes.md``.
DISPUTE_STATUSES = ("open", "reported upstream", "resolved", "withdrawn")

_V1 = """
CREATE TABLE scans (
    uid TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    logfile TEXT NOT NULL,
    platform TEXT NOT NULL,
    events_scanned INTEGER NOT NULL,
    rules_loaded INTEGER NOT NULL,
    detection_count INTEGER NOT NULL,
    sigma_version TEXT,
    attack_version TEXT,
    summary TEXT NOT NULL
);
CREATE TABLE detections (
    id INTEGER PRIMARY KEY,
    scan_uid TEXT NOT NULL REFERENCES scans(uid) ON DELETE CASCADE,
    finding_uid TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_title TEXT NOT NULL,
    level TEXT NOT NULL,
    host TEXT,
    event_time TEXT,
    source TEXT NOT NULL,
    techniques TEXT NOT NULL,
    matched_fields TEXT NOT NULL,
    event TEXT NOT NULL
);
CREATE INDEX detections_scan ON detections(scan_uid);
CREATE INDEX detections_finding ON detections(finding_uid);
CREATE INDEX detections_rule ON detections(rule_id);
CREATE TABLE triage (
    finding_uid TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('new', 'reviewed', 'false_positive',
                                           'needs_follow_up')),
    note TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE TABLE triage_history (
    id INTEGER PRIMARY KEY,
    finding_uid TEXT NOT NULL,
    status TEXT NOT NULL,
    note TEXT NOT NULL,
    at TEXT NOT NULL
);
CREATE INDEX triage_history_finding ON triage_history(finding_uid);
CREATE TABLE bench_runs (
    name TEXT PRIMARY KEY,
    imported_at TEXT NOT NULL,
    source_path TEXT NOT NULL,
    bastion_commit TEXT,
    evaluation_source_hash TEXT,
    pins TEXT NOT NULL,
    summary TEXT NOT NULL
);
CREATE TABLE filter_documents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    text TEXT NOT NULL,
    imported_at TEXT NOT NULL
);
CREATE TABLE tag_disputes (
    id INTEGER PRIMARY KEY,
    rule TEXT NOT NULL,
    tag_carried TEXT NOT NULL,
    evidence_points_at TEXT NOT NULL,
    capture TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('open', 'reported upstream', 'resolved',
                                           'withdrawn')),
    note TEXT NOT NULL DEFAULT '',
    origin TEXT NOT NULL CHECK (origin IN ('ledger', 'local')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (rule, tag_carried)
);
"""

#: Migration n takes the store from user_version n to n + 1.
MIGRATIONS: tuple[str, ...] = (_V1,)
SCHEMA_VERSION = len(MIGRATIONS)


class StoreError(ValueError):
    """A request the store refuses (invalid state or value)."""


class NotFoundError(StoreError):
    """The record a request names does not exist."""


def default_store_path(os_name: str | None = None) -> Path:
    """One store per workspace, outside the repository.

    ``%LOCALAPPDATA%\\bastion\\store.sqlite3`` on Windows, ``$XDG_DATA_HOME/bastion`` (default
    ``~/.local/share``) elsewhere; ``BASTION_STORE`` names another file.
    """
    override = os.environ.get(STORE_ENV)
    if override:
        return Path(override)
    if (os_name or os.name) == "nt" and (local := os.environ.get("LOCALAPPDATA")):
        return Path(local) / "bastion" / "store.sqlite3"
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "bastion" / "store.sqlite3"


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _host(detection: Detection) -> str | None:
    fields = detection.event.fields
    for name in ("Computer", "hostname", "host", "node"):
        value = fields.get(name)
        if value not in (None, ""):
            return str(value)
    return None


class Store:
    """One SQLite file. Every method opens its own short transaction, so a store object may
    be shared by the API's threads and a job worker process may write the same file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            self._migrate(db)

    # --- connection and schema ------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=30000")
        return db

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        db = self._connect()
        try:
            yield db
        finally:
            db.close()

    def _migrate(self, db: sqlite3.Connection) -> None:
        version = int(db.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            raise StoreError(
                f"store {self.path} has schema {version}; this Bastion knows {SCHEMA_VERSION}"
            )
        for index in range(version, SCHEMA_VERSION):
            db.execute("BEGIN IMMEDIATE")
            for statement in _statements(MIGRATIONS[index]):
                db.execute(statement)
            db.execute(f"PRAGMA user_version={index + 1}")
            db.execute("COMMIT")

    def schema_version(self) -> int:
        with self._read() as db:
            return int(db.execute("PRAGMA user_version").fetchone()[0])

    # --- scans and detections -------------------------------------------------------------

    def add_scan(
        self,
        result: ScanResult,
        *,
        logfile: str,
        platform: str,
        sigma_version: str | None,
        attack_version: str | None,
    ) -> str:
        """Record a scan and its detections; returns the scan uid."""
        uid = uuid.uuid4().hex
        covered = sum(1 for entry in result.coverage if entry.covered)
        summary = result.model_dump(mode="json", exclude={"detections", "coverage"})
        summary["coverage"] = {"covered": covered, "total": len(result.coverage)}
        with self._tx() as db:
            db.execute(
                "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    uid,
                    now(),
                    logfile,
                    platform,
                    result.events_scanned,
                    result.rules_loaded,
                    len(result.detections),
                    sigma_version,
                    attack_version,
                    json.dumps(summary),
                ),
            )
            db.executemany(
                "INSERT INTO detections (scan_uid, finding_uid, rule_id, rule_title, level, host,"
                " event_time, source, techniques, matched_fields, event)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        uid,
                        finding_uid(d),
                        d.rule_id,
                        d.rule_title,
                        d.level,
                        _host(d),
                        d.event.timestamp.isoformat() if d.event.timestamp else None,
                        d.event.source,
                        json.dumps([t.model_dump(mode="json") for t in d.techniques]),
                        json.dumps(d.matched_fields),
                        d.event.model_dump_json(),
                    )
                    for d in result.detections
                ],
            )
        return uid

    def list_scans(self) -> list[dict[str, Any]]:
        with self._read() as db:
            rows = db.execute(
                "SELECT uid, created_at, logfile, platform, events_scanned, rules_loaded,"
                " detection_count, sigma_version, attack_version FROM scans"
                " ORDER BY created_at DESC, rowid DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def get_scan(self, uid: str) -> dict[str, Any]:
        with self._read() as db:
            row = db.execute("SELECT * FROM scans WHERE uid = ?", (uid,)).fetchone()
        if row is None:
            raise NotFoundError(f"no scan {uid}")
        scan = dict(row)
        scan["summary"] = json.loads(scan["summary"])
        return scan

    def delete_scan(self, uid: str) -> None:
        """Remove a scan and its detections; triage state, keyed on the finding, is kept."""
        with self._tx() as db:
            if db.execute("DELETE FROM scans WHERE uid = ?", (uid,)).rowcount == 0:
                raise NotFoundError(f"no scan {uid}")

    def list_detections(
        self,
        *,
        scan_uid: str | None = None,
        level: Sequence[str] = (),
        rule_id: str | None = None,
        host: str | None = None,
        triage: Sequence[str] = (),
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Detections with their triage state, newest scan first; returns (total, page)."""
        where: list[str] = []
        args: list[Any] = []
        if scan_uid is not None:
            where.append("d.scan_uid = ?")
            args.append(scan_uid)
        if level:
            where.append(f"d.level IN ({','.join('?' * len(level))})")
            args.extend(level)
        if rule_id is not None:
            where.append("d.rule_id = ?")
            args.append(rule_id)
        if host is not None:
            where.append("d.host = ?")
            args.append(host)
        if triage:
            where.append(f"COALESCE(t.status, 'new') IN ({','.join('?' * len(triage))})")
            args.extend(triage)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        base = (
            "FROM detections d JOIN scans s ON s.uid = d.scan_uid "
            f"LEFT JOIN triage t ON t.finding_uid = d.finding_uid {clause}"
        )
        with self._read() as db:
            total = int(db.execute(f"SELECT COUNT(*) {base}", args).fetchone()[0])
            rows = db.execute(
                "SELECT d.id, d.scan_uid, d.finding_uid, d.rule_id, d.rule_title, d.level,"
                " d.host, d.event_time, d.source, d.techniques, d.matched_fields,"
                " COALESCE(t.status, 'new') AS triage_status, COALESCE(t.note, '') AS"
                f" triage_note {base} ORDER BY s.created_at DESC, d.id LIMIT ? OFFSET ?",
                [*args, limit, offset],
            ).fetchall()
        return total, [_detection_row(row) for row in rows]

    def get_detection(self, detection_id: int) -> dict[str, Any]:
        with self._read() as db:
            row = db.execute(
                "SELECT d.*, COALESCE(t.status, 'new') AS triage_status,"
                " COALESCE(t.note, '') AS triage_note FROM detections d"
                " LEFT JOIN triage t ON t.finding_uid = d.finding_uid WHERE d.id = ?",
                (detection_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError(f"no detection {detection_id}")
        detection = _detection_row(row)
        detection["event"] = json.loads(row["event"])
        return detection

    # --- triage ---------------------------------------------------------------------------

    def set_triage(self, finding: str, status: str, note: str = "") -> dict[str, Any]:
        if status not in TRIAGE_STATUSES:
            raise StoreError(f"triage status must be one of {', '.join(TRIAGE_STATUSES)}")
        stamp = now()
        with self._tx() as db:
            known = db.execute(
                "SELECT 1 FROM detections WHERE finding_uid = ? LIMIT 1", (finding,)
            ).fetchone()
            if known is None:
                raise NotFoundError(f"no detection with finding uid {finding}")
            db.execute(
                "INSERT INTO triage VALUES (?, ?, ?, ?) ON CONFLICT(finding_uid) DO UPDATE SET"
                " status = excluded.status, note = excluded.note, updated_at = excluded.updated_at",
                (finding, status, note, stamp),
            )
            db.execute(
                "INSERT INTO triage_history (finding_uid, status, note, at) VALUES (?, ?, ?, ?)",
                (finding, status, note, stamp),
            )
        return {"finding_uid": finding, "status": status, "note": note, "updated_at": stamp}

    def triage_history(self, finding: str) -> list[dict[str, Any]]:
        with self._read() as db:
            rows = db.execute(
                "SELECT status, note, at FROM triage_history WHERE finding_uid = ? ORDER BY id",
                (finding,),
            ).fetchall()
        return [dict(row) for row in rows]

    # --- bench run records ----------------------------------------------------------------

    def import_bench_run(self, run_dir: Path) -> str:
        """Record ``run_dir/summary.json`` (summary level only; no capture events)."""
        summary_path = run_dir / "summary.json"
        if not summary_path.is_file():
            raise NotFoundError(f"no summary.json in {run_dir}")
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        name = str(summary.get("run") or run_dir.name)
        bastion = summary.get("bastion", {})
        with self._tx() as db:
            db.execute(
                "INSERT INTO bench_runs VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE"
                " SET imported_at = excluded.imported_at, source_path = excluded.source_path,"
                " bastion_commit = excluded.bastion_commit,"
                " evaluation_source_hash = excluded.evaluation_source_hash,"
                " pins = excluded.pins, summary = excluded.summary",
                (
                    name,
                    now(),
                    str(run_dir),
                    bastion.get("commit"),
                    bastion.get("evaluation_source_hash"),
                    json.dumps(summary.get("pins", {})),
                    json.dumps(summary),
                ),
            )
        return name

    def import_bench_results(self, results_root: Path) -> list[str]:
        """Record every run directory under ``results_root`` that has a summary."""
        if not results_root.is_dir():
            return []
        return [
            self.import_bench_run(path.parent)
            for path in sorted(results_root.glob("*/summary.json"))
        ]

    def list_bench_runs(self) -> list[dict[str, Any]]:
        with self._read() as db:
            rows = db.execute(
                "SELECT name, imported_at, source_path, bastion_commit, evaluation_source_hash,"
                " pins FROM bench_runs ORDER BY name"
            ).fetchall()
        runs = []
        for row in rows:
            run = dict(row)
            run["pins"] = json.loads(run["pins"])
            runs.append(run)
        return runs

    def get_bench_run(self, name: str) -> dict[str, Any]:
        with self._read() as db:
            row = db.execute("SELECT * FROM bench_runs WHERE name = ?", (name,)).fetchone()
        if row is None:
            raise NotFoundError(f"no bench run {name}")
        run = dict(row)
        run["pins"] = json.loads(run["pins"])
        run["summary"] = json.loads(run["summary"])
        return run

    # --- filter documents -----------------------------------------------------------------

    def sync_filters(self, filters_dir: Path) -> list[str]:
        """Record every filter document under ``filters_dir`` (a record; the engine keeps
        reading the directory). Documents no longer on disk are removed from the record."""
        found: dict[str, tuple[str, str, str, str]] = {}
        if filters_dir.is_dir():
            for path in sorted(filters_dir.rglob("*.yml")):
                text = path.read_text(encoding="utf-8")
                doc = yaml.safe_load(text)
                if not isinstance(doc, dict) or "filter" not in doc or "id" not in doc:
                    continue
                found[str(doc["id"])] = (
                    str(doc.get("title", "")),
                    path.relative_to(filters_dir).as_posix(),
                    hashlib.sha256(text.encode()).hexdigest(),
                    text,
                )
        stamp = now()
        with self._tx() as db:
            db.execute(
                f"DELETE FROM filter_documents WHERE id NOT IN ({','.join('?' * len(found))})",
                list(found),
            )
            for fid, (title, rel, digest, text) in found.items():
                db.execute(
                    "INSERT INTO filter_documents VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO"
                    " UPDATE SET title = excluded.title, path = excluded.path,"
                    " sha256 = excluded.sha256, text = excluded.text,"
                    " imported_at = excluded.imported_at",
                    (fid, title, rel, digest, text, stamp),
                )
        return sorted(found)

    def list_filters(self) -> list[dict[str, Any]]:
        with self._read() as db:
            rows = db.execute(
                "SELECT id, title, path, sha256, imported_at FROM filter_documents ORDER BY path"
            ).fetchall()
        return [dict(row) for row in rows]

    def get_filter(self, fid: str) -> dict[str, Any]:
        with self._read() as db:
            row = db.execute("SELECT * FROM filter_documents WHERE id = ?", (fid,)).fetchone()
        if row is None:
            raise NotFoundError(f"no filter document {fid}")
        return dict(row)

    # --- tag disputes ---------------------------------------------------------------------

    def sync_tag_disputes(self, ledger: Path) -> int:
        """Record the entries of ``docs/tag-disputes.md``. The ledger file is the record of
        origin: an entry from it takes the ledger's status. Local entries are left alone."""
        entries = parse_dispute_ledger(ledger) if ledger.is_file() else []
        stamp = now()
        with self._tx() as db:
            for entry in entries:
                db.execute(
                    "INSERT INTO tag_disputes (rule, tag_carried, evidence_points_at, capture,"
                    " status, origin, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'ledger', ?,"
                    " ?) ON CONFLICT(rule, tag_carried) DO UPDATE SET"
                    " evidence_points_at = excluded.evidence_points_at,"
                    " capture = excluded.capture, status = excluded.status, origin = 'ledger',"
                    " updated_at = excluded.updated_at",
                    (
                        entry["rule"],
                        entry["tag_carried"],
                        entry["evidence_points_at"],
                        entry["capture"],
                        entry["status"],
                        stamp,
                        stamp,
                    ),
                )
        return len(entries)

    def list_tag_disputes(self) -> list[dict[str, Any]]:
        with self._read() as db:
            rows = db.execute("SELECT * FROM tag_disputes ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def add_tag_dispute(
        self,
        *,
        rule: str,
        tag_carried: str,
        evidence_points_at: str,
        capture: str = "",
        note: str = "",
    ) -> dict[str, Any]:
        stamp = now()
        try:
            with self._tx() as db:
                cursor = db.execute(
                    "INSERT INTO tag_disputes (rule, tag_carried, evidence_points_at, capture,"
                    " status, note, origin, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, 'open', ?, 'local', ?, ?)",
                    (rule, tag_carried, evidence_points_at, capture, note, stamp, stamp),
                )
                new_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"a dispute for {rule} carrying {tag_carried} exists") from exc
        return self.get_tag_dispute(int(new_id or 0))

    def get_tag_dispute(self, dispute_id: int) -> dict[str, Any]:
        with self._read() as db:
            row = db.execute("SELECT * FROM tag_disputes WHERE id = ?", (dispute_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"no tag dispute {dispute_id}")
        return dict(row)

    def update_tag_dispute(
        self, dispute_id: int, *, status: str | None = None, note: str | None = None
    ) -> dict[str, Any]:
        if status is not None and status not in DISPUTE_STATUSES:
            raise StoreError(f"dispute status must be one of {', '.join(DISPUTE_STATUSES)}")
        current = self.get_tag_dispute(dispute_id)
        with self._tx() as db:
            db.execute(
                "UPDATE tag_disputes SET status = ?, note = ?, updated_at = ? WHERE id = ?",
                (
                    status if status is not None else current["status"],
                    note if note is not None else current["note"],
                    now(),
                    dispute_id,
                ),
            )
        return self.get_tag_dispute(dispute_id)


def _statements(script: str) -> list[str]:
    return [part.strip() for part in script.split(";") if part.strip()]


def _detection_row(row: sqlite3.Row) -> dict[str, Any]:
    keys = row.keys()
    detection = {k: row[k] for k in keys if k not in ("techniques", "matched_fields", "event")}
    detection["techniques"] = json.loads(row["techniques"])
    detection["matched_fields"] = json.loads(row["matched_fields"])
    return detection


def parse_dispute_ledger(path: Path) -> list[dict[str, str]]:
    """The entries of the ledger table in ``docs/tag-disputes.md``.

    The table's columns are Rule, Tag carried, Evidence points at, Capture, Status. Cells are
    kept as written, with surrounding backticks removed from the capture name.
    """
    entries: list[dict[str, str]] = []
    in_table = False
    for line in path.read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("| Rule |"):
            in_table = True
            continue
        if not in_table:
            continue
        if not line.startswith("|"):
            if entries:
                break
            continue
        if set(line.replace("|", "").strip()) <= set(":- "):
            continue
        if len(cells) != 5:
            continue
        rule, tag, evidence, capture, status = cells
        capture = capture.split(" (")[0].strip().strip("`") if capture else ""
        if status not in DISPUTE_STATUSES:
            status = "open"
        entries.append(
            {
                "rule": rule,
                "tag_carried": tag,
                "evidence_points_at": evidence,
                "capture": capture,
                "status": status,
            }
        )
    return entries
