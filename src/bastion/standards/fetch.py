"""Download the pinned standards mapping data into the cache, and report what is there."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from bastion.fetch import DEFAULT_DATA_DIR
from bastion.pins import load_pins


@dataclass(frozen=True)
class StandardsFile:
    """One cached file: which pin it belongs to, where it lives, and its expected digest."""

    key: str
    url: str
    relative: str
    sha256: str
    #: True when the digest must match (a static file); False when only the commit is the pin
    strict: bool = True


def standards_dir(data_dir: Path = DEFAULT_DATA_DIR) -> Path:
    return data_dir / "standards"


def standards_files() -> list[StandardsFile]:
    pins = load_pins()["standards"]
    d3fend, ctid, car = pins["d3fend"], pins["ctid_800_53"], pins["car"]
    return [
        StandardsFile(
            "d3fend",
            str(d3fend["mappings_url"]),
            f"d3fend/{d3fend['version']}/d3fend-full-mappings.csv",
            str(d3fend["mappings_sha256"]),
        ),
        StandardsFile(
            "d3fend",
            str(d3fend["techniques_url"]),
            f"d3fend/{d3fend['version']}/d3fend.csv",
            str(d3fend["techniques_sha256"]),
        ),
        StandardsFile(
            "ctid_800_53",
            str(ctid["url"]),
            f"ctid/{str(ctid['commit'])[:12]}/{str(ctid['url']).rsplit('/', 1)[-1]}",
            str(ctid["sha256"]),
        ),
        StandardsFile(
            "car",
            str(car["url"]),
            f"car/car-{str(car['commit'])[:12]}.zip",
            str(car["sha256"]),
            strict=False,
        ),
    ]


def standards_path(key: str, data_dir: Path = DEFAULT_DATA_DIR) -> list[Path]:
    """The cached paths of one pinned source, in :func:`standards_files` order."""
    root = standards_dir(data_dir)
    return [root / f.relative for f in standards_files() if f.key == key]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch_standards(
    data_dir: Path = DEFAULT_DATA_DIR,
    force: bool = False,
    client: httpx.Client | None = None,
) -> list[dict[str, Any]]:
    """Download every pinned standards file not yet cached; verify digests.

    A strict file whose digest differs from its pin is not kept and raises ``ValueError``.
    A non-strict file (an archive GitHub builds on request) is kept, and the difference is
    reported in the returned rows.
    """
    rows: list[dict[str, Any]] = []
    owned = client is None
    http = client or httpx.Client(timeout=120, follow_redirects=True)
    try:
        for item in standards_files():
            dest = standards_dir(data_dir) / item.relative
            if dest.exists() and not force:
                rows.append(
                    {
                        "file": item.relative,
                        "status": "cached",
                        "digest_matches": _sha256(dest) == item.sha256,
                    }
                )
                continue
            response = http.get(item.url)
            response.raise_for_status()
            payload = response.content
            actual = hashlib.sha256(payload).hexdigest()
            if item.strict and actual != item.sha256:
                raise ValueError(
                    f"{item.url}: sha256 {actual} does not match the pin {item.sha256}"
                )
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_suffix(dest.suffix + ".tmp")
            tmp.write_bytes(payload)
            tmp.replace(dest)
            rows.append(
                {
                    "file": item.relative,
                    "status": "fetched",
                    "digest_matches": actual == item.sha256,
                }
            )
    finally:
        if owned:
            http.close()
    return rows
