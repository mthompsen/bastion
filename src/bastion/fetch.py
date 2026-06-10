"""One-time download and caching of the external datasets.

Bastion needs two external datasets (SPEC.md section 5), fetched once and
cached under ``data/`` so the core flow runs offline afterwards:

1. the MITRE ATT&CK enterprise STIX bundle;
2. the SigmaHQ ruleset (pinned release tag, ``rules/`` tree only).

Versions are pinned for reproducibility; the cached copy is reused until
``--force`` is passed.
"""

from __future__ import annotations

import io
import json
import shutil
import zipfile
from pathlib import Path

import httpx

#: Pinned ATT&CK release (verified against mitre-attack/attack-stix-data).
ATTACK_VERSION = "19.1"
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"master/enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)

#: Pinned SigmaHQ/sigma release tag (verified against the live repo).
SIGMA_VERSION = "r2026-04-01"
SIGMA_URL = f"https://github.com/SigmaHQ/sigma/archive/refs/tags/{SIGMA_VERSION}.zip"

DEFAULT_DATA_DIR = Path("data")
ATTACK_FILENAME = "enterprise-attack.json"


def attack_bundle_path(data_dir: Path = DEFAULT_DATA_DIR) -> Path:
    """Where the cached ATT&CK STIX bundle lives."""
    return data_dir / "attack" / ATTACK_FILENAME


def fetch_attack(
    data_dir: Path = DEFAULT_DATA_DIR,
    force: bool = False,
    client: httpx.Client | None = None,
) -> Path:
    """Download the pinned ATT&CK enterprise STIX bundle into the cache.

    Returns the cached path immediately when it already exists (unless
    ``force``). The download is validated as JSON and written atomically,
    alongside a ``.version.txt`` recording the pinned release and URL.

    ``client`` is injectable for tests; callers normally omit it.
    """
    dest = attack_bundle_path(data_dir)
    if dest.exists() and not force:
        return dest

    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = _download(client, ATTACK_URL)

    tmp = dest.with_suffix(".tmp")
    tmp.write_bytes(payload)
    tmp.replace(dest)
    dest.with_name("enterprise-attack.version.txt").write_text(
        f"version: {ATTACK_VERSION}\nurl: {ATTACK_URL}\n", encoding="utf-8"
    )
    return dest


def sigma_rules_path(data_dir: Path = DEFAULT_DATA_DIR) -> Path:
    """Where the cached Sigma ``rules/`` tree lives."""
    return data_dir / "sigma" / "rules"


def fetch_sigma(
    data_dir: Path = DEFAULT_DATA_DIR,
    force: bool = False,
    client: httpx.Client | None = None,
) -> Path:
    """Download the pinned SigmaHQ release and cache its ``rules/`` tree.

    Only the ``rules/`` directory of the release archive is extracted,
    preserving its layout under ``data/sigma/rules/``.
    """
    dest = sigma_rules_path(data_dir)
    if dest.exists() and not force:
        return dest

    payload = _request(client, SIGMA_URL)
    archive = zipfile.ZipFile(io.BytesIO(payload))

    if dest.exists():
        shutil.rmtree(dest)
    extracted = 0
    for name in archive.namelist():
        parts = Path(name).parts
        # Archive root is "sigma-<tag>/"; keep only the rules/ subtree.
        if len(parts) < 3 or parts[1] != "rules" or name.endswith("/"):
            continue
        relative = Path(*parts[2:])
        if ".." in relative.parts:
            raise ValueError(f"archive member escapes extraction root: {name!r}")
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(archive.read(name))
        extracted += 1
    if extracted == 0:
        raise ValueError(f"no rules/ tree found in archive from {SIGMA_URL}")
    dest.parent.joinpath("sigma.version.txt").write_text(
        f"version: {SIGMA_VERSION}\nurl: {SIGMA_URL}\nrule files: {extracted}\n",
        encoding="utf-8",
    )
    return dest


def _download(client: httpx.Client | None, url: str) -> bytes:
    payload = _request(client, url)
    try:
        json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"downloaded file from {url} is not valid JSON: {exc}") from exc
    return payload


def _request(client: httpx.Client | None, url: str) -> bytes:
    if client is None:
        with httpx.Client(follow_redirects=True, timeout=120.0) as own_client:
            return _request(own_client, url)
    response = client.get(url)
    response.raise_for_status()
    return response.content
