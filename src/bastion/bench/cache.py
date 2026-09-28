"""Corpus cache outside the repository, and pinned downloads into it.

The cache root is ``$BASTION_CACHE_DIR`` when set, otherwise
``%LOCALAPPDATA%\\bastion\\corpora`` on Windows and
``$XDG_CACHE_HOME/bastion/corpora`` (default ``~/.cache``) elsewhere.
Downloads are streamed to a ``.part`` file, hashed, checked against the
expected size or digest when one is pinned, and only then moved into place,
so a cached file is either complete or absent.
"""

from __future__ import annotations

import hashlib
import os
import tarfile
import zipfile
from collections.abc import Callable, Iterable
from pathlib import Path

import httpx

ENV_VAR = "BASTION_CACHE_DIR"


def cache_root(os_name: str | None = None) -> Path:
    """Where corpora are cached; never inside the repository.

    ``os_name`` defaults to ``os.name`` and exists so the other platform's
    branch can be tested without patching ``os.name`` (which changes which
    ``Path`` flavour pathlib instantiates).
    """
    override = os.environ.get(ENV_VAR)
    if override:
        return Path(override)
    if (os_name or os.name) == "nt" and (local := os.environ.get("LOCALAPPDATA")):
        return Path(local) / "bastion" / "corpora"
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "bastion" / "corpora"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_files(paths: Iterable[Path]) -> str:
    """One digest over several files, in the given order, for manifests."""
    digest = hashlib.sha256()
    for path in paths:
        digest.update(sha256_file(path).encode("ascii"))
    return digest.hexdigest()


def download(
    url: str,
    dest: Path,
    client: httpx.Client | None = None,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
    force: bool = False,
) -> Path:
    """Fetch ``url`` into ``dest`` unless it is already cached.

    ``client`` is injectable for tests. A size or digest mismatch raises
    ``ValueError`` and leaves nothing at ``dest``.
    """
    if dest.exists() and not force:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    if client is None:
        with httpx.Client(follow_redirects=True, timeout=httpx.Timeout(600.0)) as own:
            return download(url, dest, own, expected_sha256, expected_size, force)
    digest = hashlib.sha256()
    size = 0
    with client.stream("GET", url) as response, part.open("wb") as out:
        response.raise_for_status()
        for chunk in response.iter_bytes():
            digest.update(chunk)
            size += len(chunk)
            out.write(chunk)
    try:
        if expected_size is not None and size != expected_size:
            raise ValueError(f"{url}: downloaded {size} bytes, pinned size is {expected_size}")
        if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
            raise ValueError(f"{url}: sha256 {digest.hexdigest()} does not match the pin")
    except ValueError:
        part.unlink(missing_ok=True)
        raise
    part.replace(dest)
    return dest


def _safe_relative(relative: Path, archive_name: str) -> Path:
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"archive member escapes extraction root: {archive_name!r}")
    return relative


def extract_zip(
    archive: Path, dest: Path, select: Callable[[str], Path | None], force: bool = False
) -> int:
    """Extract the members ``select`` maps to a relative target path.

    ``select`` receives each member name and returns where it should land
    under ``dest`` (relative), or None to skip it. Returns the number of
    files written. An existing ``dest`` is reused unless ``force``.
    """
    marker = dest / ".extracted"
    if marker.exists() and not force:
        return int(marker.read_text(encoding="utf-8") or 0)
    count = 0
    with zipfile.ZipFile(archive) as zipped:
        for name in zipped.namelist():
            if name.endswith("/"):
                continue
            relative = select(name)
            if relative is None:
                continue
            target = dest / _safe_relative(relative, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zipped.read(name))
            count += 1
    dest.mkdir(parents=True, exist_ok=True)
    marker.write_text(str(count), encoding="utf-8")
    return count


def extract_tgz(archive: Path, dest: Path, force: bool = False) -> int:
    """Extract the regular files of a ``.tgz`` under ``dest``, refusing escapes."""
    marker = dest / ".extracted"
    if marker.exists() and not force:
        return int(marker.read_text(encoding="utf-8") or 0)
    count = 0
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            relative = _safe_relative(Path(member.name), member.name)
            source = tar.extractfile(member)
            if source is None:
                continue
            target = dest / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, target.open("wb") as out:
                while chunk := source.read(1 << 20):
                    out.write(chunk)
            count += 1
    dest.mkdir(parents=True, exist_ok=True)
    marker.write_text(str(count), encoding="utf-8")
    return count
