"""Tests for the corpus cache: root resolution, pinned downloads, safe extraction."""

from __future__ import annotations

import io
import os
import tarfile
import zipfile
from pathlib import Path

import httpx
import pytest

from bastion.bench.cache import (
    ENV_VAR,
    cache_root,
    download,
    extract_tgz,
    extract_zip,
    sha256_file,
    sha256_files,
)


def _client(payload: bytes, status: int = 200) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=payload)

    return httpx.Client(transport=httpx.MockTransport(handler))


def _refusing() -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("network must not be touched")

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_cache_root_prefers_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(ENV_VAR, str(tmp_path / "corp"))
    assert cache_root() == tmp_path / "corp"


def test_cache_root_windows_uses_localappdata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(ENV_VAR, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert cache_root(os_name="nt") == tmp_path / "bastion" / "corpora"


def test_cache_root_posix_uses_xdg_or_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(ENV_VAR, raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert cache_root(os_name="posix") == tmp_path / "xdg" / "bastion" / "corpora"
    monkeypatch.delenv("XDG_CACHE_HOME")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    assert cache_root(os_name="posix") == tmp_path / "home" / ".cache" / "bastion" / "corpora"
    assert cache_root() == cache_root(os_name=os.name)


def test_sha256_helpers(tmp_path: Path) -> None:
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"abc")
    b.write_bytes(b"def")
    assert sha256_file(a) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_files([a, b]) != sha256_files([b, a])
    assert len(sha256_files([a, b])) == 64


def test_download_writes_and_reuses_cache(tmp_path: Path) -> None:
    dest = tmp_path / "x" / "file.bin"
    assert download("https://example.test/f", dest, _client(b"payload")) == dest
    assert dest.read_bytes() == b"payload"
    assert not dest.with_name("file.bin.part").exists()
    assert download("https://example.test/f", dest, _refusing()) == dest
    download("https://example.test/f", dest, _client(b"new"), force=True)
    assert dest.read_bytes() == b"new"


def test_download_verifies_size_and_digest(tmp_path: Path) -> None:
    dest = tmp_path / "file.bin"
    with pytest.raises(ValueError, match="pinned size"):
        download("https://example.test/f", dest, _client(b"abc"), expected_size=99)
    assert not dest.exists()
    with pytest.raises(ValueError, match="sha256"):
        download("https://example.test/f", dest, _client(b"abc"), expected_sha256="00")
    assert not dest.exists()
    good = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    download("https://example.test/f", dest, _client(b"abc"), expected_sha256=good, expected_size=3)
    assert dest.read_bytes() == b"abc"


def test_download_raises_on_http_error(tmp_path: Path) -> None:
    with pytest.raises(httpx.HTTPStatusError):
        download("https://example.test/f", tmp_path / "f", _client(b"", status=404))


def test_download_without_client_builds_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    prebuilt = _client(b"via-default")

    def fake_client(**kwargs: object) -> httpx.Client:
        return prebuilt

    monkeypatch.setattr(httpx, "Client", fake_client)
    dest = download("https://example.test/f", tmp_path / "f")
    assert dest.read_bytes() == b"via-default"


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_extract_zip_selects_members_and_reuses_marker(tmp_path: Path) -> None:
    archive = tmp_path / "a.zip"
    archive.write_bytes(_zip({"root/keep/x.txt": b"x", "root/skip.txt": b"s", "root/dir/": b""}))
    dest = tmp_path / "out"

    def select(name: str) -> Path | None:
        return Path(name.split("/", 1)[1]) if "/keep/" in name else None

    assert extract_zip(archive, dest, select) == 1
    assert (dest / "keep" / "x.txt").read_text() == "x"
    assert not (dest / "skip.txt").exists()
    # Marker short-circuits a second extraction even if the archive changed.
    archive.write_bytes(_zip({"root/keep/y.txt": b"y"}))
    assert extract_zip(archive, dest, select) == 1
    assert not (dest / "keep" / "y.txt").exists()
    assert extract_zip(archive, dest, select, force=True) == 1
    assert (dest / "keep" / "y.txt").exists()


def test_extract_zip_refuses_escapes(tmp_path: Path) -> None:
    archive = tmp_path / "a.zip"
    archive.write_bytes(_zip({"root/../evil.txt": b"e"}))
    with pytest.raises(ValueError, match="escapes"):
        extract_zip(archive, tmp_path / "out", lambda name: Path(name.split("/", 1)[1]))


def _tgz(members: dict[str, bytes], names: list[str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for name in names or []:
            directory = tarfile.TarInfo(name)
            directory.type = tarfile.DIRTYPE
            tar.addfile(directory)
    return buffer.getvalue()


def test_extract_tgz_writes_regular_files_and_marker(tmp_path: Path) -> None:
    archive = tmp_path / "s.tgz"
    archive.write_bytes(_tgz({"set/one.evtx": b"1", "set/two.evtx": b"22"}, ["set/dir"]))
    dest = tmp_path / "set-out"
    assert extract_tgz(archive, dest) == 2
    assert (dest / "set" / "two.evtx").read_bytes() == b"22"
    assert extract_tgz(archive, dest) == 2  # marker reused


def test_extract_tgz_refuses_escapes(tmp_path: Path) -> None:
    archive = tmp_path / "s.tgz"
    archive.write_bytes(_tgz({"../evil": b"e"}))
    with pytest.raises(ValueError, match="escapes"):
        extract_tgz(archive, tmp_path / "out")
