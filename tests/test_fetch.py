"""Tests for dataset fetching/caching — fully offline via httpx.MockTransport."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import httpx
import pytest

from bastion.fetch import (
    ATTACK_URL,
    ATTACK_VERSION,
    SIGMA_EXTRA_TREES,
    SIGMA_URL,
    SIGMA_VERSION,
    attack_bundle_path,
    fetch_attack,
    fetch_sigma,
    fetch_sigma_trees,
    sigma_rules_path,
    sigma_tree_path,
)

VALID_BUNDLE = json.dumps({"type": "bundle", "objects": []}).encode()


def _client(handler: httpx.MockTransport) -> httpx.Client:
    return httpx.Client(transport=handler)


def _serving(payload: bytes, status_code: int = 200, url: str = ATTACK_URL) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == url
        return httpx.Response(status_code, content=payload)

    return _client(httpx.MockTransport(handler))


def _refusing() -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("network must not be touched when the cache is warm")

    return _client(httpx.MockTransport(handler))


def _sigma_zip(root: str = f"sigma-{SIGMA_VERSION}") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(f"{root}/rules/windows/proc.yml", "title: Win Rule\n")
        archive.writestr(f"{root}/rules/linux/auth.yml", "title: Linux Rule\n")
        archive.writestr(f"{root}/tests/not_a_rule.yml", "title: Skipped\n")
        archive.writestr(f"{root}/README.md", "readme")
        archive.writestr(f"{root}/rules-emerging-threats/2025/et.yml", "title: ET Rule\n")
        archive.writestr(f"{root}/rules-threat-hunting/windows/th.yml", "title: TH Rule\n")
    return buffer.getvalue()


def test_fetch_attack_downloads_and_writes_cache_and_version(tmp_path: Path) -> None:
    dest = fetch_attack(data_dir=tmp_path, client=_serving(VALID_BUNDLE))
    assert dest == attack_bundle_path(tmp_path)
    assert dest.read_bytes() == VALID_BUNDLE
    version_file = dest.with_name("enterprise-attack.version.txt")
    assert f"version: {ATTACK_VERSION}" in version_file.read_text(encoding="utf-8")


def test_fetch_attack_uses_cache_without_network(tmp_path: Path) -> None:
    dest = attack_bundle_path(tmp_path)
    dest.parent.mkdir(parents=True)
    dest.write_bytes(VALID_BUNDLE)
    assert fetch_attack(data_dir=tmp_path, client=_refusing()) == dest


def test_fetch_attack_force_redownloads(tmp_path: Path) -> None:
    dest = attack_bundle_path(tmp_path)
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"{}")
    fetch_attack(data_dir=tmp_path, force=True, client=_serving(VALID_BUNDLE))
    assert dest.read_bytes() == VALID_BUNDLE


def test_fetch_attack_rejects_non_json_download(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not valid JSON"):
        fetch_attack(data_dir=tmp_path, client=_serving(b"<html>error page</html>"))
    assert not attack_bundle_path(tmp_path).exists()


def test_fetch_attack_raises_on_http_error(tmp_path: Path) -> None:
    with pytest.raises(httpx.HTTPStatusError):
        fetch_attack(data_dir=tmp_path, client=_serving(b"missing", status_code=404))
    assert not attack_bundle_path(tmp_path).exists()


def test_fetch_sigma_extracts_only_rules_tree(tmp_path: Path) -> None:
    dest = fetch_sigma(data_dir=tmp_path, client=_serving(_sigma_zip(), url=SIGMA_URL))
    assert dest == sigma_rules_path(tmp_path)
    assert (dest / "windows" / "proc.yml").read_text(encoding="utf-8") == "title: Win Rule\n"
    assert (dest / "linux" / "auth.yml").exists()
    assert not (dest / "tests").exists()
    assert not (dest.parent / "README.md").exists()
    version_file = dest.parent / "sigma.version.txt"
    assert f"version: {SIGMA_VERSION}" in version_file.read_text(encoding="utf-8")


def test_fetch_sigma_uses_cache_without_network(tmp_path: Path) -> None:
    dest = sigma_rules_path(tmp_path)
    dest.mkdir(parents=True)
    (dest / "existing.yml").write_text("title: Cached\n", encoding="utf-8")
    assert fetch_sigma(data_dir=tmp_path, client=_refusing()) == dest
    assert (dest / "existing.yml").exists()


def test_fetch_sigma_force_replaces_cache(tmp_path: Path) -> None:
    dest = sigma_rules_path(tmp_path)
    dest.mkdir(parents=True)
    (dest / "stale.yml").write_text("title: Stale\n", encoding="utf-8")
    fetch_sigma(data_dir=tmp_path, force=True, client=_serving(_sigma_zip(), url=SIGMA_URL))
    assert not (dest / "stale.yml").exists()
    assert (dest / "windows" / "proc.yml").exists()


def test_fetch_sigma_rejects_archive_without_rules(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("sigma-x/README.md", "no rules here")
    with pytest.raises(ValueError, match="no rules"):
        fetch_sigma(data_dir=tmp_path, client=_serving(buffer.getvalue(), url=SIGMA_URL))


def test_fetch_sigma_trees_extracts_each_tree_beside_rules(tmp_path: Path) -> None:
    paths = fetch_sigma_trees(data_dir=tmp_path, client=_serving(_sigma_zip(), url=SIGMA_URL))
    assert set(paths) == set(SIGMA_EXTRA_TREES)
    assert paths["rules-emerging-threats"] == sigma_tree_path("rules-emerging-threats", tmp_path)
    assert (paths["rules-emerging-threats"] / "2025" / "et.yml").exists()
    assert (paths["rules-threat-hunting"] / "windows" / "th.yml").exists()
    assert not sigma_rules_path(tmp_path).exists()  # rules/ is fetch_sigma's job
    version = (tmp_path / "sigma" / "sigma-trees.version.txt").read_text(encoding="utf-8")
    assert f"version: {SIGMA_VERSION}" in version
    assert "rules-threat-hunting files: 1" in version


def test_fetch_sigma_trees_uses_cache_without_network(tmp_path: Path) -> None:
    for tree in SIGMA_EXTRA_TREES:
        sigma_tree_path(tree, tmp_path).mkdir(parents=True)
    paths = fetch_sigma_trees(data_dir=tmp_path, client=_refusing())
    assert all(path.is_dir() for path in paths.values())


def test_fetch_sigma_trees_rejects_archive_missing_a_tree(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("sigma-x/rules-threat-hunting/a.yml", "title: a\n")
    with pytest.raises(ValueError, match="rules-emerging-threats"):
        fetch_sigma_trees(data_dir=tmp_path, client=_serving(buffer.getvalue(), url=SIGMA_URL))
