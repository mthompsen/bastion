"""Nextron evtx-baseline: goodware Windows event logs for benign replay.

Each release asset is one host's full set of event log channels, one
``.evtx`` per channel. A set becomes one capture per channel file, all
sharing the set name as the host, so benign alert volume can be expressed
per host per day from the timestamps actually scanned.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from urllib.parse import unquote

import httpx

from bastion.bench.cache import download, extract_tgz
from bastion.bench.captures import Capture
from bastion.pins import load_pins

CORPUS = "evtx_baseline"


def available_sets() -> dict[str, tuple[str, int]]:
    """Asset name -> (url, pinned size)."""
    assets = load_pins()["corpora"][CORPUS]["assets"]
    return {name: (str(url), int(size)) for name, (url, size) in assets.items()}


def default_sets() -> list[str]:
    return [str(name) for name in load_pins()["corpora"][CORPUS]["default_sets"]["sets"]]


def set_dir(cache: Path, name: str) -> Path:
    release = str(load_pins()["corpora"][CORPUS]["release"])
    return cache / "evtx-baseline" / release / name


def fetch_baseline_set(
    cache: Path, name: str, client: httpx.Client | None = None, force: bool = False
) -> Path:
    sets = available_sets()
    if name not in sets:
        raise ValueError(f"unknown evtx-baseline set {name!r}; pinned sets: {sorted(sets)}")
    url, size = sets[name]
    release = str(load_pins()["corpora"][CORPUS]["release"])
    archive = download(
        url,
        cache / "evtx-baseline" / release / f"{name}.tgz",
        client,
        expected_size=size,
        force=force,
    )
    root = set_dir(cache, name)
    extract_tgz(archive, root, force=force)
    return root


def channel_name(path: Path) -> str:
    """Channel from a file name: ``Microsoft-Windows-Sysmon%4Operational.evtx`` is
    ``Microsoft-Windows-Sysmon/Operational``."""
    return unquote(path.stem.replace("%4", "/"))


def baseline_captures(
    root: Path, set_name: str, channels: Sequence[str] | None = None
) -> list[Capture]:
    """One benign capture per channel file; ``channels`` narrows by channel name."""
    wanted = {c.lower() for c in channels} if channels else None
    license_text = str(load_pins()["corpora"][CORPUS]["license"])
    captures: list[Capture] = []
    for path in sorted(p for p in root.rglob("*") if p.suffix.lower() == ".evtx"):
        channel = channel_name(path)
        if wanted is not None and channel.lower() not in wanted:
            continue
        captures.append(
            Capture(
                id=f"{CORPUS}/{set_name}/{path.relative_to(root).as_posix()}",
                corpus=CORPUS,
                kind="benign",
                platform="windows",
                source_kind="evtx",
                paths=(path,),
                host=set_name,
                license=license_text,
                notes={"channel": channel},
            )
        )
    return captures
