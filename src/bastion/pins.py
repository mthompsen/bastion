"""Pinned versions of every external source Bastion reads.

The pins live in ``bastion/data/PINS.toml`` (packaged) and are read with the
standard library ``tomllib``. Every bench result and report footer prints
them, so a number can always be traced to the exact data it was computed
from.
"""

from __future__ import annotations

import tomllib
from functools import lru_cache
from importlib import resources
from typing import Any


@lru_cache(maxsize=1)
def load_pins() -> dict[str, Any]:
    """The parsed PINS.toml as nested dicts."""
    text = resources.files("bastion.data").joinpath("PINS.toml").read_text(encoding="utf-8")
    return tomllib.loads(text)


def pin_summary() -> dict[str, str]:
    """Flat ``name -> version`` view for footers and result files."""
    pins = load_pins()
    corpora = pins.get("corpora", {})
    summary = {
        "sigma": str(pins["sigma"]["tag"]),
        "sigma_commit": str(pins["sigma"]["commit"]),
        "attack": str(pins["attack"]["version"]),
    }
    for key, entry in corpora.items():
        version = entry.get("commit") or entry.get("release") or entry.get("recorded") or ""
        summary[f"corpus:{key}"] = str(version)
    return summary


def data_file_text(name: str) -> str:
    """Read a packaged data file (for example a corpus dataset list)."""
    return resources.files("bastion.data").joinpath(name).read_text(encoding="utf-8")
