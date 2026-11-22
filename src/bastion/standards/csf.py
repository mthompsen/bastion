"""NIST CSF 2.0 labels for Bastion's functions (packaged; the assignment is Bastion's)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources


@dataclass(frozen=True)
class CsfOutcome:
    id: str
    text: str


@dataclass(frozen=True)
class CsfLabel:
    """One Bastion function and the CSF 2.0 outcomes it supports."""

    function: str
    outcomes: tuple[CsfOutcome, ...]
    #: "full" or "partial" (supports the outcome only for the logs Bastion reads)
    scope: str
    note: str


@dataclass(frozen=True)
class CsfLabels:
    version: str
    source: str
    #: who asserts the mapping: Bastion, not NIST
    assertion: str
    labels: tuple[CsfLabel, ...]


@lru_cache(maxsize=1)
def load_csf_labels() -> CsfLabels:
    text = (
        resources.files("bastion.data")
        .joinpath("standards/csf-2.0-labels.toml")
        .read_text(encoding="utf-8")
    )
    data = tomllib.loads(text)
    outcomes = {key: CsfOutcome(key, str(value)) for key, value in data["outcomes"].items()}
    labels = tuple(
        CsfLabel(
            function=str(item["name"]),
            outcomes=tuple(outcomes[key] for key in item["outcomes"]),
            scope=str(item["scope"]),
            note=str(item.get("note", "")),
        )
        for item in data["function"]
    )
    meta = data["csf"]
    return CsfLabels(str(meta["version"]), str(meta["source"]), str(meta["assertion"]), labels)
