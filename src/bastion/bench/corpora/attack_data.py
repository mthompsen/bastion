"""Splunk attack_data: per-technique captures from Atomic Red Team runs (Linux auditd subset).

Each dataset directory carries a YAML manifest naming its ``mitre_technique``
ids and its files with a ``sourcetype``. Files are Git LFS objects, served
from ``media.githubusercontent.com`` at the pinned commit, so no LFS client
is needed and only the approved datasets are pulled.

Splunk splits one audit event's records (SYSCALL, EXECVE, PROCTITLE, PATH)
across files and orders them newest first, so a dataset's auditd files are
concatenated and stable-sorted by ``(epoch, serial)`` into one normalized
log before Bastion's ``AuditdSource`` reads it. Files are routed by the
YAML ``sourcetype``, never by directory name: syslog-format files sit in
auditd-named directories upstream.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import httpx
import yaml

from bastion.attack import AttackData
from bastion.bench.cache import download
from bastion.bench.captures import Capture
from bastion.bench.labels import resolve_labels
from bastion.pins import data_file_text, load_pins

CORPUS = "attack_data"
NORMALIZED_AUDITD = "_bastion_auditd_sorted.log"
SYSLOG_SOURCETYPES = {"linux_secure", "linux_messages_syslog", "syslog", "linux_audit"}
_AUDIT_ID_RE = re.compile(r"msg=audit\((\d+)(?:\.(\d+))?:(\d+)\)")
_RECORD_TYPE_RE = re.compile(r"^type=([A-Z_]+)")


def dataset_manifests() -> list[str]:
    """Repository-relative YAML paths of the approved datasets."""
    name = str(load_pins()["corpora"][CORPUS]["datasets_list"])
    return [line.strip() for line in data_file_text(name).splitlines() if line.strip()]


def corpus_dir(cache: Path) -> Path:
    return cache / "attack_data" / str(load_pins()["corpora"][CORPUS]["commit"])


def fetch_attack_data(
    cache: Path,
    client: httpx.Client | None = None,
    force: bool = False,
    manifests: list[str] | None = None,
) -> Path:
    """Download each approved dataset's YAML and files into the cache."""
    pins = load_pins()["corpora"][CORPUS]
    root = corpus_dir(cache)
    if client is None:
        with httpx.Client(follow_redirects=True, timeout=httpx.Timeout(600.0)) as own:
            return fetch_attack_data(cache, own, force, manifests)
    for manifest in manifests or dataset_manifests():
        yaml_path = download(str(pins["raw_base"]) + manifest, root / manifest, client, force=force)
        doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        for entry in doc.get("datasets") or []:
            relative = str(entry.get("path", "")).lstrip("/")
            if relative:
                download(str(pins["media_base"]) + relative, root / relative, client, force=force)
    return root


#: Record order inside one audit event, as the kernel emits it into audit.log. The merged
#: Event takes its ``type`` from the first record, so the order has to be canonical.
_RECORD_ORDER = ("SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE")


def _sort_key(line: str) -> tuple[int, int, int, int]:
    found = _AUDIT_ID_RE.search(line)
    if found is None:
        return (1, 0, 0, 0)  # unparseable lines sink to the end, in their original order
    epoch, millis, serial = found.group(1), found.group(2) or "0", found.group(3)
    kind = _RECORD_TYPE_RE.match(line)
    rank = _RECORD_ORDER.index(kind.group(1)) if kind and kind.group(1) in _RECORD_ORDER else 9
    return (0, int(epoch) * 1000 + int(millis.ljust(3, "0")[:3]), int(serial), rank)


def normalize_auditd(files: list[Path], dest: Path, force: bool = False) -> Counter[str]:
    """Concatenate and stable-sort auditd files into ``dest``; returns record type counts."""
    lines: list[str] = []
    for path in files:
        lines.extend(
            line.rstrip("\r\n")
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        )
    lines.sort(key=_sort_key)
    if force or not dest.exists():
        dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    types: Counter[str] = Counter()
    for line in lines:
        found = _RECORD_TYPE_RE.match(line)
        types[found.group(1) if found else "non-audit"] += 1
    return types


def attack_data_captures(root: Path, attack: AttackData, force: bool = False) -> list[Capture]:
    license_text = str(load_pins()["corpora"][CORPUS]["license"])
    captures: list[Capture] = []
    for manifest in dataset_manifests():
        yaml_path = root / manifest
        if not yaml_path.is_file():
            continue
        doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        raw_ids = tuple(str(t).upper() for t in doc.get("mitre_technique") or [])
        live, notes = resolve_labels(raw_ids, attack)
        dataset_id = manifest.rsplit("/", 1)[0].removeprefix("datasets/attack_techniques/")
        auditd_files: list[Path] = []
        skipped: list[str] = []
        for entry in doc.get("datasets") or []:
            relative = str(entry.get("path", "")).lstrip("/")
            sourcetype = str(entry.get("sourcetype", "")).lower()
            path = root / relative
            if not path.is_file():
                skipped.append(f"{relative}: not downloaded")
            elif sourcetype == "auditd":
                auditd_files.append(path)
            elif sourcetype in SYSLOG_SOURCETYPES:
                captures.append(
                    Capture(
                        id=f"{CORPUS}/{dataset_id}/{path.name}",
                        corpus=CORPUS,
                        kind="positive",
                        platform="linux",
                        source_kind="syslog",
                        paths=(path,),
                        techniques=live,
                        raw_labels=raw_ids,
                        label_notes=notes,
                        host="attack_range",
                        license=license_text,
                        notes={"sourcetype": sourcetype},
                    )
                )
            else:
                skipped.append(f"{relative}: sourcetype {sourcetype!r} not readable yet")
        if auditd_files:
            dest = yaml_path.parent / NORMALIZED_AUDITD
            types = normalize_auditd(auditd_files, dest, force=force)
            captures.append(
                Capture(
                    id=f"{CORPUS}/{dataset_id}/auditd",
                    corpus=CORPUS,
                    kind="positive",
                    platform="linux",
                    source_kind="auditd",
                    paths=(dest,),
                    techniques=live,
                    raw_labels=raw_ids,
                    label_notes=notes,
                    host="attack_range",
                    license=license_text,
                    notes={
                        "sourcetype": "auditd",
                        "record_types": " ".join(f"{k}={v}" for k, v in sorted(types.items())),
                        "files": str(len(auditd_files)),
                        **({"skipped": "; ".join(skipped)} if skipped else {}),
                    },
                )
            )
    return captures
