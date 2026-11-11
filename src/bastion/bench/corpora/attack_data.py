"""Splunk attack_data: per-technique captures from Atomic Red Team runs.

Two dataset lists are pinned: the Linux auditd subset (B1) and the Windows event log
subset (B3), whose ``XmlWinEventLog`` files (Sysmon, Security, PowerShell, System and other
channels) become one Windows capture per dataset, read by
:class:`~bastion.ingest.evtx.XmlEventLogSource`. Labels always come from the dataset's own
YAML ``mitre_technique``.

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
from datetime import UTC, datetime
from pathlib import Path

import httpx
import yaml

from bastion.attack import AttackData
from bastion.bench.cache import download
from bastion.bench.captures import Capture, SourceKind
from bastion.bench.labels import resolve_labels
from bastion.models import Platform
from bastion.pins import data_file_text, load_pins

CORPUS = "attack_data"
NORMALIZED_AUDITD = "_bastion_auditd_sorted.log"
SYSLOG_SOURCETYPES = {"linux_secure", "linux_messages_syslog", "syslog", "linux_audit"}
_AUDIT_ID_RE = re.compile(
    r"msg=audit\((?:(\d+)(?:\.(\d+))?|(\d\d/\d\d/\d{4} \d\d:\d\d:\d\d)(?:\.(\d+))?):(\d+)\)"
)
_RECORD_TYPE_RE = re.compile(r"^type=([A-Z_]+)")


def dataset_manifests(key: str = "datasets_list") -> list[str]:
    """Repository-relative YAML paths of the approved datasets in one pinned list."""
    name = load_pins()["corpora"][CORPUS].get(key)
    if not name:
        return []
    return [line.strip() for line in data_file_text(str(name)).splitlines() if line.strip()]


def file_family(entry: dict[str, object]) -> str | None:
    """``windows`` for Windows event XML (``XmlWinEventLog`` sourcetype or source),
    ``sysmon_linux`` for Sysmon for Linux (``sysmon:linux``), else None."""
    sourcetype = str(entry.get("sourcetype", ""))
    if sourcetype.lower() == "sysmon:linux":
        return "sysmon_linux"
    if sourcetype.startswith("XmlWinEventLog") or str(entry.get("source", "")).startswith(
        "XmlWinEventLog"
    ):
        return "windows"
    return None


#: Event XML families: pinned dataset list key, capture platform, capture source kind.
_FAMILIES: dict[str, tuple[str, Platform, SourceKind]] = {
    "windows": ("windows_datasets_list", "windows", "xmlevents"),
    "sysmon_linux": ("sysmon_linux_datasets_list", "linux", "sysmon_linux"),
}


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
    epoch, millis, stamp, stamp_millis, serial = found.groups()
    if stamp is not None:
        # ausearch -i output: local time of an unnamed zone, read as UTC (see AuditdSource).
        when = datetime.strptime(stamp, "%m/%d/%Y %H:%M:%S").replace(tzinfo=UTC)
        epoch, millis = str(int(when.timestamp())), stamp_millis
    kind = _RECORD_TYPE_RE.match(line)
    rank = _RECORD_ORDER.index(kind.group(1)) if kind and kind.group(1) in _RECORD_ORDER else 9
    return (0, int(epoch) * 1000 + int((millis or "0").ljust(3, "0")[:3]), int(serial), rank)


def normalize_auditd(files: list[Path], dest: Path, force: bool = False) -> Counter[str]:
    """Concatenate and stable-sort auditd files into ``dest``; returns record type counts.

    Lines are split on ``\\n`` only: an enriched record carries a ``\\x1d`` before its
    interpreted half, and ``str.splitlines`` treats that as a line break, which cut every
    enriched record in two before B2. ``dest`` is rewritten whenever its content differs, so a
    file normalized by an older Bastion is never reused.
    """
    lines: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        lines.extend(line.rstrip("\r") for line in text.split("\n") if line.strip())
    lines.sort(key=_sort_key)
    content = "\n".join(lines) + "\n"
    current = dest.read_text(encoding="utf-8", errors="replace") if dest.exists() else None
    if force or current != content:
        dest.write_bytes(content.encode("utf-8"))
    types: Counter[str] = Counter()
    for line in lines:
        found = _RECORD_TYPE_RE.match(line)
        types[found.group(1) if found else "non-audit"] += 1
    return types


def attack_data_captures(root: Path, attack: AttackData, force: bool = False) -> list[Capture]:
    license_text = str(load_pins()["corpora"][CORPUS]["license"])
    captures: list[Capture] = []
    family_lists = {name: set(dataset_manifests(key)) for name, (key, _, _) in _FAMILIES.items()}
    linux_lists = dataset_manifests()
    extra = set().union(*family_lists.values()) - set(linux_lists)
    for manifest in [*linux_lists, *sorted(extra)]:
        xml_only = manifest not in linux_lists
        yaml_path = root / manifest
        if not yaml_path.is_file():
            continue
        doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        raw_ids = tuple(str(t).upper() for t in doc.get("mitre_technique") or [])
        live, notes = resolve_labels(raw_ids, attack)
        dataset_id = manifest.rsplit("/", 1)[0].removeprefix("datasets/attack_techniques/")
        auditd_files: list[Path] = []
        family_files: dict[str, list[Path]] = {}
        skipped: list[str] = []
        for entry in doc.get("datasets") or []:
            relative = str(entry.get("path", "")).lstrip("/")
            sourcetype = str(entry.get("sourcetype", "")).lower()
            path = root / relative
            family = file_family(entry)
            if family is not None and manifest in family_lists[family]:
                if path.is_file():
                    family_files.setdefault(family, []).append(path)
                else:
                    skipped.append(f"{relative}: not downloaded")
                continue
            if xml_only:
                continue
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
        for family, files in sorted(family_files.items()):
            _, platform, source_kind = _FAMILIES[family]
            captures.append(
                Capture(
                    id=f"{CORPUS}/{dataset_id}/{family}",
                    corpus=CORPUS,
                    kind="positive",
                    platform=platform,
                    source_kind=source_kind,
                    paths=tuple(sorted(files)),
                    techniques=live,
                    raw_labels=raw_ids,
                    label_notes=notes,
                    host="attack_range",
                    license=license_text,
                    notes={
                        "sourcetype": "XmlWinEventLog" if family == "windows" else "sysmon:linux",
                        "files": str(len(files)),
                        **({"skipped": "; ".join(skipped)} if skipped else {}),
                    },
                )
            )
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
