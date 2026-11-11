"""Tests for the corpus loaders, fully offline with fake corpus trees and mock transports."""

from __future__ import annotations

import gzip
import io
import json
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from bastion.attack import load_attack_data
from bastion.bench.corpora import attack_data, citadel, evtx_baseline, evtx_samples, regression
from bastion.bench.corpora.fixtures import fixture_captures
from bastion.bench.labels import LabelRow
from bastion.pins import load_pins

REPO = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
EVTX = REPO / "examples" / "logs" / "sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx"
ATTACK = load_attack_data(FIXTURES / "mini_attack.json")


def _serving(payloads: dict[str, bytes]) -> httpx.Client:
    """Serve payloads by URL suffix; anything else is a 404."""

    def handler(request: httpx.Request) -> httpx.Response:
        for suffix, payload in payloads.items():
            if str(request.url).endswith(suffix):
                return httpx.Response(200, content=payload)
        return httpx.Response(404, content=b"missing")

    return httpx.Client(transport=httpx.MockTransport(handler))


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


# --- regression_data ------------------------------------------------------------------------


def _info(rule_id: str, entries: list[dict[str, object]]) -> str:
    doc = {
        "rule_metadata": [{"id": rule_id, "title": f"Rule {rule_id}"}],
        "regression_tests_info": entries,
    }
    return json.dumps(doc)


def test_fetch_regression_extracts_data_and_known_fps(tmp_path: Path) -> None:
    tag = load_pins()["sigma"]["tag"]
    payload = _zip(
        {
            f"sigma-{tag}/regression_data/rules/windows/x/info.yml": b"a: 1",
            f"sigma-{tag}/.github/workflows/known-FPs.csv": (
                b"RuleId;RuleName;MatchString\nr1;R;.*\n"
            ),
            f"sigma-{tag}/rules/windows/x.yml": b"title: not extracted",
        }
    )
    root = regression.fetch_regression(tmp_path, _serving({".zip": payload}))
    assert (root / "regression_data" / "rules" / "windows" / "x" / "info.yml").exists()
    assert regression.known_false_positives(root) == {"r1": [".*"]}
    assert not (root / "rules").exists()
    assert regression.known_false_positives(tmp_path / "nowhere") == {}


def test_regression_cases_and_captures(tmp_path: Path) -> None:
    root = tmp_path / "rel"
    case_dir = root / "regression_data" / "rules" / "windows" / "process_creation" / "case"
    case_dir.mkdir(parents=True)
    sample = case_dir / "11111111-1111-4111-8111-111111111111.evtx"
    sample.write_bytes(EVTX.read_bytes())
    rel = sample.relative_to(root).as_posix()
    (case_dir / "info.yml").write_text(
        _info(
            "11111111-1111-4111-8111-111111111111",
            [
                {"type": "evtx", "match_count": 1, "path": rel, "name": "positive"},
                {"type": "evtx", "path": rel},
                {"type": "json", "match_count": 1, "path": rel},
                {"type": "evtx", "match_count": 1, "path": "regression_data/missing.evtx"},
                {"type": "weird", "path": rel},
            ],
        ),
        encoding="utf-8",
    )
    et_dir = root / "regression_data" / "rules-emerging-threats" / "2025" / "y"
    et_dir.mkdir(parents=True)
    (et_dir / "info.yml").write_text(_info("", [{"type": "evtx", "path": rel}]), encoding="utf-8")
    broken = root / "regression_data" / "rules" / "broken"
    broken.mkdir(parents=True)
    (broken / "info.yml").write_text("a: [unclosed", encoding="utf-8")

    cases = regression.load_regression_cases(root)
    reasons = [c.skip_reason for c in cases]
    assert reasons.count(None) == 2
    assert regression.JSON_SKIP_REASON in reasons
    assert "sample file missing from the archive" in reasons
    assert "unknown sample type 'weird'" in reasons
    assert "info.yml names no rule id" in reasons
    assert any(r and r.startswith("info.yml does not parse") for r in reasons)
    assert cases[0].tree == "rules"
    captures = regression.regression_captures(cases)
    assert [c.id for c in captures] == [
        "regression/rules/11111111-1111-4111-8111-111111111111/0",
        "regression/rules/11111111-1111-4111-8111-111111111111/1",
    ]
    assert captures[0].expected_matches == {"11111111-1111-4111-8111-111111111111": 1}
    assert captures[1].expected_matches == {"11111111-1111-4111-8111-111111111111": None}
    assert captures[0].notes["case"] == "positive"
    assert sum(1 for _ in captures[0].events()) == 6


# --- EVTX-ATTACK-SAMPLES --------------------------------------------------------------------


def test_fetch_and_label_evtx_samples(tmp_path: Path) -> None:
    payload = _zip(
        {
            "repo-sha/Execution/one.evtx": EVTX.read_bytes(),
            "repo-sha/Persistence/two.EVTX": EVTX.read_bytes(),
            "repo-sha/README.md": b"readme",
        }
    )
    root = evtx_samples.fetch_evtx_samples(tmp_path, _serving({".zip": payload}))
    assert evtx_samples.sample_paths(root) == ["Execution/one.evtx", "Persistence/two.EVTX"]
    labels = {
        "Execution/one.evtx": LabelRow("Execution/one.evtx", "Execution", ("T9001", "T1110"), (2,))
    }
    captures = evtx_samples.evtx_sample_captures(root, labels, ATTACK)
    assert captures[0].techniques == ("T1059.001", "T1110")
    assert captures[0].label_notes == ("T9001 revoked, remapped to T1059.001",)
    assert captures[0].tactic == "Execution" and captures[0].platform == "windows"
    assert captures[1].techniques == () and "not named" in captures[1].notes["label"]
    assert captures[0].license == "GPL-3.0"


# --- evtx-baseline ---------------------------------------------------------------------------


def _tgz(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_baseline_sets_fetch_and_captures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sets = evtx_baseline.available_sets()
    assert "win2022-evtx" in sets and evtx_baseline.default_sets() == ["win2022-evtx"]
    with pytest.raises(ValueError, match="unknown evtx-baseline set"):
        evtx_baseline.fetch_baseline_set(tmp_path, "nope", _serving({}))
    payload = _tgz(
        {
            "win7-x86/Security.evtx": EVTX.read_bytes(),
            "win7-x86/Microsoft-Windows-Sysmon%4Operational.evtx": EVTX.read_bytes(),
        }
    )
    # The real asset size will not match a synthetic archive; pin the size to the payload.
    monkeypatch.setattr(
        evtx_baseline,
        "available_sets",
        lambda: {"win7-x86": ("https://x/win7-x86.tgz", len(payload))},
    )
    root = evtx_baseline.fetch_baseline_set(tmp_path, "win7-x86", _serving({".tgz": payload}))
    captures = evtx_baseline.baseline_captures(root, "win7-x86")
    assert [c.notes["channel"] for c in captures] == [
        "Microsoft-Windows-Sysmon/Operational",
        "Security",
    ]
    assert all(c.kind == "benign" and c.host == "win7-x86" for c in captures)
    only = evtx_baseline.baseline_captures(root, "win7-x86", channels=["security"])
    assert [c.notes["channel"] for c in only] == ["Security"]
    assert (
        evtx_baseline.channel_name(Path("Microsoft-Windows-DNS-Client%4Operational.evtx"))
        == "Microsoft-Windows-DNS-Client/Operational"
    )


# --- Splunk attack_data ----------------------------------------------------------------------

AUDIT_LINES = (FIXTURES / "audit_sample.log").read_text(encoding="utf-8").splitlines()


def test_normalize_auditd_sorts_by_epoch_and_serial(tmp_path: Path) -> None:
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    # Split one event's records across files, newest first, plus a stray non-audit line.
    a.write_text(
        "\n".join(reversed(AUDIT_LINES[:2])) + "\nMay  6 17:24:02 host su: junk\n", encoding="utf-8"
    )
    b.write_text("\n".join(reversed(AUDIT_LINES[2:])) + "\n", encoding="utf-8")
    dest = tmp_path / "sorted.log"
    types = attack_data.normalize_auditd([a, b], dest)
    lines = dest.read_text(encoding="utf-8").splitlines()
    audit_only = [line for line in AUDIT_LINES if line.startswith("type=")]
    # Records come back in (epoch, serial, kernel record order); stray lines sink to the end.
    assert lines[: len(audit_only)] == audit_only
    assert not any(line.startswith("type=") for line in lines[len(audit_only) :])
    assert any(line.startswith("May  6") for line in lines[len(audit_only) :])
    assert types["SYSCALL"] >= 1 and types["non-audit"] == 2
    # A normalized file left by an older Bastion is never reused: it is rewritten when stale,
    # and left alone (same bytes, same mtime) when current.
    dest.write_text("stale\n", encoding="utf-8")
    attack_data.normalize_auditd([a, b], dest)
    assert dest.read_text(encoding="utf-8") != "stale\n"
    before = dest.stat().st_mtime_ns
    attack_data.normalize_auditd([a, b], dest)
    assert dest.stat().st_mtime_ns == before
    attack_data.normalize_auditd([a, b], dest, force=True)
    assert dest.read_text(encoding="utf-8").startswith("type=SYSCALL")


def test_normalize_auditd_keeps_enriched_records_whole(tmp_path: Path) -> None:
    """str.splitlines() treats the \\x1d before an enriched half as a line break."""
    enriched = (
        'type=SYSCALL msg=audit(1724076881.293:4522): syscall=42 exe="/usr/sbin/route"'
        '\x1dARCH=x86_64 SYSCALL=connect AUID="ubuntu"'
    )
    source = tmp_path / "a.log"
    source.write_bytes((enriched + "\n").encode("utf-8"))
    dest = tmp_path / "sorted.log"
    types = attack_data.normalize_auditd([source], dest)
    assert dest.read_bytes().decode("utf-8") == enriched + "\n"
    assert types == {"SYSCALL": 1}


def test_normalize_auditd_sorts_interpreted_records(tmp_path: Path) -> None:
    newest = "type=PATH msg=audit(04/16/2025 09:14:42.784:96445) : item=0 name=/tmp"
    oldest = "type=SYSCALL msg=audit(04/16/2025 09:14:42.784:96444) : syscall=execve"
    raw_between = "type=SYSCALL msg=audit(1744794882.900:96446): syscall=59"
    source = tmp_path / "a.log"
    source.write_text("\n".join([raw_between, newest, oldest]) + "\n", encoding="utf-8")
    dest = tmp_path / "sorted.log"
    attack_data.normalize_auditd([source], dest)
    assert dest.read_text(encoding="utf-8").splitlines() == [oldest, newest, raw_between]


def _attack_data_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = attack_data.corpus_dir(tmp_path)
    manifest = "datasets/attack_techniques/T1110/linux_auditd_demo/linux_auditd_demo.yml"
    monkeypatch.setattr(attack_data, "dataset_manifests", lambda: [manifest])
    dataset_dir = root / "datasets/attack_techniques/T1110/linux_auditd_demo"
    dataset_dir.mkdir(parents=True)
    (dataset_dir / "part1.log").write_text("\n".join(AUDIT_LINES[:2]) + "\n", encoding="utf-8")
    (dataset_dir / "part2.log").write_text("\n".join(AUDIT_LINES[2:]) + "\n", encoding="utf-8")
    (dataset_dir / "secure.log").write_text(
        (FIXTURES / "auth_sample.log").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (root / manifest).write_text(
        json.dumps(
            {
                "mitre_technique": ["T1110", "T9002"],
                "datasets": [
                    {
                        "path": "/datasets/attack_techniques/T1110/linux_auditd_demo/part1.log",
                        "sourcetype": "auditd",
                    },
                    {
                        "path": "/datasets/attack_techniques/T1110/linux_auditd_demo/part2.log",
                        "sourcetype": "auditd",
                    },
                    {
                        "path": "/datasets/attack_techniques/T1110/linux_auditd_demo/secure.log",
                        "sourcetype": "linux_secure",
                    },
                    {
                        "path": "/datasets/attack_techniques/T1110/linux_auditd_demo/sysmon.log",
                        "sourcetype": "sysmon_linux",
                    },
                    {
                        "path": "/datasets/attack_techniques/T1110/linux_auditd_demo/gone.log",
                        "sourcetype": "auditd",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    (dataset_dir / "sysmon.log").write_text("<Event/>", encoding="utf-8")
    return root


def test_attack_data_captures_route_by_sourcetype(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _attack_data_root(tmp_path, monkeypatch)
    captures = attack_data.attack_data_captures(root, ATTACK)
    by_id = {c.id: c for c in captures}
    assert set(by_id) == {
        "attack_data/T1110/linux_auditd_demo/secure.log",
        "attack_data/T1110/linux_auditd_demo/auditd",
    }
    audit = by_id["attack_data/T1110/linux_auditd_demo/auditd"]
    assert audit.techniques == ("T1110",)
    assert "T9002 deprecated" in audit.label_notes[0]
    assert audit.notes["files"] == "2" and "SYSCALL" in audit.notes["record_types"]
    assert "sysmon_linux" in audit.notes["skipped"] and "not downloaded" in audit.notes["skipped"]
    assert audit.paths[0].name == attack_data.NORMALIZED_AUDITD
    assert sum(1 for _ in audit.events()) >= 2
    assert by_id["attack_data/T1110/linux_auditd_demo/secure.log"].source_kind == "syslog"
    # A manifest that was never fetched is skipped quietly.
    monkeypatch.setattr(
        attack_data, "dataset_manifests", lambda: ["datasets/attack_techniques/T0000/x/x.yml"]
    )
    assert attack_data.attack_data_captures(root, ATTACK) == []


def test_fetch_attack_data_downloads_yaml_then_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = "datasets/attack_techniques/T1110/demo/demo.yml"
    yaml_text = json.dumps(
        {
            "datasets": [
                {"path": "/datasets/attack_techniques/T1110/demo/demo.log", "sourcetype": "auditd"}
            ]
        }
    )
    client = _serving(
        {"demo.yml": yaml_text.encode(), "demo.log": b"type=SYSCALL msg=audit(1.0:1): a=b\n"}
    )
    root = attack_data.fetch_attack_data(tmp_path, client, manifests=[manifest])
    assert (root / manifest).read_text(encoding="utf-8") == yaml_text
    assert (
        (root / "datasets/attack_techniques/T1110/demo/demo.log").read_bytes().startswith(b"type=")
    )


def test_fetch_attack_data_builds_a_client_when_none_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def fake_fetch(cache: Path, client: object, force: bool, manifests: list[str] | None) -> Path:
        calls.append("inner")
        return cache

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: _serving({}))
    original = attack_data.fetch_attack_data
    # The recursion passes the built client back into the same function; intercept the second call.
    monkeypatch.setattr(
        attack_data,
        "fetch_attack_data",
        lambda cache, client=None, force=False, manifests=None: (
            original(cache, client, force, manifests)
            if client is not None
            else fake_fetch(cache, client, force, manifests)
        ),
    )
    attack_data.fetch_attack_data(tmp_path, manifests=[])
    assert calls == ["inner"]


# --- Citadel captures -----------------------------------------------------------------------


def _citadel_dir(tmp_path: Path) -> Path:
    base = datetime.fromtimestamp(1780000000, tz=UTC)  # matches the fixture audit log's epoch
    audit = tmp_path / "audit.log.gz"
    with gzip.open(audit, "wt", encoding="utf-8") as out:
        out.write("\n".join(AUDIT_LINES) + "\n")
    captures = tmp_path / "captures"
    v1 = captures / "v1-2026-09-01"
    v1.mkdir(parents=True)
    (v1 / "audit.log.gz").write_bytes(audit.read_bytes())
    (v1 / "capture.json").write_text(
        json.dumps(
            {
                "version": 1,
                "clock": {"seconds": 0.0, "uncertainty": 0.05},
                "failures": {"T9999/failed": "did not run"},
                "runs": [
                    {
                        "identifier": "T1110/run-a",
                        "technique": "T1110",
                        "started_at": base.isoformat(),
                        "finished_at": base.replace(microsecond=150000).isoformat(),
                        "cleanup_started_at": base.replace(microsecond=300000).isoformat(),
                        "cleanup_finished_at": base.replace(microsecond=400000).isoformat(),
                    },
                    {
                        "identifier": "T9999/failed",
                        "technique": "T9999",
                        "started_at": base.isoformat(),
                        "finished_at": base.isoformat(),
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    v2 = captures / "v2-2026-09-02"
    (v2 / "segments" / "000").mkdir(parents=True)
    (v2 / "segments" / "000" / "audit.log.gz").write_bytes(audit.read_bytes())
    (v2 / "segments" / "001").mkdir(parents=True)  # no audit log
    (v2 / "capture.json").write_text(
        json.dumps(
            {
                "version": 2,
                "segments": [
                    {
                        "logs": "segments/000",
                        "clock": None,
                        "runs": [
                            {
                                "identifier": "T1110/x",
                                "technique": "T1110",
                                "started_at": base.isoformat(),
                                "finished_at": base.isoformat(),
                            }
                        ],
                    },
                    {"logs": "segments/001", "clock": {"seconds": 0}, "runs": []},
                ],
            }
        ),
        encoding="utf-8",
    )
    (captures / "empty").mkdir()
    return captures


def test_citadel_captures_windows_failures_and_skips(tmp_path: Path) -> None:
    captures_dir = _citadel_dir(tmp_path)
    found, skipped = citadel.citadel_captures(
        captures_dir, tmp_path / "cache", ATTACK, ["v1-2026-09-01", "v2-2026-09-02", "empty"]
    )
    ids = [c.id for c in found]
    assert ids == [
        "citadel_captures/v1-2026-09-01/T1110/run-a",
        "citadel_captures/v1-2026-09-01/0/benign",
    ]
    run = found[0]
    assert run.techniques == ("T1110",) and run.notes["split"] == "dev"
    assert run.window is not None and run.exclude_windows and run.kind == "positive"
    events = list(run.events())
    assert (
        len(events) == 1 and events[0].fields["Image"] == "/usr/bin/cat"
    )  # first record at +0.101s
    benign = found[1]
    assert benign.kind == "benign" and len(benign.exclude_windows) == 2
    assert [e.fields.get("Image") for e in benign.events()] == ["/usr/bin/curl"]
    assert any("run failed in the lab" in s for s in skipped)
    assert any("no clock offset" in s for s in skipped)
    assert any("no audit.log.gz" in s for s in skipped)
    assert any("no capture.json" in s for s in skipped)
    assert citadel.default_capture_names() and citadel.default_captures_dir().name == "captures"


# --- in-repo fixtures ------------------------------------------------------------------------


def test_fixture_captures_from_committed_labels() -> None:
    captures = fixture_captures(REPO, REPO / "bench" / "labels" / "fixtures.csv", ATTACK)
    ids = {c.id for c in captures}
    assert "fixtures/tests/fixtures/auth_sample.log" in ids
    auth = next(c for c in captures if c.id.endswith("tests/fixtures/auth_sample.log"))
    assert auth.kind == "fixture" and auth.techniques == ("T1110",)
    assert all(c.platform == "linux" for c in captures)


def test_fixture_captures_skip_missing_files(tmp_path: Path) -> None:
    labels = tmp_path / "labels.csv"
    labels.write_text(
        "path,source_kind,platform,technique_ids\nnope.log,syslog,linux,T1110\n", encoding="utf-8"
    )
    assert fixture_captures(tmp_path, labels, ATTACK) == []
