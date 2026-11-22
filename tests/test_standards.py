"""Standards data loaders with version drift reporting (B5)."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from bastion.attack import AttackData, load_attack_data
from bastion.cli import app
from bastion.models import TechniqueRef
from bastion.pins import load_pins, standards_pin_summary
from bastion.standards import load_standards
from bastion.standards.csf import load_csf_labels
from bastion.standards.dettect import load_dettect
from bastion.standards.drift import attack_drift
from bastion.standards.fetch import fetch_standards, standards_files, standards_path
from bastion.standards.mappings import load_car, load_ctid_800_53, load_d3fend

FIXTURES = Path(__file__).parent / "fixtures" / "standards"


def _attack() -> AttackData:
    return AttackData(
        techniques={
            tid: TechniqueRef(id=tid, name=tid)
            for tid in ("T1059", "T1059.001", "T1110", "T1110.001")
        },
        version="20.1",
        revoked_by={"T9001": "T1059"},
        deprecated=frozenset({"T9002"}),
        data_components=frozenset({"Command Execution"}),
    )


class TestDrift:
    def test_older_declared_release_warns(self) -> None:
        drift, resolved = attack_drift("X", "16.1", ["T1059", "t9001", "T9002", "T0000"], _attack())
        assert drift.older is True
        assert resolved == {"T1059": "T1059", "T9001": "T1059"}
        assert drift.revoked == {"T9001": "T1059"}
        assert drift.deprecated == ["T9002"] and drift.unknown == ["T0000"]
        assert drift.ids_total == 4 and drift.ids_live == 1
        assert drift.live_unmapped == 3 and drift.live_total == 4
        assert drift.warnings[0] == "X maps ATT&CK 16.1, older than the pinned 20.1"
        assert drift.as_dict()["older"] is True

    def test_no_declared_release_is_reported_not_guessed(self) -> None:
        drift, _ = attack_drift("Y", "", ["T1059"], _attack())
        assert drift.older is None
        assert drift.warnings == ["Y states no ATT&CK release; ids checked against 20.1"]

    def test_same_or_newer_release_has_no_version_warning(self) -> None:
        assert attack_drift("Z", "20.1", [], _attack())[0].warnings == []
        assert attack_drift("Z", "20.10", [], _attack())[0].older is False


class TestMappings:
    def test_d3fend_keeps_enterprise_rows_and_names_ids(self) -> None:
        mapping = load_d3fend(
            FIXTURES / "d3fend-1.6.0-mappings-excerpt.csv",
            FIXTURES / "d3fend-1.6.0-techniques-excerpt.csv",
            _attack(),
            "1.6.0",
        )
        assert mapping.skipped == {"ATTACKICSTechnique": 1}
        names = {(c.id, c.name, c.tactic) for c in mapping.for_technique("t1059")}
        assert names == {
            ("D3-EDL", "Executable Denylisting", "Isolate"),
            ("D3-EI", "Execution Isolation", "Isolate"),
        }
        assert mapping.for_technique("T1110.001")[0].id == "D3-TB"
        assert mapping.drift.older is None

    def test_ctid_drops_non_mappable_and_warns_on_old_release(self) -> None:
        mapping = load_ctid_800_53(FIXTURES / "ctid-800-53-attack-16.1-excerpt.json", _attack())
        assert mapping.skipped == {"non_mappable": 1}
        assert [c.id for c in mapping.for_technique("T1110")] == [
            "AC-06",
            "CA-07",
            "CM-06",
            "IA-05",
        ]
        assert mapping.drift.declared_attack_version == "16.1" and mapping.drift.older is True
        assert mapping.version == "rev5 for ATT&CK 16.1"

    def test_car_reads_a_checkout_and_an_archive(self, tmp_path: Path) -> None:
        from_dir = load_car(FIXTURES / "car-excerpt", _attack(), "1b922fe1527d")
        assert {a.id for a in from_dir.for_technique("T1059.001")} == {
            "CAR-2014-04-003",
            "CAR-2014-11-004",
        }
        archive = tmp_path / "car.zip"
        shutil.make_archive(str(archive.with_suffix("")), "zip", FIXTURES, "car-excerpt")
        from_zip = load_car(archive, _attack(), "1b922fe1527d")
        assert from_zip.entries == from_dir.entries
        assert from_dir.drift.older is None


class TestCsf:
    def test_labels_quote_csf_and_say_whose_assertion(self) -> None:
        labels = load_csf_labels()
        assert labels.version == "2.0"
        assert "Bastion" in labels.assertion
        outcomes = {o.id: o.text for label in labels.labels for o in label.outcomes}
        assert outcomes["DE.AE-03"] == "Information is correlated from multiple sources"
        assert {label.scope for label in labels.labels} <= {"full", "partial"}


class TestDettect:
    def test_technique_administration_scores_and_drift(self) -> None:
        loaded = load_dettect(FIXTURES / "dettect-techniques.yaml", _attack())
        assert loaded.supported and loaded.version == "1.2"
        assert loaded.techniques["T1059.001"] == {"detection": 3, "visibility": 4}
        assert loaded.techniques["T1059"] == {"detection": -1, "visibility": None}
        assert loaded.drift is not None and loaded.drift.deprecated == ["T9002"]
        assert any("revoked" in w for w in loaded.warnings)

    def test_data_source_administration_flags_unknown_components(self) -> None:
        loaded = load_dettect(FIXTURES / "dettect-data-sources.yaml", _attack())
        assert loaded.supported
        assert loaded.data_sources == {
            "Command Execution": ["Windows workstations"],
            "Not A Data Component": ["Windows workstations"],
        }
        assert loaded.unknown_data_sources == ["Not A Data Component"]

    def test_other_versions_and_types_are_reported(self, tmp_path: Path) -> None:
        old = tmp_path / "old.yaml"
        old.write_text(
            "version: 1.0\nfile_type: technique-administration\ntechniques: []\n", encoding="utf-8"
        )
        loaded = load_dettect(old, _attack())
        assert not loaded.supported and "format 1.0" in loaded.reason
        other = tmp_path / "groups.yaml"
        other.write_text("version: 1.0\nfile_type: group-administration\n", encoding="utf-8")
        assert "not one Bastion reads" in load_dettect(other, _attack()).reason


def _serve(payloads: dict[str, bytes]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=payloads[str(request.url)])

    return httpx.Client(transport=httpx.MockTransport(handler))


class TestFetchAndLoad:
    def test_strict_digest_mismatch_is_refused(self, tmp_path: Path) -> None:
        payloads = {f.url: b"not the pinned file" for f in standards_files()}
        with pytest.raises(ValueError, match="does not match the pin"):
            fetch_standards(tmp_path, client=_serve(payloads))
        assert not any(p.exists() for p in standards_path("d3fend", tmp_path))

    def test_unfetched_sources_are_reported_not_failed(self, tmp_path: Path) -> None:
        standards = load_standards(_attack(), tmp_path)
        rows = {row["source"]: row for row in standards.status()}
        assert rows["d3fend"]["fetched"] is False and rows["ctid_800_53"]["fetched"] is False
        assert rows["ctid_800_53"]["declared_attack_version"] == "16.1"
        assert rows["csf"]["fetched"] is True

    def test_fetched_sources_load_with_drift(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sources = {
            "d3fend-full-mappings.csv": FIXTURES / "d3fend-1.6.0-mappings-excerpt.csv",
            "d3fend.csv": FIXTURES / "d3fend-1.6.0-techniques-excerpt.csv",
            ".json": FIXTURES / "ctid-800-53-attack-16.1-excerpt.json",
        }
        archive = tmp_path / "car-src.zip"
        shutil.make_archive(str(archive.with_suffix("")), "zip", FIXTURES, "car-excerpt")
        payloads: dict[str, bytes] = {}
        for item in standards_files():
            source = next(
                (p for suffix, p in sources.items() if item.relative.endswith(suffix)), archive
            )
            payloads[item.url] = source.read_bytes()
        pins = load_pins()
        patched = json.loads(json.dumps(pins))
        for item in standards_files():
            digest = hashlib.sha256(payloads[item.url]).hexdigest()
            entry = patched["standards"][item.key]
            for key, value in list(entry.items()):
                if value == item.sha256:
                    entry[key] = digest
        monkeypatch.setattr("bastion.standards.fetch.load_pins", lambda: patched)
        rows = fetch_standards(tmp_path, client=_serve(payloads))
        assert {r["status"] for r in rows} == {"fetched"}
        again = fetch_standards(tmp_path, client=_serve(payloads))
        assert {r["status"] for r in again} == {"cached"}
        standards = load_standards(_attack(), tmp_path)
        assert standards.ctid_800_53 is not None and standards.ctid_800_53.drift.older is True
        assert standards.d3fend is not None and standards.car is not None
        status = {row["source"]: row for row in standards.status()}
        assert status["ctid_800_53"]["drift"]["warnings"][0].startswith(
            "CTID ATT&CK to NIST 800-53 maps ATT&CK 16.1"
        )


def test_standards_pins_are_flat_and_separate_from_bench_pins() -> None:
    summary = standards_pin_summary()
    assert summary["ocsf"] == "1.9.0" and summary["ecs"] == "9.5.0" and summary["d3fend"] == "1.6.0"
    assert summary["navigator"] == "4.5"
    assert summary["ctid_800_53"] == "69c2e8e00661"
    from bastion.pins import pin_summary

    assert not set(summary) & set(pin_summary())


def test_attack_loader_reads_data_components(tmp_path: Path) -> None:
    bundle = json.loads(
        (Path(__file__).parent / "fixtures" / "mini_attack.json").read_text(encoding="utf-8")
    )
    bundle["objects"].append(
        {
            "type": "x-mitre-data-component",
            "id": "x-mitre-data-component--1",
            "name": "Command Execution",
        }
    )
    bundle["objects"].append(
        {
            "type": "x-mitre-data-component",
            "id": "x-mitre-data-component--2",
            "name": "Gone",
            "x_mitre_deprecated": True,
        }
    )
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert load_attack_data(path).data_components == frozenset({"Command Execution"})


class TestCli:
    def test_status_and_technique_without_fetched_data(self, tmp_path: Path) -> None:
        runner = CliRunner()
        attack = str(Path(__file__).parent / "fixtures" / "mini_attack.json")
        result = runner.invoke(
            app,
            ["standards", "status", "--data-dir", str(tmp_path), "--attack-file", attack, "--json"],
        )
        assert result.exit_code == 0, result.output
        rows = {row["source"]: row for row in json.loads(result.output)["sources"]}
        assert rows["car"]["fetched"] is False
        result = runner.invoke(
            app,
            [
                "standards",
                "technique",
                "T1059",
                "--data-dir",
                str(tmp_path),
                "--attack-file",
                attack,
            ],
        )
        assert result.exit_code == 0 and "not fetched" in result.output

    def test_dettect_command(self) -> None:
        runner = CliRunner()
        attack = str(Path(__file__).parent / "fixtures" / "mini_attack.json")
        result = runner.invoke(
            app,
            [
                "standards",
                "dettect",
                str(FIXTURES / "dettect-data-sources.yaml"),
                "--attack-file",
                attack,
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        out = json.loads(result.output)
        assert out["supported"] is True and out["data_sources"] == 2

    def test_fetch_command_reports_rows_and_failures(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = CliRunner()
        monkeypatch.setattr(
            "bastion.cli_standards.fetch_standards",
            lambda data_dir, force: [
                {"file": "car/x.zip", "status": "fetched", "digest_matches": False},
                {"file": "ctid/y.json", "status": "cached", "digest_matches": True},
            ],
        )
        result = runner.invoke(app, ["standards", "fetch"])
        assert result.exit_code == 0
        assert (
            "digest differs from the pin" in result.output
            and "cached: ctid/y.json" in result.output
        )

        def fail(data_dir: Path, force: bool) -> list[dict[str, object]]:
            raise ValueError("sha256 mismatch")

        monkeypatch.setattr("bastion.cli_standards.fetch_standards", fail)
        result = runner.invoke(app, ["standards", "fetch"])
        assert result.exit_code == 1 and "Fetch failed" in result.output

    def test_tables_with_fetched_data(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mapping_dir = tmp_path / "standards"
        targets = dict(
            zip(
                [f.relative for f in standards_files()],
                [
                    FIXTURES / "d3fend-1.6.0-mappings-excerpt.csv",
                    FIXTURES / "d3fend-1.6.0-techniques-excerpt.csv",
                    FIXTURES / "ctid-800-53-attack-16.1-excerpt.json",
                    None,
                ],
                strict=True,
            )
        )
        for relative, source in targets.items():
            dest = mapping_dir / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            if source is None:
                shutil.make_archive(str(dest.with_suffix("")), "zip", FIXTURES, "car-excerpt")
            else:
                shutil.copy(source, dest)
        monkeypatch.setattr(
            "bastion.cli_standards._attack", lambda attack_file, data_dir: _attack()
        )
        runner = CliRunner()
        args = ["--data-dir", str(tmp_path)]
        result = runner.invoke(app, ["standards", "status", *args])
        assert result.exit_code == 0, result.output
        assert "16.1" in result.output and "older" in result.output
        result = runner.invoke(app, ["standards", "technique", "T1110", *args])
        assert result.exit_code == 0 and "AC-06" in result.output and "drift:" in result.output
        result = runner.invoke(app, ["standards", "technique", "T1059.001", *args, "--json"])
        out = json.loads(result.output)
        assert {e["id"] for e in out["car"]["entries"]} == {"CAR-2014-04-003", "CAR-2014-11-004"}
        result = runner.invoke(
            app, ["standards", "dettect", str(FIXTURES / "dettect-techniques.yaml"), *args]
        )
        assert result.exit_code == 0 and "supported" in result.output

    def test_missing_attack_bundle_exits(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(app, ["standards", "status", "--data-dir", str(tmp_path)])
        assert result.exit_code == 1
