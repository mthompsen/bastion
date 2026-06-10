"""Tests for report rendering: Markdown, JSON, and the HTML dashboard."""

from __future__ import annotations

import json
import re
from pathlib import Path

from bastion.attack import load_attack
from bastion.coverage import summarize_coverage
from bastion.engine import scan
from bastion.models import Event, ScanResult
from bastion.report import (
    ReportContext,
    detections_by_tactic,
    render_dashboard,
    render_markdown,
    write_report,
)
from bastion.sigma.loader import load_rules

FIXTURES = Path(__file__).parent / "fixtures"
ATTACK = load_attack(FIXTURES / "mini_attack.json")
RULES = load_rules(FIXTURES / "rules")

PS_EVENT = Event(
    platform="windows",
    source="sample.evtx",
    fields={
        "EventID": 1,
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
    },
    raw="<Event><EventData>powershell -enc &amp; evil</EventData></Event>",
)


def build_result() -> tuple[ScanResult, ReportContext]:
    outcome = scan([PS_EVENT], RULES, ATTACK)
    summary = summarize_coverage(RULES, ATTACK)
    result = ScanResult(
        detections=outcome.detections,
        events_scanned=outcome.events_scanned,
        rules_loaded=len(RULES),
        coverage=summary.entries,
    )
    context = ReportContext(
        logfile="sample.evtx",
        platform="windows",
        attack_version="99.0",
        sigma_version="r2026-04-01",
        unsupported_rule_count=1,
        rule_error_count=0,
        unresolved_techniques=["T9999"],
    )
    return result, context


SUMMARY = summarize_coverage(RULES, ATTACK)


class TestMarkdown:
    def test_contains_detections_and_coverage(self) -> None:
        result, context = build_result()
        text = render_markdown(result, SUMMARY, context)
        assert "Suspicious Encoded PowerShell Command" in text
        assert "T1059.001 PowerShell" in text
        assert "`CommandLine=" in text
        assert "2 of 3" in text.replace("**", "")
        assert "T1059" in text  # the blind spot is named
        assert "T9999" in text  # unresolved tag surfaced

    def test_pipe_characters_are_escaped_in_cells(self) -> None:
        result, context = build_result()
        result.detections[0].matched_fields["CommandLine"] = "a | b"
        text = render_markdown(result, SUMMARY, context)
        assert r"a \| b" in text


class TestDashboard:
    def test_contains_evidence_and_blind_spots(self) -> None:
        result, context = build_result()
        html = render_dashboard(result, SUMMARY, context)
        assert "Suspicious Encoded PowerShell Command" in html
        assert "powershell.exe -nop -w hidden -enc SQBFAFgA" in html
        assert 'class="chip miss"' in html  # uncovered technique chip
        assert 'class="chip ok"' in html
        assert "techniques with no detection rule" in html

    def test_raw_log_content_is_html_escaped(self) -> None:
        result, context = build_result()
        html = render_dashboard(result, SUMMARY, context)
        assert "<Event><EventData>" not in html
        assert "&lt;Event&gt;" in html

    def test_no_external_resources(self) -> None:
        result, context = build_result()
        html = render_dashboard(result, SUMMARY, context)
        assert not re.search(r'(src|href)\s*=\s*"https?://', html)
        assert "<script" not in html


class TestWriteReport:
    def test_writes_all_three_artifacts(self, tmp_path: Path) -> None:
        result, context = build_result()
        paths = write_report(result, SUMMARY, context, tmp_path / "out")
        assert set(paths) == {"report.md", "result.json", "dashboard.html"}
        for path in paths.values():
            assert path.exists() and path.stat().st_size > 0

    def test_json_round_trips_to_scan_result(self, tmp_path: Path) -> None:
        result, context = build_result()
        paths = write_report(result, SUMMARY, context, tmp_path)
        data = json.loads(paths["result.json"].read_text(encoding="utf-8"))
        restored = ScanResult.model_validate(data)
        assert restored == result

    def test_output_is_deterministic(self, tmp_path: Path) -> None:
        result, context = build_result()
        first = render_markdown(result, SUMMARY, context)
        second = render_markdown(result, SUMMARY, context)
        assert first == second


class TestGrouping:
    def test_detections_grouped_by_tactic(self) -> None:
        result, _ = build_result()
        groups = detections_by_tactic(result.detections)
        assert "execution" in groups
        assert groups["execution"][0].rule_title == "Suspicious Encoded PowerShell Command"

    def test_unmapped_detections_get_their_own_group(self) -> None:
        result, _ = build_result()
        result.detections[0].techniques = []
        groups = detections_by_tactic(result.detections)
        assert "unmapped" in groups
