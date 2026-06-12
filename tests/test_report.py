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
    render_sarif,
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
        assert "writable gaps" in html

    def test_raw_log_content_is_html_escaped(self) -> None:
        result, context = build_result()
        html = render_dashboard(result, SUMMARY, context)
        assert "<Event><EventData>" not in html
        assert "&lt;Event&gt;" in html

    def test_explains_uncovered_split_with_counts(self) -> None:
        result, context = build_result()
        html = render_dashboard(result, SUMMARY, context)
        assert "writable gaps: visible in this telemetry, no rule" in html
        assert "needs telemetry Bastion does not read" in html
        assert "Linux component at all" in html
        assert "never understates the work" in html

    def test_no_external_resources(self) -> None:
        result, context = build_result()
        html = render_dashboard(result, SUMMARY, context)
        assert not re.search(r'(src|href)\s*=\s*"https?://', html)
        assert "<script" not in html


class TestSarif:
    def test_valid_sarif_structure(self) -> None:
        result, context = build_result()
        sarif = json.loads(render_sarif(result, context))
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "bastion"
        assert len(run["results"]) == len(result.detections)
        rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        assert {res["ruleId"] for res in run["results"]} <= rule_ids

    def test_level_mapping_and_message_content(self) -> None:
        result, context = build_result()
        sarif = json.loads(render_sarif(result, context))
        res = sarif["runs"][0]["results"][0]
        assert res["level"] == "error"  # the fixture rule is level high
        assert "T1059.001" in res["message"]["text"]
        assert "CommandLine=" in res["message"]["text"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "sample.evtx"
        assert res["properties"]["matchedFields"]["CommandLine"]

    def test_no_detections_gives_empty_results(self) -> None:
        _, context = build_result()
        empty = ScanResult(events_scanned=1, rules_loaded=1, coverage=SUMMARY.entries)
        sarif = json.loads(render_sarif(empty, context))
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


class TestTimeline:
    def test_timeline_orders_by_timestamp(self) -> None:
        from datetime import UTC, datetime

        result, context = build_result()
        early = result.detections[0].model_copy(deep=True)
        late = result.detections[0].model_copy(deep=True)
        early.event.timestamp = datetime(2026, 6, 10, 6, 0, 0, tzinfo=UTC)
        early.rule_title = "Earlier Detection"
        late.event.timestamp = datetime(2026, 6, 10, 7, 0, 0, tzinfo=UTC)
        late.rule_title = "Later Detection"
        no_ts = result.detections[0].model_copy(deep=True)
        no_ts.event.timestamp = None
        no_ts.rule_title = "Timestampless Detection"
        result.detections = [late, no_ts, early]
        html = render_dashboard(result, SUMMARY, context)
        assert "Timeline" in html
        # Rule titles also appear in the by-tactic section, so compare order
        # inside the timeline block only.
        timeline_html = html[html.index('class="timeline"') :]
        assert timeline_html.index("Earlier Detection") < timeline_html.index("Later Detection")
        # Detections without a timestamp sort last.
        assert timeline_html.index("Later Detection") < timeline_html.index(
            "Timestampless Detection"
        )


class TestWriteReport:
    def test_writes_all_artifacts(self, tmp_path: Path) -> None:
        result, context = build_result()
        paths = write_report(result, SUMMARY, context, tmp_path / "out")
        assert set(paths) == {"report.md", "result.json", "result.sarif", "dashboard.html"}
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
