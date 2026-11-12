"""Sigma correlation (B4 lever c, ported from Citadel M2): parsing, semantics, engine, CLI."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from bastion.cli import app
from bastion.engine import scan
from bastion.models import Event, FieldValue, SigmaRule
from bastion.sigma.correlation import (
    CorrelationError,
    CorrelationRule,
    UnsupportedCorrelation,
    correlation_techniques,
    load_correlations,
    parse_correlation,
    parse_timespan,
)
from bastion.sigma.loader import load_rules

T0 = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
LOCAL = Path(__file__).parent.parent / "rules"


def _event(seconds: float, **fields: FieldValue) -> Event:
    return Event(
        timestamp=T0 + timedelta(seconds=seconds),
        platform="windows",
        source="Security.evtx",
        fields={"Channel": "Security", "Computer": "dc1", **fields},
        raw="<Event/>",
    )


def _doc(correlation: dict[str, Any], *blocks: dict[str, Any], **head: Any) -> list[dict[str, Any]]:
    header = {"title": "C", "id": "corr-1", "status": "test", "level": "high", **head}
    return [{**header, "correlation": correlation}, *blocks]


FAILED: dict[str, Any] = {
    "name": "failed",
    "logsource": {"product": "windows", "service": "security"},
    "detection": {"sel": {"EventID": 4625}, "condition": "sel"},
}
SUCCESS: dict[str, Any] = {
    "name": "success",
    "logsource": {"product": "windows", "service": "security"},
    "detection": {"sel": {"EventID": 4624}, "condition": "sel"},
}


def _rule(correlation: dict[str, Any], *blocks: dict[str, Any], **head: Any) -> CorrelationRule:
    return parse_correlation(_doc(correlation, *blocks, **head), Path("c.yml"))


def test_parse_timespan_units_and_rejects_others() -> None:
    assert parse_timespan("10s") == timedelta(seconds=10)
    assert parse_timespan("5m") == timedelta(minutes=5)
    assert parse_timespan("1d") == timedelta(days=1)
    with pytest.raises(CorrelationError):
        parse_timespan("5 minutes")


@pytest.mark.parametrize(
    ("correlation", "blocks", "head", "error", "message"),
    [
        ({"type": "event_count"}, [FAILED], {"generate": True}, CorrelationError, "generate"),
        ({"type": "nope"}, [FAILED], {}, CorrelationError, "not in the specification"),
        ({"type": "value_sum"}, [FAILED], {}, UnsupportedCorrelation, "not evaluated"),
        (
            {"type": "event_count", "rules": ["failed"], "timespan": "1m", "condition": {"gte": 2}},
            [FAILED],
            {},
            CorrelationError,
            "group-by",
        ),
        (
            {
                "type": "event_count",
                "rules": ["other"],
                "group-by": ["x"],
                "timespan": "1m",
                "condition": {"gte": 2},
            },
            [FAILED],
            {},
            CorrelationError,
            "not in `rules`",
        ),
        (
            {"type": "event_count", "rules": ["failed"], "group-by": ["x"], "timespan": "1m"},
            [FAILED],
            {},
            CorrelationError,
            "needs a condition",
        ),
        (
            {
                "type": "value_count",
                "rules": ["failed"],
                "group-by": ["x"],
                "timespan": "1m",
                "condition": {"gte": 2},
            },
            [FAILED],
            {},
            CorrelationError,
            "needs a `field`",
        ),
        (
            {
                "type": "value_count",
                "rules": ["failed"],
                "group-by": ["x"],
                "timespan": "1m",
                "condition": {"field": ["a", "b"], "gte": 2},
            },
            [FAILED],
            {},
            UnsupportedCorrelation,
            "several fields",
        ),
        (
            {
                "type": "event_count",
                "rules": ["failed"],
                "group-by": ["x"],
                "timespan": "1m",
                "condition": {"about": 2},
            },
            [FAILED],
            {},
            CorrelationError,
            "not a comparison",
        ),
        (
            {
                "type": "event_count",
                "rules": ["failed"],
                "group-by": ["x"],
                "timespan": "1m",
                "condition": {"gte": 2},
            },
            [{"detection": {}}],
            {},
            CorrelationError,
            "no name",
        ),
    ],
)
def test_parse_refuses_what_the_specification_or_adr_forbids(
    correlation: dict[str, Any],
    blocks: list[dict[str, Any]],
    head: dict[str, Any],
    error: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error, match=message):
        _rule(correlation, *blocks, **head)


def test_value_count_slides_and_counts_distinct_values() -> None:
    rule = _rule(
        {
            "type": "value_count",
            "rules": ["failed"],
            "group-by": ["IpAddress"],
            "timespan": "1m",
            "condition": {"field": "TargetUserName", "gte": 3},
        },
        FAILED,
    )
    events = [
        _event(0, EventID=4625, IpAddress="10.0.0.1", TargetUserName="a"),
        _event(1, EventID=4625, IpAddress="10.0.0.1", TargetUserName="a"),  # same account
        _event(2, EventID=4625, IpAddress="10.0.0.2", TargetUserName="b"),  # other source
        _event(70, EventID=4625, IpAddress="10.0.0.1", TargetUserName="b"),
        _event(80, EventID=4625, IpAddress="10.0.0.1", TargetUserName="c"),
        _event(90, EventID=4625, IpAddress="10.0.0.1", TargetUserName="d"),
        _event(95, EventID=4624, IpAddress="10.0.0.1", TargetUserName="e"),  # not an input
    ]
    outcome = scan(events, [], {}, correlations=[rule])
    findings = outcome.correlation.findings
    assert len(findings) == 1  # b, c, d inside one minute; a is 70 s earlier
    assert findings[0].group == {"IpAddress": "10.0.0.1"}
    assert len(findings[0].events) == 3 and outcome.detections == []


def test_upper_bounds_tumble_rather_than_slide() -> None:
    rule = _rule(
        {
            "type": "event_count",
            "rules": ["failed"],
            "group-by": ["IpAddress"],
            "timespan": "1m",
            "condition": {"lt": 3},
        },
        FAILED,
    )
    events = [_event(s, EventID=4625, IpAddress="x") for s in (0, 1, 2)]
    assert scan(events, [], {}, correlations=[rule]).correlation.findings == []


def test_temporal_ordered_needs_the_order() -> None:
    rule = _rule(
        {
            "type": "temporal_ordered",
            "rules": ["failed", "success"],
            "group-by": ["TargetUserName"],
            "timespan": "5m",
        },
        FAILED,
        SUCCESS,
    )
    ordered = [
        _event(0, EventID=4625, TargetUserName="u"),
        _event(5, EventID=4624, TargetUserName="u"),
    ]
    reversed_ = [
        _event(0, EventID=4624, TargetUserName="v"),
        _event(5, EventID=4625, TargetUserName="v"),
    ]
    assert len(scan(ordered, [], {}, correlations=[rule]).correlation.findings) == 1
    assert scan(reversed_, [], {}, correlations=[rule]).correlation.findings == []
    temporal = _rule(
        {
            "type": "temporal",
            "rules": ["failed", "success"],
            "group-by": ["TargetUserName"],
            "timespan": "5m",
        },
        FAILED,
        SUCCESS,
    )
    assert len(scan(reversed_, [], {}, correlations=[temporal]).correlation.findings) == 1


def test_ungrouped_events_and_pid_collisions_are_reported() -> None:
    rule = _rule(
        {
            "type": "event_count",
            "rules": ["failed"],
            "group-by": ["pid"],
            "timespan": "1m",
            "condition": {"gte": 2},
        },
        FAILED,
    )
    events = [
        _event(0, EventID=4625),  # no pid: ungrouped
        _event(1, EventID=4625, pid=7, Image="a"),
        _event(2, EventID=4625, pid=7, Image="b"),  # same pid, another image
    ]
    outcome = scan(events, [], {}, correlations=[rule]).correlation
    assert outcome.ungrouped == {"corr-1": 1}
    assert outcome.collisions == {"corr-1": 1} and outcome.findings == []


def test_external_rules_and_constituent_techniques() -> None:
    external = SigmaRule(
        id="ext-1",
        title="Failed logon rule",
        logsource={"product": "windows", "service": "security"},
        detection={"sel": {"EventID": 4625}, "condition": "sel"},
        attack_techniques=["T1110"],
    )
    rule = _rule(
        {
            "type": "event_count",
            "rules": ["ext-1"],
            "group-by": ["IpAddress"],
            "timespan": "1m",
            "condition": {"gte": 2},
        },
        tags=["attack.t1110", "attack.t1078"],
    )
    assert correlation_techniques(rule, {"ext-1": external}) == (["T1110"], ["T1078"])
    events = [_event(s, EventID=4625, IpAddress="x") for s in (0, 1)]
    outcome = scan(events, [external], {}, correlations=[rule])
    assert len(outcome.detections) == 2  # the external rule alerts on its own
    assert outcome.correlation.findings[0].techniques == ["T1110"]
    untagged = _rule(
        {
            "type": "event_count",
            "rules": ["ext-1"],
            "group-by": ["IpAddress"],
            "timespan": "1m",
            "condition": {"gte": 2},
        },
    )
    assert correlation_techniques(untagged, {"ext-1": external}) == (["T1110"], [])


def test_unsupported_building_block_is_recorded_not_fatal() -> None:
    bad = {**FAILED, "detection": {"sel": {"EventID|fieldref": "x"}, "condition": "sel"}}
    rule = _rule(
        {
            "type": "event_count",
            "rules": ["failed"],
            "group-by": ["IpAddress"],
            "timespan": "1m",
            "condition": {"gte": 1},
        },
        bad,
    )
    outcome = scan([_event(0, EventID=4625, IpAddress="x")], [], {}, correlations=[rule])
    assert "corr-1:failed" in outcome.correlation.unsupported_rules


def test_loader_skips_correlation_files_and_correlation_loader_reads_them(tmp_path: Path) -> None:
    good = _doc(
        {
            "type": "event_count",
            "rules": ["failed"],
            "group-by": ["IpAddress"],
            "timespan": "1m",
            "condition": {"gte": 2},
        },
        FAILED,
    )
    (tmp_path / "good.yml").write_text(yaml.safe_dump_all(good), encoding="utf-8")
    (tmp_path / "sum.yml").write_text(
        yaml.safe_dump_all(_doc({"type": "value_sum"}, FAILED)), encoding="utf-8"
    )
    (tmp_path / "broken.yml").write_text(
        yaml.safe_dump_all(_doc({"type": "event_count"}, FAILED, generate=True)), encoding="utf-8"
    )
    (tmp_path / "plain.yml").write_text(
        yaml.safe_dump({"title": "p", "detection": {"s": {"a": 1}, "condition": "s"}}),
        encoding="utf-8",
    )
    assert [r.title for r in load_rules(tmp_path)] == ["p"]  # building blocks never load
    loaded = load_correlations(tmp_path)
    assert [c.id for c in loaded.rules] == ["corr-1"]
    assert list(map(Path, loaded.unsupported)) == [tmp_path / "sum.yml"]
    assert list(map(Path, loaded.errors)) == [tmp_path / "broken.yml"]
    assert load_correlations(tmp_path / "missing").rules == []


# --- the local correlation rules (B4) -----------------------------------------------------


def _local(title: str) -> CorrelationRule:
    loaded = load_correlations(LOCAL)
    assert not loaded.errors and not loaded.unsupported
    return next(c for c in loaded.rules if c.header.title == title)


def test_password_spray_fires_on_many_accounts_from_one_source() -> None:
    rule = _local("Failed Logons For Many Accounts From One Source")
    spray = [
        _event(i, EventID=4625, IpAddress="10.0.1.15", TargetUserName=f"user{i}", LogonType="3")
        for i in range(12)
    ]
    findings = scan(spray, [], {}, correlations=[rule]).correlation.findings
    assert len(findings) == 1 and findings[0].techniques == ["T1110.003"]


@pytest.mark.parametrize(
    "events",
    [
        # one account failing many times (a typo loop or lockout, not a spray)
        [_event(i, EventID=4625, IpAddress="10.0.1.15", TargetUserName="alice") for i in range(30)],
        # nine accounts: under the threshold
        [_event(i, EventID=4625, IpAddress="10.0.1.15", TargetUserName=f"u{i}") for i in range(9)],
        # twelve accounts, one every 30 minutes
        [
            _event(i * 1800, EventID=4625, IpAddress="1.2.3.4", TargetUserName=f"u{i}")
            for i in range(12)
        ],
        # twelve accounts from twelve sources
        [
            _event(i, EventID=4625, IpAddress=f"10.0.0.{i}", TargetUserName=f"u{i}")
            for i in range(12)
        ],
        # twelve successful logons
        [_event(i, EventID=4624, IpAddress="10.0.1.15", TargetUserName=f"u{i}") for i in range(12)],
    ],
)
def test_password_spray_stays_quiet_on_benign_patterns(events: list[Event]) -> None:
    rule = _local("Failed Logons For Many Accounts From One Source")
    assert scan(events, [], {}, correlations=[rule]).correlation.findings == []


def test_kerberos_spray_counts_both_failure_kinds_and_ignores_others() -> None:
    rule = _local("Kerberos Authentication Failures For Many Accounts From One Source")
    mixed = [
        _event(
            i,
            EventID=4771 if i % 2 else 4768,
            Status="0x18" if i % 2 else "0x6",
            IpAddress="::ffff:10.0.1.15",
            TargetUserName=f"user{i}",
        )
        for i in range(10)
    ]
    assert len(scan(mixed, [], {}, correlations=[rule]).correlation.findings) == 1
    successes = [
        _event(i, EventID=4768, Status="0x0", IpAddress="::ffff:10.0.1.15", TargetUserName=f"u{i}")
        for i in range(20)
    ]
    assert scan(successes, [], {}, correlations=[rule]).correlation.findings == []


def test_ported_discovery_burst_is_hunting_status_and_fires_on_a_burst() -> None:
    rule = _local("Several Host Discovery Commands From One Parent")
    assert rule.header.status == "experimental"

    def proc(seconds: float, image: str, ppid: int) -> Event:
        return Event(
            timestamp=T0 + timedelta(seconds=seconds),
            platform="linux",
            source="audit.log",
            fields={"Image": image, "ppid": ppid},
            raw="",
            # an audit record makes it a merged auditd exec event, which process_creation reads
            records=[
                Event(platform="linux", source="audit.log", fields={"type": "EXECVE"}, raw="")
            ],
        )

    burst = [proc(0, "/usr/bin/whoami", 10), proc(1, "/usr/bin/id", 10), proc(2, "/bin/uname", 10)]
    spread = [
        proc(0, "/usr/bin/whoami", 11),
        proc(30, "/usr/bin/id", 11),
        proc(60, "/bin/uname", 11),
    ]
    assert len(scan(burst, [], {}, correlations=[rule]).correlation.findings) == 1
    assert scan(spread, [], {}, correlations=[rule]).correlation.findings == []


def test_cli_scan_reports_correlation_findings(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "corr.yml").write_text(
        yaml.safe_dump_all(
            _doc(
                {
                    "type": "event_count",
                    "rules": ["sudo_fail"],
                    "group-by": ["host"],
                    "timespan": "1d",
                    "condition": {"gte": 1},
                },
                {
                    "name": "sudo_fail",
                    "logsource": {"product": "linux"},
                    "detection": {"k": ["Failed password"], "condition": "k"},
                },
                tags=["attack.t1110"],
            )
        ),
        encoding="utf-8",
    )
    (rules_dir / "unsupported.yml").write_text(
        yaml.safe_dump_all(_doc({"type": "value_avg"}, FAILED)), encoding="utf-8"
    )
    fixtures = Path(__file__).parent / "fixtures"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(fixtures / "auth_sample.log"),
            "--rules-dir",
            str(rules_dir),
            "--attack-file",
            str(fixtures / "mini_attack.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Correlation:" in result.output and "T1110" in result.output
    assert "Correlation not evaluated" in result.output


def test_a_group_may_mix_naive_and_zoned_timestamps() -> None:
    rule = _rule(
        {
            "type": "event_count",
            "rules": ["failed"],
            "group-by": ["IpAddress"],
            "timespan": "1m",
            "condition": {"gte": 2},
        },
        FAILED,
    )
    zoned = _event(0, EventID=4625, IpAddress="x")
    naive = _event(5, EventID=4625, IpAddress="x")
    naive.timestamp = naive.timestamp.replace(tzinfo=None) if naive.timestamp else None
    assert len(scan([zoned, naive], [], {}, correlations=[rule]).correlation.findings) == 1
