"""Tests for the Capture model: parsing through ingesters and window filtering."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from bastion.bench.captures import Capture
from bastion.models import Event

FIXTURES = Path(__file__).parent / "fixtures"


def _event(ts: datetime | None) -> Event:
    return Event(timestamp=ts, platform="linux", source="x", fields={}, raw="r")


def test_events_parse_files_with_the_named_ingester() -> None:
    auth = Capture("c", "t", "positive", "linux", "syslog", (FIXTURES / "auth_sample.log",))
    audit = Capture("a", "t", "positive", "linux", "auditd", (FIXTURES / "audit_sample.log",))
    assert sum(1 for _ in auth.events()) == 7
    audit_events = list(audit.events())
    assert audit_events and audit_events[0].fields["Image"] == "/usr/bin/cat"
    assert not auth.labelled


def test_window_and_exclusions_filter_by_event_time() -> None:
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    stamps = [t0.replace(second=s) for s in (0, 10, 20, 30, 40)]
    events = [_event(s) for s in stamps] + [_event(None)]
    capture = Capture(
        "w",
        "t",
        "positive",
        "linux",
        "auditd",
        (),
        techniques=("T1110",),
        window=(stamps[1], stamps[3]),
        exclude_windows=((stamps[2], stamps[2]),),
        events_override=lambda: iter(events),
    )
    kept = [e.timestamp for e in capture.events()]
    assert kept == [stamps[1], stamps[3]]  # inside the window, minus the excluded instant
    assert capture.labelled


def test_untimestamped_events_pass_only_without_a_window() -> None:
    events = [_event(None), _event(datetime(2026, 1, 1, tzinfo=UTC))]
    no_window = Capture(
        "n", "t", "benign", "linux", "auditd", (), events_override=lambda: iter(events)
    )
    assert len(list(no_window.events())) == 2
    excluded_only = Capture(
        "e",
        "t",
        "benign",
        "linux",
        "auditd",
        (),
        exclude_windows=((datetime(2025, 1, 1, tzinfo=UTC), datetime(2027, 1, 1, tzinfo=UTC)),),
        events_override=lambda: iter(events),
    )
    # No window: the untimestamped event is admitted; the timestamped one is excluded.
    assert [e.timestamp for e in excluded_only.events()] == [None]
