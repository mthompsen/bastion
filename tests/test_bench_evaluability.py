"""Tests for the static evaluability check."""

from __future__ import annotations

from pathlib import Path

from bastion.bench.evaluability import check_rule, check_rules, classify
from bastion.models import SigmaRule
from bastion.sigma.loader import load_rules

FIXTURE_RULES = Path(__file__).parent / "fixtures" / "rules"


def _rule(detection: dict[str, object], rid: str = "r") -> SigmaRule:
    return SigmaRule(id=rid, title=rid, detection=detection, file_path=f"{rid}.yml")


def test_fixture_rules_are_evaluable() -> None:
    report = check_rules(load_rules(FIXTURE_RULES))
    assert report.unsupported == []
    assert report.by_reason == {}


def test_reasons_are_classified() -> None:
    cases: dict[str, dict[str, object]] = {
        "aggregation:timeframe": {"s": {"a": 1}, "timeframe": "5m", "condition": "s"},
        "aggregation:count": {"s": {"a": 1}, "condition": "s | count() > 5"},
        "structure:no-condition": {"s": {"a": 1}},
        "structure:no-identifiers": {"condition": "s"},
        "modifier:fieldref": {"s": {"a|fieldref": "b"}, "condition": "s"},
        "structure:regex-does-not-compile": {"s": {"a|re": "("}, "condition": "s"},
        "structure:identifier-mixes": {"s": [{"a": 1}, "kw"], "condition": "s"},
        "structure:unknown-identifier": {"s": {"a": 1}, "condition": "s and t"},
        "structure:null-values-cannot": {"s": {"a|windash|contains": [None]}, "condition": "s"},
        "structure:unsupported-identifier-shape": {"s": {"a": 1}, "t": None, "condition": "s"},
    }
    for expected, detection in cases.items():
        found = check_rule(_rule(detection))
        assert found is not None, expected
        assert found.reason == expected


def test_list_conditions_and_map_lists_are_walked() -> None:
    ok = _rule({"s": [{"a": 1}, {"b|contains": "x"}], "condition": ["s", "1 of s*"]})
    assert check_rule(ok) is None
    bad = _rule({"s": [{"a": 1}, {"b|expand": "x"}], "condition": ["s"]})
    found = check_rule(bad)
    assert found is not None and found.reason == "modifier:expand"


def test_classify_falls_back_to_other() -> None:
    assert classify("something entirely new happened").startswith("other:")


def test_report_evaluable_map() -> None:
    good = _rule({"s": {"a": 1}, "condition": "s"}, "good")
    bad = _rule({"s": {"a|fieldref": "b"}, "condition": "s"}, "bad")
    report = check_rules([good, bad])
    assert report.by_reason == {"modifier:fieldref": 1}
    assert report.evaluable(good) and not report.evaluable(bad)
    mapping = report.evaluable_map([good, bad])
    assert mapping[good.id + good.file_path] is True
    assert mapping[bad.id + bad.file_path] is False
