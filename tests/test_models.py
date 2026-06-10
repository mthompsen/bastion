"""Tests for the shared Pydantic models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from bastion.models import (
    CoverageEntry,
    Detection,
    Event,
    ScanResult,
    SigmaRule,
    TechniqueRef,
)


def _sample_event() -> Event:
    return Event(
        platform="linux",
        source="auth.log",
        fields={"process": "sshd", "pid": 412, "user": "alice"},
        raw="Jun 10 06:12:01 web01 sshd[412]: Accepted password for alice",
    )


def test_event_rejects_unknown_platform() -> None:
    with pytest.raises(ValidationError):
        Event(platform="macos", source="x", raw="y")  # type: ignore[arg-type]


def test_sigma_rule_rejects_unknown_level() -> None:
    with pytest.raises(ValidationError):
        SigmaRule(id="r1", title="t", level="urgent")  # type: ignore[arg-type]


def test_scan_result_round_trips_through_json() -> None:
    result = ScanResult(
        detections=[
            Detection(
                rule_id="r1",
                rule_title="Suspicious PowerShell",
                level="high",
                event=_sample_event(),
                matched_fields={"CommandLine": "powershell -enc"},
                techniques=[
                    TechniqueRef(id="T1059.001", name="PowerShell", tactics=["execution"])
                ],
            )
        ],
        events_scanned=10,
        rules_loaded=3,
        coverage=[
            CoverageEntry(
                technique=TechniqueRef(id="T1059.001", name="PowerShell", tactics=["execution"]),
                rule_count=2,
                covered=True,
            )
        ],
    )
    restored = ScanResult.model_validate_json(result.model_dump_json())
    assert restored == result
    assert restored.detections[0].techniques[0].id == "T1059.001"
