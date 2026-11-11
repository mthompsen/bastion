"""Tests for the EVTX-ATTACK-SAMPLES label pipeline and retired-id resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from bastion.attack import load_attack_data
from bastion.bench.labels import (
    build_label_table,
    parse_sheet,
    read_label_table,
    read_supplement,
    resolve_labels,
    unmatched_mentions,
    write_label_table,
)

MINI_STIX = Path(__file__).parent / "fixtures" / "mini_attack.json"

SHEET = (
    "Tactic,Technique,ID,Procedure related detection traces\n"
    "Execution,Rundll32,T1085,Launch via rundll32 -> exec_rundll32_openurl.evtx\n"
    ",,,windows_bits_4_59_60 lolbas desktopimgdownldr.evtx\n"
    "Privilege Escalation,Access Token Manipulation,T1134/005,"
    '"4765_sidhistory_add.evtx, and more"\n'
    'Privilege Escalation,Scheduled Task and Token,"T1053 \nT1134",PrivEsc_upnp_4698.evtx\n'
    "Persistence,NA,NA,sysmon_exec_from_vss_persistence.evtx\n"
    "Discovery,Account Discovery,T1087,PsLoggedOn.exe traces on the destination host\n"
)

PATHS = [
    "Execution/exec_rundll32_openurl.evtx",
    "Execution/windows_bits_4_59_60 lolbas desktopimgdownldr.evtx",
    "Privilege Escalation/4765_sidhistory_add.evtx",
    "Privilege Escalation/PrivEsc_upnp_4698.evtx",
    "Persistence/sysmon_exec_from_vss_persistence.evtx",
    "Other/never_mentioned.evtx",
    "Other/x_exec_rundll32_openurl.evtx",
]


def test_parse_sheet_handles_continuation_slash_ids_multiline_and_na() -> None:
    rows = parse_sheet(SHEET)
    assert [r.technique_ids for r in rows] == [
        ("T1085",),
        ("T1085",),  # continuation row inherits the previous technique
        ("T1134.005",),  # slash form normalized
        ("T1053", "T1134"),  # two ids in one cell
        (),  # NA
        ("T1087",),
    ]
    assert rows[1].tactic == "Execution"
    assert rows[0].row_number == 2


def test_build_label_table_matches_file_names_with_boundaries() -> None:
    table = {row.path: row for row in build_label_table(parse_sheet(SHEET), PATHS)}
    assert table["Execution/exec_rundll32_openurl.evtx"].technique_ids == ("T1085",)
    assert table["Execution/exec_rundll32_openurl.evtx"].sheet_rows == (2,)
    # A name with spaces is found inside free text, via the continuation row.
    assert table["Execution/windows_bits_4_59_60 lolbas desktopimgdownldr.evtx"].technique_ids == (
        "T1085",
    )
    assert table["Privilege Escalation/4765_sidhistory_add.evtx"].technique_ids == ("T1134.005",)
    assert table["Privilege Escalation/PrivEsc_upnp_4698.evtx"].technique_ids == ("T1053", "T1134")
    assert table["Persistence/sysmon_exec_from_vss_persistence.evtx"].technique_ids == ()
    assert table["Other/never_mentioned.evtx"].technique_ids == ()
    # "x_exec_rundll32_openurl.evtx" must not be matched by the shorter name inside it.
    assert table["Other/x_exec_rundll32_openurl.evtx"].technique_ids == ()
    assert table["Other/never_mentioned.evtx"].tactic_folder == "Other"


def test_unmatched_mentions_lists_sheet_names_absent_from_corpus() -> None:
    rows = parse_sheet(SHEET + "Execution,Scripting,T1064,ghost_file.evtx\n")
    assert unmatched_mentions(rows, PATHS) == ["ghost_file.evtx"]


def test_label_table_round_trips_through_csv() -> None:
    table = build_label_table(parse_sheet(SHEET), PATHS)
    text = write_label_table(table, "provenance line one\nline two")
    assert text.startswith("# provenance line one\n# line two\n")
    parsed = read_label_table(text)
    assert set(parsed) == set(PATHS)
    for row in table:
        assert parsed[row.path].technique_ids == row.technique_ids
        assert parsed[row.path].sheet_rows == row.sheet_rows


def test_resolve_labels_follows_revoked_by_and_excludes_retired_ids() -> None:
    attack = load_attack_data(MINI_STIX)
    live, notes = resolve_labels(["T1110", "t9001", "T9002", "T9999", "T1110"], attack)
    assert live == ("T1110", "T1059.001")
    assert notes == (
        "T9001 revoked, remapped to T1059.001",
        "T9002 deprecated in this ATT&CK release, excluded",
        "T9999 unknown in this ATT&CK release, excluded",
    )


SUPPLEMENT = """# provenance comment
path,technique_ids,confidence,source,note
A/one.evtx,T1003.001,exact,sheet row 7,
A/two.evtx,T1218.011;T1053.005,inferred_from_name,file name,two named
A/three.evtx,,ambiguous,file name,no technique named
"""


def test_read_supplement() -> None:
    table = read_supplement(SUPPLEMENT)
    assert table["A/two.evtx"].technique_ids == ("T1218.011", "T1053.005")
    assert [table[p].applied for p in ("A/one.evtx", "A/two.evtx", "A/three.evtx")] == [
        True,
        True,
        False,
    ]


@pytest.mark.parametrize(
    "row",
    [
        "A/x.evtx,T1003,guessed,file name,",
        "A/x.evtx,,exact,sheet row 1,",
        "A/x.evtx,T1003,ambiguous,file name,",
    ],
)
def test_read_supplement_rejects_bad_rows(row: str) -> None:
    with pytest.raises(ValueError):
        read_supplement("path,technique_ids,confidence,source,note\n" + row + "\n")


def test_read_supplement_rejects_duplicates() -> None:
    text = "path,technique_ids,confidence,source,note\nA,T1,exact,s,\nA,T1,exact,s,\n"
    with pytest.raises(ValueError, match="twice"):
        read_supplement(text)
