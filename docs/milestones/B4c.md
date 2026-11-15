# B4c: ingest normalization

Scope (Mason, 2026-11-14): (a) normalize hex-valued fields so `0x00000100` and `0x100`
compare equal, following how Windows renders them and how SigmaHQ rules write them; (b) find
where System 7045 `Provider_Name` is lost and supply it from the event's provider metadata if
the event carries it; (c) survey upstream rules whose required field or value format never
appears in any capture where the right event exists, list them with counts, and fix only
clear format mismatches. Benchmark before and after each lever, one run at a time; report the
frozen 130 headline with strict beside it, and the expanded set.

Baseline: `b4b-3` (code identical to the pushed `b4b` tag, `docs/milestones/B4b.md`, Mason's
review). Each lever is one commit and one run: `b4c-a`, `b4c-b`, `b4c-c`, each against the run
before it.

## Evidence used

- **Rule side:** the detection blocks of every rule the benchmark loads (core,
  emerging-threats and threat-hunting trees, local pack).
- **Data side:** one counts-only survey over all 1,418 captures (`shape_survey.py`): for each
  (platform, source kind, channel, EventID, field) and split, how many values have each shape
  (python-evtx padded hex, other hex, integer, GUID, SID, `%%` code, `-`, empty, path, text).
  No value was printed or stored. Test captures were included as counts only, logged in
  `docs/bench/contamination-log.md`.
- **Fix decisions** use dev and benign `.evtx` files only: a per-event before/after dump diff
  (25 dev captures and the README canary log) and presence counts of System-block elements
  (goodware System and Application logs, 25 dev captures).

## Lever a: hex values

**Cause.** python-evtx renders the `win:HexInt32` and `win:HexInt64` types byte by byte, so
always 8 or 16 lowercase digits (`0x00000100`, `0x00000000000003e7`). Windows renders them
without leading zeros (`0x100`, `0x3e7`).

**Evidence.**

- The XML exports (Splunk `XmlWinEventLog`, which carries Windows' own rendering) hold no
  padded value in any hex field.
- Every padded value comes from `.evtx` files: `SubjectLogonId` 20,762, `ProcessId` 19,477,
  `TargetLogonId` 14,237, `GrantedAccess` 4,807, `LogonId` 2,805, `HandleId` 2,714, `Status`
  1,408, `NewProcessId` 1,338, `AccessMask` 1,139, `ErrorCode` 281, and smaller counts in
  about 40 other fields.
- SigmaHQ writes every hex literal unpadded. Rules comparing a field exactly to a hex
  literal: `GrantedAccess` 18 (plus 6 with `startswith`, `endswith` or `contains`),
  `AccessMask` 14 (plus 1), `Status` 4, `LogonId` 3, `TicketEncryptionType` 3,
  `SubjectLogonId` 2, `ErrorCode` 2, and one each on `SubStatus`, `TicketOptions`,
  `ServiceType`, `TargetLogonId` and `Keywords`. On `.evtx` captures each of these could not
  match before. This includes both DCSync rules (B4b batch 1 finding).

**Fix** (`2ec947c`). Records read from `.evtx` have a whole value in python-evtx's exact
padded form rewritten without leading zeros (`0x00000000` becomes `0x0`). Hex inside text
(Sysmon's registry `DWORD (0x00000001)`, which two rules match with `contains`), uppercase
and odd-length values (Sysmon's own `StartAddress`), and every XML export are left as they
are. Process lineage parses ids numerically and is unaffected. Dump diff on 25 dev captures
and the canary log: 825 events, 255 values changed across 10 fields, every one padded hex to
the same number unpadded, nothing else.

## Lever b: Provider_Name

**Cause.** The parser stored `<Provider Name=...>` as `Provider` only. Sigma's field is
`Provider_Name`, which 106 SigmaHQ rules read (50 of them `Provider_Name: 'Service Control
Manager'`).

**Evidence.** The provider name is present on every Windows event of both source kinds
(262,393 of 262,394 `.evtx` events, all 66,965 XML events), including all 50 System 7045
events (16 `.evtx`, 34 XML). It was never lost from the data, only not exposed under Sigma's
name.

**Fix** (`86a3445`). `Provider_Name` is added from the same element; `Provider` stays.

## Lever c: survey of fields and formats that never appear

Method: for each Windows rule whose logsource Bastion routes to specific channels and
EventIDs, the fields it reads are checked against every event of those channels and EventIDs
in any capture (python-evtx padding read as fixed, `Provider_Name` as present). Rules whose
logsource is not routed are left out, since the right event is not identified. Events with
no `Channel` are left out too (they would otherwise admit every service).

Result: 71 (rule, field) pairs in 56 rules (44 alerting) where the field never appears.

| Field | Rules (alerting) | Logsource | Events of the routed kinds | Reading |
|:-|-:|:-|-:|:-|
| CommandLine | 11 (9) | file_event, image_load, network_connection | 60,532 | Sysmon 3, 7 and 11 have no command line; rules expecting enrichment |
| ParentImage | 6 (6) | file_event, network_connection | 4,176 | same |
| Level | 4 (4) | application, system | 4,625 | **lost by the parser** (System block) |
| NewValue | 4 (4) | windefend | 116 | the Defender events present are not configuration changes |
| NewName | 4 (4) | registry_event | 93,373 | Sysmon 14 (rename) occurs in no capture |
| ProcessName | 3 (2) | windefend | 116 | event kinds absent |
| ExceptionCode, ModuleName | 2, 1 (0) | application | 2,644 | event kinds absent |
| Message | 2 (2) | application | 2,644 | rendered message text, not in event XML |
| TemplateContent, NewTemplateContent | 2, 2 (2) | security | 29,514 | 4898/4899 occur in no capture |
| Binary | 2 (2) | system | 4,625 | **lost by the parser** (EventData `<Binary>`) |
| SourceName | 2 (1) | windefend | 116 | event kinds absent |
| SourceCommandLine, SourceParentImage | 2, 2 (1, 1) | process_access, create_remote_thread | 25,269 | not in Sysmon's schema |
| GrandParentImage | 2 (1) | process_creation | 13,487 | not in Sysmon's schema |
| Keywords | 1 (1) | security | 29,514 | **lost by the parser** (System block) |
| ProcessId | 1 (1) | system | 4,625 | 7045 `ProcessId: 0` means System `Execution ProcessID`; Sigma has no settled name for it, listed only |
| 20 more, one rule each | 20 (15) | various | | event kinds that occur in no capture |

Value formats: one rule's exact literal has a shape no routed event carries,
Local Privilege Escalation Indicator TabTip (`param3`, a braced GUID). Whether the events use
another form cannot be told from shape counts, so it is listed only. One further rule is
known from reading it: AD Object WriteDAC Access compares `ObjectType` exactly to a bare GUID
or `domainDNS`, while 4662 event XML writes `%{GUID}`. That is the rule's format, not
Bastion's; rewriting the value would depart from Windows' rendering, so it is listed for the
upstream issue Mason may file. The emerging-threats rule for CVE-2020-0688 compares `Level`
to `Error`, a display name the event XML does not carry, and is listed for the same reason.

**Fix** (`34bd324`). Only the three fields the source carries and the parser dropped:
System `Level` (as written, `2` or `4`, the form SigmaHQ uses) and `Keywords`
(`0x8010000000000000`), and the EventData `<Binary>` element. Presence on benign and dev data:
every one of 1,917 goodware System and Application events and 819 events of 25 dev captures
carries `Level` and `Keywords`; 1,000 goodware events (944 of them System 7036) carry
`Binary`. A provider's own `<Data>` of the same name is never replaced.

## Results

Filled in as each run completes.
