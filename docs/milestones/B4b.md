# B4b: Procedure variants

Started 2026-11-13. Prepared by Claude Code for Mason Thompsen. Follows `docs/milestones/B4.md`
(tag `b4`, pushed). Baseline run: `b4-final` (`LATEST`).

## Scope (Mason, 2026-11-13)

Lever a of B4, widened: techniques where rules exist but miss their dev captures (procedure
variants).

**Guardrails:**

- **Rules:** new local rules only, never edits to upstream rules. A loosened copy of an upstream
  rule counts as an edit and is not written.
- **Logic:** behavior-level, Summiting the Pyramid level 3 or higher. A candidate that can only be
  written at level 1 or 2 is dropped with its reason. Every rule goes into
  `bench/stp-scores.csv`.
- **Development:** on dev captures only. Only the fields a rule keys on are read, and every read
  is logged (B4 hygiene rule, confirmed by Mason). Test captures stay off-limits, and the B1 gap
  appendix is not opened during rule work.
- **Tags:** each rule is tagged to the behaviour it detects, never to a parent only to match a
  coarse label.
- **Class:** new rules stay `experimental` (hunting) until they have true-positive and
  true-negative fixtures (the B2 standard: `tests/test_local_rules.py`) and benign evidence
  that contains the events they read. Benign evidence is checked per rule: the goodware must
  hold the rule's channel and EventID with the fields it reads populated. A promotion goes in
  its own commit and its own run, after the hunting-only run, so both numbers exist.
- **Reporting:** gains on the frozen 130, and separately on never-inspected expanded-set
  captures from a corpus other than the rule's dev capture. Hunting-class held-out results are
  reported beside the headline.
- **Priority:** techniques by how many held-out captures they cover.
- **Process:** benchmark one run at a time, commit per batch of rules, tag `b4b` locally, do
  not push, stop and report.

## Selection, before any rule

`scripts/b4b_candidates.py` (output `bench/b4b/candidates-dev.csv`) reads the manifest, ATT&CK,
the loaded rules and the **dev** outcomes of `b4-final`; no test outcome is read.

- **Candidate:** a labelled dev positive capture the headline misses, whose label already has an
  alerting-class rule tagged to it.
- **Miss reason:** from the capture's own outcome record.

| Miss reason | Dev captures |
|:-|-:|
| Evaluated, no alerting rule fires (a procedure variant: B4b material) | 117 |
| An alerting rule fires but is tagged to another technique (a tag dispute; B2 rule: no retagging, and a local rule here would be a retag by duplicate) | 54 |
| A tagged alerting rule was not evaluable (missing field: a telemetry gap, not B4b) | 43 |
| A hunting or emerging rule tagged to the label already fires (a class question, not B4b) | 19 |

**Correction, before any rule was written.** The first selection (`aea7750`) put the 54
tag-dispute captures with the procedure variants. The first dev read showed the error: Bypass
UAC Using Event Viewer fires on `attack_data/T1548.002/ssa_eventvwr` but is tagged T1547.010.
The script now separates the two classes, and the cut line below replaces the first one.

The 233 rows cover 123 techniques; the 117 procedure-variant captures cover 77.

**Priority** is held-out captures on the dev capture's own platform, from manifest labels only:

- **Order:** first by the count from a corpus other than the dev capture's, then by the total.
- **Columns beside it:** the exact-label count (what a specific rule could cover) and the
  frozen-130 count.
- **Why platform matters:** a Linux rule cannot hit a Windows capture, so counts across
  platforms would mislead.

**Cut line, fixed before any rule:** the first 18 techniques of the "evaluated, no alerting
firing" rows,
in that order. Batch 1 is techniques 1 to 9, batch 2 is techniques 10 to 18. A technique is
dropped, with its reason, when:

- its dev capture does not show the behaviour in a field Bastion reads;
- or the only workable rule would be below STP level 3;
- or the rule would be a loosened copy of an upstream rule.

All 18 are Windows; the first Linux candidate ranks lower.

| # | Technique | Held out, other corpus | Held out, same platform | Exact label | Frozen 130 | Dev captures |
|-:|:-|-:|-:|-:|-:|-:|
| 1 | T1021 Remote Services | 15 | 22 | 4 | 7 | 2 |
| 2 | T1218 System Binary Proxy Execution | 12 | 29 | 9 | 11 | 1 |
| 3 | T1059.001 PowerShell | 10 | 13 | 9 | 2 | 5 |
| 4 | T1003 OS Credential Dumping | 9 | 21 | 9 | 8 | 1 |
| 5 | T1685.001 Disable or Modify Windows Event Log | 8 | 15 | 3 | 5 | 1 |
| 6 | T1134.001 Token Impersonation/Theft | 8 | 8 | 1 | 7 | 1 |
| 7 | T1546 Event Triggered Execution | 7 | 13 | 2 | 6 | 1 |
| 8 | T1036 Masquerading | 7 | 8 | 4 | 1 | 3 |
| 9 | T1685.005 Clear Windows Event Logs | 6 | 15 | 3 | 5 | 1 |
| 10 | T1218.014 MMC | 6 | 10 | 1 | 4 | 1 |
| 11 | T1021.006 Windows Remote Management | 6 | 8 | 4 | 4 | 2 |
| 12 | T1059 Command and Scripting Interpreter | 4 | 20 | 4 | 2 | 1 |
| 13 | T1574.001 DLL | 4 | 10 | 8 | 2 | 1 |
| 14 | T1003.002 Security Account Manager | 3 | 12 | 3 | 8 | 1 |
| 15 | T1021.001 Remote Desktop Protocol | 3 | 9 | 5 | 5 | 2 |
| 16 | T1055 Process Injection | 3 | 9 | 8 | 4 | 1 |
| 17 | T1068 Exploitation for Privilege Escalation | 3 | 7 | 7 | 2 | 2 |
| 18 | T1569.002 Service Execution | 3 | 6 | 5 | 1 | 2 |

**Inspected test captures.** `scripts/b4b_inspected.py` writes `bench/b4b/inspected-test.txt`
(ids only): test captures named in the contamination log or the B1 gap appendix. That is 49
captures, 39 of them in the frozen 130. A gain on one of these is reported as not clean.

## Batches

Sections below are filled in as each batch completes.

## Batch 1: candidates 1 to 9 (commit `dffc04f`, run `b4b-1`)

| # | Technique | Outcome |
|-:|:-|:-|
| 1 | T1021 | **Dropped.** `allow_inbound_traffic_in_firewall_rule` is a firewall change (T1686.003), already matched by the SigmaHQ threat-hunting rule for `New-NetFirewallRule`; a T1021 rule would be tagged to match the label. `smb_bi_auth_conn_spoolsample` holds only two Sysmon 3 connections from System to port 445, nothing a rule could key on above STP 2 |
| 2 | T1218 | **Dropped.** `desktopimgdownldr` creates a BITS job to download a file: the behaviour is T1197 and T1105, not proxy execution, so a rule could not honestly carry the T1218 label |
| 3 | T1059.001 | **Two rules:** PowerShell Runs Code Stored In An Environment Variable (STP 4, attack_data `vip_env_var_execution`); PowerShell Invokes A Command Name Built From Concatenated Fragments (STP 3, EVTX-ATTACK-SAMPLES `emotet/exec_emotet_ps_4104`). The three Emotet `800` captures carry no parsed fields, so nothing was written for them |
| 4 | T1003 | **Dropped, finding.** `CA_DCSync_4662` is matched in substance by two SigmaHQ rules (`win_security_dcsync`, `win_security_ad_replication_non_machine_account`), which miss because the capture writes `AccessMask` as `0x00000100` and the rules expect `0x100`. That is a value-normalisation question for the ingest layer, not a missing rule; a local copy would be a loosened upstream rule |
| 5 | T1685.001 | **Dropped.** `DE_WinEventLogSvc_Crash_System_7036` holds only service state changes to "running", which every boot also produces |
| 6 | T1134.001 | **One rule:** Auto-Elevating Binary Opened By A Program Outside System Folders (STP 3, attack_data `uac_process_handle_dup`), also tagged T1548.002 |
| 7 | T1546 | **One rule:** AdminSDHolder Security Descriptor Modified (STP 4, attack_data `adminsdholder_modified`), tagged T1098 and T1546 (no SigmaHQ rule covers AdminSDHolder) |
| 8 | T1036 | **One rule, tagged to the behaviour:** PsExec-Style Service Redirection Pipes Under Any Service Name (STP 3, EVTX-ATTACK-SAMPLES `DE_renamed_psexec_service`), tagged T1569.002 and T1021.002, not T1036: it detects the remote service, not the rename. `msdtc_process_param` and `suspicious_process_path` dropped: the behaviour-level form compares two fields (OriginalFileName against Image), which needs `fieldref`, unsupported; the rest would be below STP 3 |
| 9 | T1685.005 | **Dropped.** `suspicious_kerberos_service_ticket_request` holds one ordinary AES service ticket for a computer account; no behaviour to key on |

Counts-only check before the run: each rule fires only on its own dev capture across all 254
dev Windows captures, and on none of the 330 benign Windows captures.

## Batch 2: candidates 10 to 18 (commit `ab4cfde`, run `b4b-2`)

| # | Technique | Outcome |
|-:|:-|:-|
| 10 | T1218.014 | **One rule:** MMC Opens A Console File From A User-Writable Folder (STP 3, attack_data `msc_execution`) |
| 11 | T1021.006 | **One rule:** WinRM TrustedHosts Changed From PowerShell (STP 3, attack_data `wsman_trustedhost`). `compmgtm_access` dropped: remote Computer Management uses RPC, not WinRM, and is routine administration |
| 12 | T1059 | **One rule, tagged to the behaviour:** Service Process Started From The Root Of The Windows Folder (STP 3, attack_data `suspiciously_named_executables`), tagged T1569.002 and T1021.002: the capture is a service binary copied to ADMIN$, not an interpreter |
| 13 | T1574.001 | **Dropped.** `sccm_adsource_dll` is a product-specific DLL replacement; the only separable indicator is the renamed original's file name, STP 1 |
| 14 | T1003.002 | **One correlation:** Remote Registry Pipe Followed By An Administrative Share Write (STP 4, EVTX-ATTACK-SAMPLES `remote_sam_registry_access_via_backup_operator_priv`) |
| 15 | T1021.001 | **One rule:** RDP Client Control Loaded By A Program Outside System Folders (STP 3, EVTX-ATTACK-SAMPLES `sharprdp_sysmon_7_mstscax.dll`). `DFIR_RDP_Client_TimeZone_RdpCoreTs_104` dropped: its fields are not parsed |
| 16 | T1055 | **One rule:** File System Transaction Used By A Program Outside System Folders (STP 4, EVTX-ATTACK-SAMPLES `Win_4985_T1186_Process_Doppelganging`), tagged T1055.013 |
| 17 | T1068 | **Two rules:** Registry Symbolic Link Created By A Program Outside System Folders (STP 4, `privesc_registry_symlink_CVE-2020-1377`); Printer CopyFiles Module Registered To A Non-Default Library (STP 4, `privesc_spoolfool_mahdihtm`) |
| 18 | T1569.002 | **One rule:** Service Installed With A Bare Executable Name (STP 3, attack_data `windows_service_created_with_suspicious_service_path` and EVTX-ATTACK-SAMPLES `LM_Remote_Service02_7045`). Found while writing it: these System 7045 events carry no `Provider_Name`, so SigmaHQ rules that require it cannot match them |

Every batch 2 rule fires on its dev capture(s) (checked on the 13 dev captures before commit).
The full counts-only pass over all dev and benign captures runs after `b4b-1`, before `b4b-2`.

**Benign evidence per rule** (goodware `win2022-evtx`, events of the exact channel and EventID
the rule reads, with its fields populated):

| Reads | Goodware events | Rules |
|:-|-:|:-|
| Sysmon 13 (registry value set) | 64,294 | registry symbolic link, printer CopyFiles module |
| Sysmon 7 (image load) | 54,896 | RDP client control |
| Sysmon 10 (process access) | 4,648 | auto-elevating binary |
| Sysmon 1 (process creation, ParentImage populated) | 1,165 | MMC console, service from the Windows root |
| Sysmon 17 (pipe created) | 1,004 | PsExec-style pipes |
| System 7045 (service installed) | 12 | bare executable name |
| PowerShell 4104 (script block) | 5 | environment-variable IEX, concatenated command, TrustedHosts |
| Security 5136, 4985, 5145 | 0 | AdminSDHolder, transaction, remote hive dump |
