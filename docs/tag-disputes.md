# Tag disputes

Ledger required by START_PROMPT section 3, rule 2: when an upstream SigmaHQ rule's ATT&CK tag
looks wrong, it is recorded here. Upstream rules are never retagged in this repository.
Each entry names the rule, the tag it carries, the technique the evidence points at, the
capture that surfaced it, and its status (open, reported upstream, resolved, withdrawn).

All entries below were opened on 2026-09-26 from the B1 held-out gap analysis
(`docs/milestones/B1.md`, section 4). They are candidates, not verdicts: the reviewer read
one capture each.

| Rule | Tag carried | Evidence points at | Capture (EVTX-ATTACK-SAMPLES) | Status |
|:-|:-|:-|:-|:-|
| Potential Dropper Script Execution Via WScript/CScript/MSHTA | T1059.005, T1059.007 | T1218.005 Mshta when the image is mshta.exe | `sysmon_mshta_sharpshooter_stageless_meterpreter.evtx` (labelled T1218.005) | open |
| PowerShell Credential Prompt | T1059.001 | T1056.002 GUI Input Capture, which is what the prompt is | `phish_windows_credentials_powershell_scriptblockLog_4104.evtx` (labelled T1056.002) | open |
| RottenPotato Like Attack Pattern | T1557.001 | T1134.001 Token Impersonation/Theft; the potato family is token manipulation, not LLMNR poisoning | `4624 LT3 AnonymousLogon Localhost - JuicyPotato.evtx` (labelled T1134) | open |
| Creation Exe for Service with Unquoted Path | T1547.009 | T1574.009 Path Interception by Unquoted Path | `privesc_unquoted_svc_sysmon_1_11.evtx` (labelled T1574) | open |

One-line summaries (Mason's decision B1-4, 2026-09-27; drafts for upstream issues are in
`docs/tag-disputes-drafts.md`, not filed):

1. Potential Dropper Script Execution Via WScript/CScript/MSHTA carries T1059.005 and
   T1059.007; on `sysmon_mshta_sharpshooter_stageless_meterpreter.evtx` it fires on the mshta
   launch, which is T1218.005.
2. PowerShell Credential Prompt carries T1059.001; it detects `Get-Credential` prompts, which
   ATT&CK files as T1056.002, and it fires on the T1056.002-labelled 4104 capture.
3. RottenPotato Like Attack Pattern carries T1557.001 (LLMNR poisoning); it fires on the
   JuicyPotato 4624 capture, whose behaviour is token impersonation, T1134.001.
4. Creation Exe for Service with Unquoted Path carries T1547.009 (Shortcut Modification); it
   fires on the unquoted service path capture, whose technique is T1574.009.

Label-side issues found in the same pass are recorded against the corpus, not the rules:
the mapping sheet labels `persistence_security_dcshadow_4742.evtx` as T1138 (Application
Shimming) although the capture and the firing rule are DCShadow (T1207), and it labels
KeePass credential theft (`CA_keefarce_keepass_credump.evtx`, `CA_keepass_KeeThief_...evtx`)
as T1003 where the rules' T1555.005 is the closer technique. Those stay as the corpus wrote
them; the bench does not edit upstream labels either.
