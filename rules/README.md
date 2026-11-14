# Local rule pack

Hand-written Sigma rules that ship with Bastion, covering ATT&CK techniques the upstream
SigmaHQ ruleset (at the pinned release) does not tag. They follow the same Sigma format as the
fetched rules and are loaded automatically alongside the cache when you run `bastion scan`,
`coverage`, `report`, or `rules list` without a `--rules-dir` override.

| Rule | Technique | Platform |
|---|---|---|
| Shadow File Read Attempt | T1003.008 /etc/passwd and /etc/shadow | linux |
| Systemd Timer Unit Creation Or Activation | T1053.006 Systemd Timers | linux |
| SSH Authorized Keys File Modification | T1098.004 SSH Authorized Keys | linux |
| PAM Configuration Modification | T1556.003 Pluggable Authentication Modules | linux |
| Crypto Miner Indicators In Logs | T1496.001 Compute Hijacking | linux |
| Host Log Enumeration | T1654 Log Enumeration | linux |
| Wi-Fi Profile Enumeration Via Netsh | T1016.002 Wi-Fi Discovery | windows |
| System Language And Location Discovery | T1614 System Location Discovery | windows |

B4 lever a, writable gaps (`bench/b4/writable-gaps-dev.csv`), each developed on one dev capture
and recording its Summiting the Pyramid level at the top of the file; all `experimental`:

| Rule | Technique | Platform | STP | Developed on (dev) |
|---|---|---|---|---|
| RC Script Modified From The Command Line | T1037.004 RC Scripts | linux | 4 | Citadel own-lab `proving2-2026-09-22/T1037.004` |
| Loaded Kernel Module Enumeration | T1652 Device Driver Discovery | linux | 3 | Citadel own-lab `proving-2026-09-22/T1652`, `proving2-2026-09-22/T1652` |
| Shared Object Compiled With A Load-Time Initialiser | T1129 Shared Modules | linux | 3 | attack_data `T1129/snapattack/sysmon_linux` |

Correlation rules (Sigma correlation specification 2.1.0, evaluated by
`bastion.sigma.correlation`; their building blocks never alert on their own). Each records its
Summiting the Pyramid level and the dev capture it was developed on in a comment at the top of
the file:

| Rule | Technique | Platform | STP | Status |
|---|---|---|---|---|
| Failed Logons For Many Accounts From One Source | T1110.003 Password Spraying | windows | 4 | experimental |
| Kerberos Authentication Failures For Many Accounts From One Source | T1110.003 Password Spraying | windows | 4 | experimental |
| Several Host Discovery Commands From One Parent (ported from Citadel M2) | T1033 System Owner/User Discovery | linux | 4 | experimental |

The two Windows correlations stay `experimental` because the goodware replay holds none of
the events they read, so it cannot show they are quiet on benign data
(`docs/milestones/B4.md` section 4).

B4b procedure variants (`docs/milestones/B4b.md`): rules for techniques that upstream rules
already claim but miss on a dev capture. Each records its dev capture in its header.

| Rule | Technique | Platform | STP | Developed on (dev) |
|---|---|---|---|---|
| PowerShell Runs Code Stored In An Environment Variable | T1059.001 PowerShell | windows | 4 | attack_data `T1059.001/vip_env_var_execution` |
| PowerShell Invokes A Command Name Built From Concatenated Fragments | T1059.001 PowerShell, T1027.010 | windows | 3 | EVTX-ATTACK-SAMPLES `Other/emotet/exec_emotet_ps_4104` |
| AdminSDHolder Security Descriptor Modified | T1098, T1546 | windows | 4 | attack_data `T1546/adminsdholder_modified` |
| Auto-Elevating Binary Opened By A Program Outside System Folders | T1134.001, T1548.002 | windows | 3 | attack_data `T1134.001/uac_process_handle_dup` |
| PsExec-Style Service Redirection Pipes Under Any Service Name | T1569.002, T1021.002 | windows | 3 | EVTX-ATTACK-SAMPLES `Defense Evasion/DE_renamed_psexec_service_sysmon_17_18` |
| MMC Opens A Console File From A User-Writable Folder | T1218.014 MMC | windows | 3 | attack_data `T1218.014/msc_execution` |
| WinRM TrustedHosts Changed From PowerShell | T1021.006 Windows Remote Management | windows | 3 | attack_data `T1021.006/wsman_trustedhost` |
| Service Process Started From The Root Of The Windows Folder | T1569.002, T1021.002 | windows | 3 | attack_data `T1059/suspiciously_named_executables` |
| RDP Client Control Loaded By A Program Outside System Folders | T1021.001 Remote Desktop Protocol | windows | 3 | EVTX-ATTACK-SAMPLES `Lateral Movement/sharprdp_sysmon_7_mstscax.dll` |
| File System Transaction Used By A Program Outside System Folders | T1055.013 Process Doppelganging | windows | 4 | EVTX-ATTACK-SAMPLES `Defense Evasion/Win_4985_T1186_Process_Doppelganging` |
| Registry Symbolic Link Created By A Program Outside System Folders | T1068 | windows | 4 | EVTX-ATTACK-SAMPLES `Privilege Escalation/privesc_registry_symlink_CVE-2020-1377` |
| Printer CopyFiles Module Registered To A Non-Default Library | T1068 | windows | 4 | EVTX-ATTACK-SAMPLES `Privilege Escalation/privesc_spoolfool_mahdihtm_sysmon_1_11_7_13` |
| Service Installed With A Bare Executable Name | T1569.002, T1543.003 | windows | 3 | attack_data `T1569.002/windows_service_created_with_suspicious_service_path`, EVTX-ATTACK-SAMPLES `Lateral Movement/LM_Remote_Service02_7045` |
| Remote Registry Pipe Followed By An Administrative Share Write (correlation) | T1003.002 Security Account Manager | windows | 4 | EVTX-ATTACK-SAMPLES `Credential Access/remote_sam_registry_access_via_backup_operator_priv` |

All fourteen started `experimental`, to stay there until they have fixtures (they do) and benign
evidence that holds the events they read (Mason, 2026-11-13). After `b4b-2`, six carry status
`test` and count in the headline: Auto-Elevating Binary, PsExec-Style Pipes, MMC Console, RDP
Client Control, Registry Symbolic Link and Printer CopyFiles Module. The goodware holds
thousands of the Sysmon events each reads (Sysmon 1, 7, 10, 13 and 17) and none of them fires
on it. The other eight stay `experimental`:

- Service Process Started From The Root Of The Windows Folder fires twice on the goodware. It
  is not filtered against that goodware, for the reason in `docs/milestones/B4.md` section 6.
- AdminSDHolder, File System Transaction and the remote hive dump correlation read Security
  5136, 4985 and 5145, which the goodware does not hold.
- The two PowerShell 4104 rules, WinRM TrustedHosts (5 goodware script blocks) and Bare
  Executable Name (12 goodware 7045 events) have too little benign evidence to judge; that is
  left to Mason.

Status by platform (decided 2026-11-10, recorded in `docs/milestones/B2.md` section 1):

- The 2 Windows rules carry Sigma status `test`. Each has a true-positive and a true-negative
  fixture in `tests/test_local_rules.py` and produced no alerts on the Nextron evtx-baseline
  goodware replay, so they count in the headline.
- The 6 Linux rules stay `experimental`, which places them in the hunting class. They have
  passing true-positive and true-negative fixtures, but there is no Linux goodware corpus yet.
  The only benign Linux evidence is Citadel's own-lab auditd background, and it is close to
  empty for these rules: five of the six read the `message` field, which only the auth.log and
  syslog parser produces, and Shadow File Read Attempt is limited to `service: auth`, so only
  Crypto Miner Indicators In Logs was really exercised. They are promoted when a Linux benign
  corpus shows them within the budget.

All eight are single-host detections written against the log shapes Bastion ingests
(auth.log/syslog text and Sysmon process creation). Review the false-positive notes inside
each rule before relying on them. Licensed MIT with the rest of the repository.
