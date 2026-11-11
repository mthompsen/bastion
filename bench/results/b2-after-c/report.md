# Bastion bench results

Run `b2-after-c`, Bastion 0.1.0 at commit `b5f64c3`. Sigma `r2026-04-01` (`fb1f07c`), ATT&CK 20.1. Split seed 20260926. Splits evaluated: test, dev.

Every rate below is numerator of denominator with a Wilson 95% interval and its basis. Hunting class (status experimental, unsupported, deprecated, or the threat-hunting tree) never raises a headline number.

## Rules

| Loaded | Alerting class | Hunting class | Not evaluable (grammar) |
|-:|-:|-:|-:|
| 3140 | 2923 | 217 | 3 |

Not evaluable by reason: modifier:fieldref 2, modifier:i 1. Files: aws_update_login_profile.yml, file_delete_win_delete_own_image.yml, proc_creation_win_susp_copy_system_dir.yml.

Technique tags resolved through ATT&CK revoked-by: 12 retired tags on 220 rules now count as their live successor (T1070.001 to T1685.005, T1070.002 to T1685.006, T1562 to T1685, T1562.001 to T1685, T1562.002 to T1685.001, T1562.003 to T1690, T1562.004 to T1686, T1562.006 to T1685, T1562.007 to T1686.001, T1562.008 to T1685.002, T1562.010 to T1689, T1562.012 to T1685.004).

Local pack: 8 rules, of which 6 are hunting class by status.

## Coverage (claim-by-tag, not validated detection)

| Metric | Value | Basis |
|:-|:-|:-|
| claimed_coverage:enterprise | 376 of 706 (53.3%, 95% CI 49.6% to 56.9%) | full enterprise matrix, ATT&CK 20.1, 2920 rules |
| claimed_coverage:windows | 288 of 479 (60.1%, 95% CI 55.7% to 64.4%) | techniques listing windows, ATT&CK 20.1, 2304 rules |
| claimed_coverage:linux | 98 of 356 (27.5%, 95% CI 23.1% to 32.4%) | techniques listing linux, ATT&CK 20.1, 248 rules |
| telemetry_feasible_coverage:enterprise | 319 of 706 (45.2%, 95% CI 41.5% to 48.9%) | full enterprise matrix, ATT&CK 20.1, 2434 rules |
| telemetry_feasible_coverage:windows | 283 of 479 (59.1%, 95% CI 54.6% to 63.4%) | techniques listing windows, ATT&CK 20.1, 2245 rules |
| telemetry_feasible_coverage:linux | 80 of 356 (22.5%, 95% CI 18.4% to 27.1%) | techniques listing linux, ATT&CK 20.1, 189 rules |
| hunting_class:enterprise | 134 of 706 (19.0%, 95% CI 16.3% to 22.0%) | full enterprise matrix, ATT&CK 20.1, 217 rules |

Uncovered by the alerting class: 330 techniques, of which 144 have no Windows or Linux component, 4 need telemetry Bastion does not read, and 182 are writable gaps.

## Detection on labelled captures, test split (held out)

| Metric | Value | Basis |
|:-|:-|:-|
| Detection rate (technique recall), headline | 38 of 130 (29.2%, 95% CI 22.1% to 37.6%) | labelled positive captures, test split, Sigma r2026-04-01, ATT&CK 20.1 |
| Detection rate, strict (exact tag) | 33 of 130 (25.4%, 95% CI 18.7% to 33.5%) | labelled positive captures, test split, Sigma r2026-04-01, ATT&CK 20.1, exact tag match only |
| Any-alert rate | 74 of 130 (56.9%, 95% CI 48.3% to 65.1%) | labelled positive captures, test split, Sigma r2026-04-01, ATT&CK 20.1 |
| Validated coverage, headline | 25 of 74 (33.8%, 95% CI 24.0% to 45.1%) | techniques with at least one labelled positive capture, test split, Sigma r2026-04-01, ATT&CK 20.1 |
| Validated coverage, strict (exact tag) | 22 of 74 (29.7%, 95% CI 20.5% to 40.9%) | techniques with at least one labelled positive capture, test split, Sigma r2026-04-01, ATT&CK 20.1, exact tag match only |
| Validated coverage, full matrix | 25 of 706 (3.5%, 95% CI 2.4% to 5.2%) | full enterprise matrix, ATT&CK 20.1 |

Captures: 130. Hits counted only through parent/sub-technique hierarchy: 5. Cross-firing: 194 alerts on 51 captures from rules tagged to another technique.

| Tactic | Detection rate | Captures |
|:-|:-|-:|
| collection | 0 of 2 (percentage suppressed, fewer than 5 captures) | 2 |
| command-and-control | 0 of 1 (percentage suppressed, fewer than 5 captures) | 1 |
| credential-access | 3 of 14 (21.4%, 95% CI 7.6% to 47.6%) | 14 |
| defense-impairment | 1 of 8 (12.5%, 95% CI 2.2% to 47.1%) | 8 |
| discovery | 1 of 6 (16.7%, 95% CI 3.0% to 56.4%) | 6 |
| execution | 6 of 14 (42.9%, 95% CI 21.4% to 67.4%) | 14 |
| exfiltration | 1 of 2 (percentage suppressed, fewer than 5 captures) | 2 |
| impact | 0 of 5 (0.0%, 95% CI 0.0% to 43.4%) | 5 |
| initial-access | 0 of 4 (percentage suppressed, fewer than 5 captures) | 4 |
| lateral-movement | 1 of 8 (12.5%, 95% CI 2.2% to 47.1%) | 8 |
| persistence | 11 of 26 (42.3%, 95% CI 25.5% to 61.1%) | 26 |
| privilege-escalation | 21 of 58 (36.2%, 95% CI 25.1% to 49.1%) | 58 |
| stealth | 10 of 37 (27.0%, 95% CI 15.4% to 43.0%) | 37 |

| Technique | Detected | Captures |
|:-|-:|-:|
| T1003 | 3 | 8 |
| T1003.008 | 0 | 1 |
| T1014 | 0 | 2 |
| T1016 | 1 | 1 |
| T1021 | 1 | 3 |
| T1021.001 | 0 | 2 |
| T1021.002 | 0 | 1 |
| T1021.006 | 0 | 1 |
| T1030 | 1 | 2 |
| T1033 | 0 | 1 |
| T1036 | 0 | 1 |
| T1037 | 1 | 1 |
| T1037.001 | 0 | 1 |
| T1047 | 1 | 1 |
| T1053 | 0 | 1 |
| T1053.002 | 2 | 2 |
| T1053.003 | 0 | 2 |
| T1055 | 0 | 4 |
| T1056.002 | 0 | 1 |
| T1059 | 0 | 1 |
| T1059.001 | 0 | 1 |
| T1068 | 0 | 4 |
| T1070.006 | 0 | 1 |
| T1078 | 0 | 2 |
| T1082 | 0 | 1 |
| T1083 | 0 | 2 |
| T1087 | 0 | 1 |
| T1090 | 0 | 1 |
| T1098 | 1 | 1 |
| T1098.004 | 0 | 1 |
| T1110 | 0 | 1 |
| T1115 | 0 | 1 |
| T1134 | 0 | 7 |
| T1134.005 | 1 | 1 |
| T1136.001 | 1 | 1 |
| T1140 | 0 | 1 |
| T1189 | 0 | 1 |
| T1197 | 0 | 1 |
| T1200 | 0 | 1 |
| T1218 | 0 | 4 |
| T1218.001 | 1 | 1 |
| T1218.002 | 0 | 1 |
| T1218.005 | 0 | 1 |
| T1218.010 | 1 | 1 |
| T1218.011 | 3 | 3 |
| T1220 | 1 | 1 |
| T1222.002 | 0 | 1 |
| T1485 | 0 | 2 |
| T1489 | 0 | 2 |
| T1529 | 0 | 1 |
| T1546.003 | 2 | 2 |
| T1546.004 | 0 | 1 |
| T1546.008 | 0 | 1 |
| T1546.011 | 0 | 1 |
| T1546.012 | 1 | 1 |
| T1546.015 | 0 | 1 |
| T1547 | 0 | 1 |
| T1547.001 | 1 | 1 |
| T1547.006 | 2 | 4 |
| T1548.001 | 0 | 1 |
| T1548.002 | 9 | 14 |
| T1548.003 | 1 | 4 |
| T1550.003 | 0 | 1 |
| T1552.001 | 0 | 1 |
| T1552.004 | 0 | 1 |
| T1555.005 | 0 | 1 |
| T1564.001 | 1 | 1 |
| T1569.002 | 1 | 1 |
| T1574 | 0 | 1 |
| T1574.001 | 1 | 1 |
| T1574.006 | 1 | 2 |
| T1685 | 0 | 5 |
| T1685.004 | 0 | 1 |
| T1686 | 1 | 1 |

Top cross-firing rules: Suspicious SQL Query (32); System Shutdown/Reboot - Linux (13); System Network Connections Discovery - Linux (11); Local Accounts Discovery (7); Network Connection Initiated Via Notepad.EXE (7); Whoami.EXE Execution From Privileged Process (5); Unusual Parent Process For Cmd.EXE (5); Non Interactive PowerShell Process Spawned (4).

## Detection on labelled captures, dev split (development)

| Metric | Value | Basis |
|:-|:-|:-|
| Detection rate (technique recall), headline | 42 of 118 (35.6%, 95% CI 27.5% to 44.6%) | labelled positive captures, dev split, Sigma r2026-04-01, ATT&CK 20.1 |
| Detection rate, strict (exact tag) | 31 of 118 (26.3%, 95% CI 19.2% to 34.9%) | labelled positive captures, dev split, Sigma r2026-04-01, ATT&CK 20.1, exact tag match only |
| Any-alert rate | 76 of 118 (64.4%, 95% CI 55.4% to 72.5%) | labelled positive captures, dev split, Sigma r2026-04-01, ATT&CK 20.1 |
| Validated coverage, headline | 25 of 63 (39.7%, 95% CI 28.5% to 52.0%) | techniques with at least one labelled positive capture, dev split, Sigma r2026-04-01, ATT&CK 20.1 |
| Validated coverage, strict (exact tag) | 17 of 63 (27.0%, 95% CI 17.6% to 39.0%) | techniques with at least one labelled positive capture, dev split, Sigma r2026-04-01, ATT&CK 20.1, exact tag match only |
| Validated coverage, full matrix | 25 of 706 (3.5%, 95% CI 2.4% to 5.2%) | full enterprise matrix, ATT&CK 20.1 |

Captures: 118. Hits counted only through parent/sub-technique hierarchy: 11. Cross-firing: 154 alerts on 46 captures from rules tagged to another technique.

| Tactic | Detection rate | Captures |
|:-|:-|-:|
| collection | 0 of 3 (percentage suppressed, fewer than 5 captures) | 3 |
| command-and-control | 1 of 3 (percentage suppressed, fewer than 5 captures) | 3 |
| credential-access | 3 of 13 (23.1%, 95% CI 8.2% to 50.3%) | 13 |
| defense-impairment | 1 of 11 (9.1%, 95% CI 1.6% to 37.7%) | 11 |
| discovery | 9 of 19 (47.4%, 95% CI 27.3% to 68.3%) | 19 |
| execution | 2 of 9 (22.2%, 95% CI 6.3% to 54.7%) | 9 |
| exfiltration | 1 of 1 (percentage suppressed, fewer than 5 captures) | 1 |
| impact | 0 of 3 (percentage suppressed, fewer than 5 captures) | 3 |
| initial-access | 1 of 2 (percentage suppressed, fewer than 5 captures) | 2 |
| lateral-movement | 3 of 7 (42.9%, 95% CI 15.8% to 75.0%) | 7 |
| persistence | 5 of 20 (25.0%, 95% CI 11.2% to 46.9%) | 20 |
| privilege-escalation | 18 of 44 (40.9%, 95% CI 27.7% to 55.6%) | 44 |
| stealth | 10 of 23 (43.5%, 95% CI 25.6% to 63.2%) | 23 |

| Technique | Detected | Captures |
|:-|-:|-:|
| T1003 | 3 | 7 |
| T1003.008 | 0 | 1 |
| T1016 | 1 | 1 |
| T1021 | 2 | 3 |
| T1021.001 | 0 | 2 |
| T1021.002 | 0 | 1 |
| T1021.006 | 1 | 1 |
| T1030 | 1 | 1 |
| T1033 | 0 | 3 |
| T1037.004 | 0 | 1 |
| T1049 | 2 | 2 |
| T1053 | 1 | 1 |
| T1053.002 | 0 | 1 |
| T1053.003 | 0 | 2 |
| T1053.006 | 0 | 1 |
| T1055 | 2 | 3 |
| T1055.012 | 1 | 1 |
| T1057 | 0 | 1 |
| T1068 | 0 | 3 |
| T1070.004 | 1 | 1 |
| T1070.006 | 0 | 1 |
| T1078 | 1 | 1 |
| T1082 | 2 | 3 |
| T1083 | 2 | 4 |
| T1087 | 0 | 1 |
| T1087.001 | 2 | 2 |
| T1090 | 1 | 1 |
| T1098.004 | 0 | 2 |
| T1105 | 0 | 1 |
| T1110 | 0 | 1 |
| T1134 | 1 | 5 |
| T1136.001 | 1 | 2 |
| T1197 | 0 | 1 |
| T1218 | 0 | 3 |
| T1218.005 | 0 | 1 |
| T1218.010 | 0 | 1 |
| T1218.011 | 3 | 3 |
| T1220 | 1 | 1 |
| T1222.002 | 0 | 1 |
| T1485 | 0 | 1 |
| T1489 | 0 | 2 |
| T1546.005 | 0 | 1 |
| T1546.015 | 1 | 1 |
| T1547 | 0 | 1 |
| T1547.001 | 1 | 1 |
| T1547.006 | 0 | 3 |
| T1548.002 | 9 | 13 |
| T1548.003 | 1 | 3 |
| T1552.001 | 0 | 1 |
| T1552.004 | 0 | 1 |
| T1555.005 | 0 | 1 |
| T1556.003 | 0 | 1 |
| T1560.001 | 0 | 1 |
| T1560.002 | 0 | 2 |
| T1569.003 | 0 | 1 |
| T1574.001 | 1 | 1 |
| T1574.006 | 0 | 1 |
| T1652 | 0 | 2 |
| T1659 | 0 | 1 |
| T1685 | 0 | 5 |
| T1685.004 | 0 | 1 |
| T1685.006 | 1 | 1 |
| T1690 | 0 | 2 |

Top cross-firing rules: Suspicious SQL Query (25); System Network Connections Discovery - Linux (15); Curl Usage on Linux (8); Relevant Anti-Virus Signature Keywords In Application Log (6); Local Groups Discovery - Linux (6); Linux Reverse Shell Indicator (6); Local Accounts Discovery (4); WmiPrvSE Spawned A Process (4).

## SigmaHQ regression suite

| Metric | Value | Basis |
|:-|:-|:-|
| Rule regression pass rate, headline | 159 of 159 (100.0%, 95% CI 97.6% to 100.0%) | evaluable SigmaHQ regression_data EVTX cases (10 skipped), Sigma r2026-04-01, ATT&CK 20.1, SigmaHQ criterion: at least the expected matches |
| Rule regression pass rate, strict | 155 of 159 (97.5%, 95% CI 93.7% to 99.0%) | evaluable SigmaHQ regression_data EVTX cases (10 skipped), Sigma r2026-04-01, ATT&CK 20.1, strict: exactly the expected matches |

The headline follows SigmaHQ's own runner: a case passes with at least the expected number of matches, and 4 case(s) passed with more than expected (SigmaHQ warns on those). The strict rate requires exactly the expected count.

Skipped by reason: rule not in the loaded ruleset (rules-emerging-threats): 9; rule not in the loaded ruleset (rules-threat-hunting): 1.

| Logsource | Passed | Failed |
|:-|-:|-:|
| windows/file_event | 16 | 0 |
| windows/image_load | 3 | 0 |
| windows/process_access | 2 | 0 |
| windows/process_creation | 103 | 0 |
| windows/registry_delete | 5 | 0 |
| windows/registry_event | 1 | 0 |
| windows/registry_set | 26 | 0 |
| windows/security | 1 | 0 |
| windows/sysmon | 1 | 0 |
| windows/taskscheduler | 1 | 0 |

## Benign replay, evtx-baseline goodware

| Hosts | Host-days scanned | Events | Alerts | Alerts per host-day | Medium+ per host-day | Budget | Within budget |
|-:|-:|-:|-:|-:|-:|-:|:-|
| 1 | 31.23 | 224797 | 1085 | 34.74 | 24.56 | 20.0 | no |

| Rule | Level | Alerts | Per host-day | On known-FPs list |
|:-|:-|-:|-:|:-|
| Suspicious SQL Query | medium | 414 | 13.26 | no |
| Certificate Private Key Acquired | medium | 116 | 3.71 | no |
| A Member Was Removed From a Security-Enabled Global Group | low | 99 | 3.17 | no |
| NTLM Logon | low | 92 | 2.95 | no |
| Sysmon Configuration Change | medium | 86 | 2.75 | yes |
| Modification of IE Registry Settings | low | 56 | 1.79 | no |
| USB Device Plugged | low | 54 | 1.73 | no |
| Windows Defender Threat Detected | high | 49 | 1.57 | no |
| WMI Event Subscription | medium | 24 | 0.77 | no |
| Sysmon Blocked Executable | high | 22 | 0.70 | no |
| Windows Defender Real-Time Protection Failure/Restart | medium | 17 | 0.54 | no |
| CodeIntegrity - Unsigned Kernel Module Loaded | high | 8 | 0.26 | no |
| WMI Persistence | medium | 5 | 0.16 | no |
| Windows Defender Malware Detection History Deletion | informational | 5 | 0.16 | no |
| AppLocker Prevented Application or Script from Running | medium | 5 | 0.16 | no |
| Win Defender Restored Quarantine File | high | 5 | 0.16 | no |
| Antivirus Relevant File Paths Alerts | high | 5 | 0.16 | no |
| Windows Firewall Settings Have Been Changed | low | 4 | 0.13 | yes |
| Relevant Anti-Virus Signature Keywords In Application Log | high | 4 | 0.13 | no |
| Potential Defense Evasion Via Raw Disk Access By Uncommon Tools | low | 3 | 0.10 | yes |
| Failed Logon From Public IP | medium | 3 | 0.10 | no |
| Disable Windows Defender Functionalities Via Registry Keys | high | 2 | 0.06 | yes |
| The Windows Defender Firewall Service Failed To Load Group Policy | low | 2 | 0.06 | no |
| User Logoff Event | informational | 1 | 0.03 | no |
| Suspicious High IntegrityLevel Conhost Legacy Option | informational | 1 | 0.03 | no |

## Own-lab background outside run windows (Citadel)

| Hosts | Host-days scanned | Events | Alerts | Alerts per host-day | Medium+ per host-day | Budget | Within budget |
|-:|-:|-:|-:|-:|-:|-:|:-|
| 5 | 12.75 | 3896 | 282 | 22.12 | 15.84 | 20.0 | no |

Notes: citadel-lab/network-2026-09-22: scanned span under one hour, floored to one hour.

| Rule | Level | Alerts | Per host-day | On known-FPs list |
|:-|:-|-:|-:|:-|
| Creation Of An User Account | medium | 170 | 13.33 | no |
| System Information Discovery | informational | 40 | 3.14 | no |
| System Network Discovery - Linux | informational | 35 | 2.74 | no |
| Suspicious SQL Query | medium | 25 | 1.96 | no |
| File Deletion | informational | 5 | 0.39 | no |
| Linux Reverse Shell Indicator | critical | 5 | 0.39 | no |
| Execution Of Script Located In Potentially Suspicious Directory | medium | 2 | 0.16 | no |

## Evidence ladder (strongest evidence per enterprise technique)

| Held-out-proven | Sample-proven | Fixture-proven | Rule-only | None |
|-:|-:|-:|-:|-:|
| 25 | 14 | 3 | 336 | 328 |

## Robustness (Summiting the Pyramid)

0 of 3140 rules scored; 3140 unscored. Scoring starts in B4.

## Captures

873 captures evaluated: regression 159, positive 375, benign 335, fixture 4. Unlabelled positive captures (scanned, in no rate): 127. Skipped: 0.

Pins: sigma r2026-04-01, sigma_commit fb1f07c928a5f94d786d4ec37ae75c29ce1634ad, attack 20.1, corpus:regression_data fb1f07c928a5f94d786d4ec37ae75c29ce1634ad, corpus:evtx_attack_samples 4ceed2f4706daf601c212a8f91c113dd85349a2c, corpus:evtx_baseline v0.8.5, corpus:attack_data b4573ed3b6bf05473b01048dd36380dbd52288c0, corpus:citadel_captures 2026-09-26.
