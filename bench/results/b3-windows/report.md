# Bastion bench results

Run `b3-windows`, Bastion 0.1.0 at commit `6f855f6`. Sigma `r2026-07-01` (`552f3fe`), ATT&CK 20.1. Split seed 20260926. Splits evaluated: test, dev.

Every rate below is numerator of denominator with a Wilson 95% interval and its basis. Hunting class (status experimental, unsupported, deprecated, or the threat-hunting tree) never raises a headline number.

## Rules

| Loaded | Alerting class | Hunting class | Not evaluable (grammar) |
|-:|-:|-:|-:|
| 3150 | 2925 | 225 | 3 |

Not evaluable by reason: modifier:fieldref 2, modifier:i 1. Files: aws_update_login_profile.yml, file_delete_win_delete_own_image.yml, proc_creation_win_susp_copy_system_dir.yml.

Technique tags resolved through ATT&CK revoked-by: 0 retired tags on 0 rules now count as their live successor.

Local pack: 8 rules, of which 6 are hunting class by status.

## Coverage (claim-by-tag, not validated detection)

| Metric | Value | Basis |
|:-|:-|:-|
| claimed_coverage:enterprise | 377 of 706 (53.4%, 95% CI 49.7% to 57.1%) | full enterprise matrix, ATT&CK 20.1, 2922 rules |
| claimed_coverage:windows | 288 of 479 (60.1%, 95% CI 55.7% to 64.4%) | techniques listing windows, ATT&CK 20.1, 2306 rules |
| claimed_coverage:linux | 98 of 356 (27.5%, 95% CI 23.1% to 32.4%) | techniques listing linux, ATT&CK 20.1, 248 rules |
| telemetry_feasible_coverage:enterprise | 320 of 706 (45.3%, 95% CI 41.7% to 49.0%) | full enterprise matrix, ATT&CK 20.1, 2436 rules |
| telemetry_feasible_coverage:windows | 283 of 479 (59.1%, 95% CI 54.6% to 63.4%) | techniques listing windows, ATT&CK 20.1, 2247 rules |
| telemetry_feasible_coverage:linux | 80 of 356 (22.5%, 95% CI 18.4% to 27.1%) | techniques listing linux, ATT&CK 20.1, 189 rules |
| hunting_class:enterprise | 136 of 706 (19.3%, 95% CI 16.5% to 22.3%) | full enterprise matrix, ATT&CK 20.1, 225 rules |

Uncovered by the alerting class: 329 techniques, of which 144 have no Windows or Linux component, 4 need telemetry Bastion does not read, and 181 are writable gaps.

## Detection on labelled captures, test split (held out)

| Metric | Value | Basis |
|:-|:-|:-|
| Detection rate (technique recall), headline | 121 of 461 (26.2%, 95% CI 22.4% to 30.4%) | labelled positive captures, test split, Sigma r2026-07-01, ATT&CK 20.1 |
| Detection rate, strict (exact tag) | 103 of 461 (22.3%, 95% CI 18.8% to 26.4%) | labelled positive captures, test split, Sigma r2026-07-01, ATT&CK 20.1, exact tag match only |
| Any-alert rate | 264 of 461 (57.3%, 95% CI 52.7% to 61.7%) | labelled positive captures, test split, Sigma r2026-07-01, ATT&CK 20.1 |
| Validated coverage, headline | 78 of 236 (33.1%, 95% CI 27.4% to 39.3%) | techniques with at least one labelled positive capture, test split, Sigma r2026-07-01, ATT&CK 20.1 |
| Validated coverage, strict (exact tag) | 69 of 236 (29.2%, 95% CI 23.8% to 35.3%) | techniques with at least one labelled positive capture, test split, Sigma r2026-07-01, ATT&CK 20.1, exact tag match only |
| Validated coverage, full matrix | 78 of 706 (11.0%, 95% CI 8.9% to 13.6%) | full enterprise matrix, ATT&CK 20.1 |

Captures: 461. Hits counted only through parent/sub-technique hierarchy: 18. Cross-firing: 1792 alerts on 193 captures from rules tagged to another technique.

| Tactic | Detection rate | Captures |
|:-|:-|-:|
| collection | 0 of 11 (0.0%, 95% CI 0.0% to 25.9%) | 11 |
| command-and-control | 7 of 18 (38.9%, 95% CI 20.3% to 61.4%) | 18 |
| credential-access | 15 of 56 (26.8%, 95% CI 17.0% to 39.6%) | 56 |
| defense-impairment | 11 of 44 (25.0%, 95% CI 14.6% to 39.4%) | 44 |
| discovery | 7 of 36 (19.4%, 95% CI 9.8% to 35.0%) | 36 |
| execution | 19 of 65 (29.2%, 95% CI 19.6% to 41.2%) | 65 |
| exfiltration | 1 of 9 (11.1%, 95% CI 2.0% to 43.5%) | 9 |
| impact | 1 of 14 (7.1%, 95% CI 1.3% to 31.5%) | 14 |
| initial-access | 0 of 20 (0.0%, 95% CI 0.0% to 16.1%) | 20 |
| lateral-movement | 6 of 29 (20.7%, 95% CI 9.8% to 38.4%) | 29 |
| persistence | 24 of 79 (30.4%, 95% CI 21.3% to 41.2%) | 79 |
| privilege-escalation | 40 of 115 (34.8%, 95% CI 26.7% to 43.9%) | 115 |
| reconnaissance | 0 of 7 (0.0%, 95% CI 0.0% to 35.4%) | 7 |
| resource-development | 0 of 4 (percentage suppressed, fewer than 5 captures) | 4 |
| stealth | 30 of 106 (28.3%, 95% CI 20.6% to 37.5%) | 106 |

| Technique | Detected | Captures |
|:-|-:|-:|
| T1001 | 0 | 1 |
| T1003 | 4 | 9 |
| T1003.001 | 4 | 4 |
| T1003.002 | 0 | 3 |
| T1003.003 | 0 | 1 |
| T1003.004 | 1 | 1 |
| T1003.005 | 1 | 1 |
| T1003.006 | 1 | 2 |
| T1003.008 | 0 | 1 |
| T1006 | 0 | 1 |
| T1011 | 0 | 1 |
| T1012 | 0 | 2 |
| T1014 | 0 | 2 |
| T1016 | 1 | 1 |
| T1016.001 | 0 | 1 |
| T1018 | 0 | 2 |
| T1020 | 0 | 1 |
| T1021 | 2 | 4 |
| T1021.001 | 1 | 5 |
| T1021.002 | 1 | 5 |
| T1021.003 | 0 | 3 |
| T1021.004 | 0 | 1 |
| T1021.006 | 0 | 4 |
| T1027 | 0 | 2 |
| T1027.009 | 0 | 1 |
| T1027.010 | 0 | 1 |
| T1030 | 1 | 3 |
| T1033 | 0 | 3 |
| T1036 | 1 | 4 |
| T1036.003 | 1 | 2 |
| T1036.005 | 0 | 1 |
| T1036.008 | 0 | 1 |
| T1037 | 1 | 1 |
| T1037.001 | 0 | 1 |
| T1037.005 | 0 | 1 |
| T1040 | 0 | 1 |
| T1046 | 1 | 2 |
| T1047 | 2 | 4 |
| T1048.003 | 0 | 1 |
| T1049 | 1 | 1 |
| T1053 | 0 | 2 |
| T1053.002 | 2 | 2 |
| T1053.003 | 0 | 2 |
| T1053.005 | 2 | 5 |
| T1055 | 3 | 8 |
| T1055.001 | 0 | 1 |
| T1056.001 | 0 | 1 |
| T1056.002 | 0 | 1 |
| T1057 | 1 | 2 |
| T1059 | 2 | 4 |
| T1059.001 | 3 | 9 |
| T1059.003 | 0 | 3 |
| T1059.005 | 0 | 1 |
| T1059.006 | 0 | 1 |
| T1059.007 | 1 | 2 |
| T1068 | 0 | 9 |
| T1069 | 0 | 1 |
| T1069.001 | 0 | 1 |
| T1069.002 | 0 | 1 |
| T1070 | 0 | 1 |
| T1070.006 | 0 | 1 |
| T1071 | 0 | 1 |
| T1071.001 | 0 | 1 |
| T1071.004 | 0 | 3 |
| T1074 | 0 | 1 |
| T1078 | 0 | 4 |
| T1078.001 | 0 | 1 |
| T1078.002 | 0 | 2 |
| T1078.003 | 0 | 1 |
| T1082 | 0 | 2 |
| T1083 | 0 | 2 |
| T1087 | 0 | 2 |
| T1087.002 | 0 | 1 |
| T1090 | 1 | 2 |
| T1090.001 | 1 | 1 |
| T1090.003 | 1 | 1 |
| T1098 | 2 | 6 |
| T1098.004 | 0 | 1 |
| T1105 | 1 | 2 |
| T1110 | 0 | 1 |
| T1110.001 | 0 | 1 |
| T1110.003 | 0 | 4 |
| T1110.004 | 0 | 1 |
| T1112 | 1 | 3 |
| T1114.001 | 0 | 1 |
| T1115 | 0 | 1 |
| T1119 | 0 | 1 |
| T1125 | 0 | 1 |
| T1127 | 0 | 1 |
| T1129 | 0 | 1 |
| T1133 | 0 | 1 |
| T1134 | 0 | 7 |
| T1134.001 | 0 | 1 |
| T1134.002 | 0 | 1 |
| T1134.005 | 2 | 2 |
| T1135 | 0 | 4 |
| T1136 | 0 | 1 |
| T1136.001 | 2 | 2 |
| T1136.002 | 0 | 1 |
| T1137.006 | 0 | 1 |
| T1140 | 0 | 2 |
| T1185 | 0 | 2 |
| T1187 | 1 | 2 |
| T1189 | 0 | 1 |
| T1190 | 0 | 3 |
| T1195.001 | 0 | 1 |
| T1195.002 | 0 | 1 |
| T1197 | 0 | 2 |
| T1200 | 0 | 2 |
| T1202 | 0 | 1 |
| T1203 | 0 | 1 |
| T1204 | 0 | 1 |
| T1204.002 | 0 | 3 |
| T1207 | 1 | 2 |
| T1210 | 0 | 1 |
| T1212 | 0 | 1 |
| T1216 | 1 | 1 |
| T1217 | 0 | 1 |
| T1218 | 0 | 9 |
| T1218.001 | 1 | 1 |
| T1218.002 | 0 | 2 |
| T1218.004 | 1 | 1 |
| T1218.005 | 1 | 2 |
| T1218.007 | 0 | 1 |
| T1218.008 | 1 | 1 |
| T1218.010 | 1 | 2 |
| T1218.011 | 8 | 9 |
| T1218.013 | 1 | 1 |
| T1218.014 | 0 | 1 |
| T1219 | 2 | 2 |
| T1220 | 1 | 1 |
| T1222 | 0 | 1 |
| T1222.001 | 0 | 2 |
| T1222.002 | 0 | 1 |
| T1482 | 1 | 1 |
| T1484 | 0 | 1 |
| T1484.001 | 1 | 4 |
| T1485 | 0 | 5 |
| T1486 | 0 | 1 |
| T1489 | 0 | 2 |
| T1490 | 1 | 2 |
| T1491 | 0 | 1 |
| T1491.001 | 0 | 1 |
| T1497 | 0 | 3 |
| T1505 | 0 | 1 |
| T1505.001 | 0 | 3 |
| T1505.003 | 1 | 2 |
| T1518 | 1 | 1 |
| T1526 | 1 | 1 |
| T1528 | 0 | 1 |
| T1529 | 0 | 1 |
| T1537 | 0 | 1 |
| T1542.001 | 0 | 1 |
| T1542.003 | 0 | 1 |
| T1543.003 | 1 | 2 |
| T1546 | 0 | 2 |
| T1546.003 | 2 | 2 |
| T1546.004 | 0 | 1 |
| T1546.007 | 1 | 1 |
| T1546.008 | 1 | 2 |
| T1546.009 | 1 | 1 |
| T1546.011 | 0 | 2 |
| T1546.012 | 1 | 1 |
| T1546.015 | 0 | 2 |
| T1547 | 0 | 1 |
| T1547.001 | 2 | 2 |
| T1547.005 | 1 | 1 |
| T1547.006 | 2 | 4 |
| T1547.008 | 1 | 1 |
| T1547.009 | 0 | 1 |
| T1547.012 | 0 | 1 |
| T1548.001 | 0 | 1 |
| T1548.002 | 14 | 22 |
| T1548.003 | 1 | 4 |
| T1550 | 0 | 1 |
| T1550.002 | 1 | 1 |
| T1550.003 | 0 | 1 |
| T1552 | 0 | 1 |
| T1552.001 | 0 | 2 |
| T1552.004 | 0 | 1 |
| T1552.006 | 1 | 1 |
| T1553.002 | 0 | 1 |
| T1553.003 | 1 | 1 |
| T1553.005 | 0 | 1 |
| T1555 | 0 | 1 |
| T1555.003 | 0 | 1 |
| T1555.005 | 0 | 1 |
| T1556 | 0 | 2 |
| T1556.001 | 0 | 1 |
| T1556.002 | 0 | 1 |
| T1558 | 0 | 3 |
| T1558.001 | 0 | 1 |
| T1558.003 | 1 | 2 |
| T1560 | 0 | 1 |
| T1560.002 | 0 | 1 |
| T1561.002 | 0 | 1 |
| T1563.002 | 1 | 1 |
| T1564 | 0 | 1 |
| T1564.001 | 2 | 2 |
| T1564.002 | 1 | 1 |
| T1564.004 | 1 | 1 |
| T1566 | 0 | 1 |
| T1566.001 | 0 | 1 |
| T1566.002 | 0 | 1 |
| T1567 | 0 | 1 |
| T1567.002 | 0 | 1 |
| T1569 | 0 | 1 |
| T1569.002 | 1 | 5 |
| T1570 | 0 | 2 |
| T1572 | 1 | 4 |
| T1574 | 1 | 2 |
| T1574.001 | 4 | 8 |
| T1574.006 | 1 | 2 |
| T1574.007 | 0 | 1 |
| T1574.008 | 0 | 1 |
| T1574.014 | 0 | 1 |
| T1587.002 | 0 | 1 |
| T1587.003 | 0 | 1 |
| T1588.002 | 0 | 1 |
| T1589.001 | 0 | 1 |
| T1589.002 | 0 | 1 |
| T1590 | 0 | 1 |
| T1592 | 0 | 1 |
| T1595 | 0 | 1 |
| T1595.001 | 0 | 1 |
| T1598.002 | 0 | 1 |
| T1608.001 | 0 | 1 |
| T1620 | 0 | 1 |
| T1621 | 0 | 1 |
| T1649 | 1 | 1 |
| T1685 | 4 | 12 |
| T1685.001 | 1 | 3 |
| T1685.004 | 0 | 1 |
| T1685.005 | 0 | 3 |
| T1686 | 2 | 3 |
| T1688 | 0 | 1 |

Top cross-firing rules: User Logoff Event (186); Credentials In Files - Linux (148); Unsigned DLL Loaded by Windows Utility (147); Suspicious SQL Query (98); Windows Processes Suspicious Parent Directory (63); System File Execution Location Anomaly (63); Non Interactive PowerShell Process Spawned (55); Potentially Suspicious Malware Callback Communication (42).

## Detection on labelled captures, dev split (development)

| Metric | Value | Basis |
|:-|:-|:-|
| Detection rate (technique recall), headline | 106 of 309 (34.3%, 95% CI 29.2% to 39.8%) | labelled positive captures, dev split, Sigma r2026-07-01, ATT&CK 20.1 |
| Detection rate, strict (exact tag) | 89 of 309 (28.8%, 95% CI 24.0% to 34.1%) | labelled positive captures, dev split, Sigma r2026-07-01, ATT&CK 20.1, exact tag match only |
| Any-alert rate | 196 of 309 (63.4%, 95% CI 57.9% to 68.6%) | labelled positive captures, dev split, Sigma r2026-07-01, ATT&CK 20.1 |
| Validated coverage, headline | 59 of 138 (42.8%, 95% CI 34.8% to 51.1%) | techniques with at least one labelled positive capture, dev split, Sigma r2026-07-01, ATT&CK 20.1 |
| Validated coverage, strict (exact tag) | 49 of 138 (35.5%, 95% CI 28.0% to 43.8%) | techniques with at least one labelled positive capture, dev split, Sigma r2026-07-01, ATT&CK 20.1, exact tag match only |
| Validated coverage, full matrix | 59 of 706 (8.4%, 95% CI 6.5% to 10.6%) | full enterprise matrix, ATT&CK 20.1 |

Captures: 309. Hits counted only through parent/sub-technique hierarchy: 17. Cross-firing: 1379 alerts on 139 captures from rules tagged to another technique.

| Tactic | Detection rate | Captures |
|:-|:-|-:|
| collection | 1 of 6 (16.7%, 95% CI 3.0% to 56.4%) | 6 |
| command-and-control | 6 of 14 (42.9%, 95% CI 21.4% to 67.4%) | 14 |
| credential-access | 9 of 33 (27.3%, 95% CI 15.1% to 44.2%) | 33 |
| defense-impairment | 13 of 34 (38.2%, 95% CI 23.9% to 55.0%) | 34 |
| discovery | 13 of 34 (38.2%, 95% CI 23.9% to 55.0%) | 34 |
| execution | 14 of 48 (29.2%, 95% CI 18.2% to 43.2%) | 48 |
| exfiltration | 2 of 3 (percentage suppressed, fewer than 5 captures) | 3 |
| impact | 1 of 7 (14.3%, 95% CI 2.6% to 51.3%) | 7 |
| initial-access | 2 of 11 (18.2%, 95% CI 5.1% to 47.7%) | 11 |
| lateral-movement | 6 of 21 (28.6%, 95% CI 13.8% to 50.0%) | 21 |
| persistence | 17 of 53 (32.1%, 95% CI 21.1% to 45.5%) | 53 |
| privilege-escalation | 35 of 85 (41.2%, 95% CI 31.3% to 51.8%) | 85 |
| reconnaissance | 0 of 1 (percentage suppressed, fewer than 5 captures) | 1 |
| stealth | 23 of 64 (35.9%, 95% CI 25.3% to 48.2%) | 64 |

| Technique | Detected | Captures |
|:-|-:|-:|
| T1003 | 4 | 8 |
| T1003.001 | 2 | 3 |
| T1003.002 | 1 | 2 |
| T1003.004 | 0 | 1 |
| T1003.006 | 1 | 1 |
| T1003.008 | 0 | 1 |
| T1012 | 0 | 1 |
| T1016 | 1 | 1 |
| T1018 | 1 | 2 |
| T1021 | 2 | 4 |
| T1021.001 | 0 | 4 |
| T1021.002 | 1 | 4 |
| T1021.003 | 2 | 3 |
| T1021.006 | 1 | 3 |
| T1027 | 0 | 2 |
| T1030 | 1 | 1 |
| T1033 | 3 | 4 |
| T1036 | 0 | 4 |
| T1036.003 | 1 | 2 |
| T1037.004 | 0 | 1 |
| T1046 | 0 | 1 |
| T1047 | 0 | 3 |
| T1048.003 | 1 | 1 |
| T1049 | 2 | 2 |
| T1053 | 1 | 2 |
| T1053.002 | 0 | 1 |
| T1053.003 | 0 | 2 |
| T1053.005 | 2 | 5 |
| T1053.006 | 0 | 1 |
| T1055 | 4 | 6 |
| T1055.012 | 1 | 2 |
| T1057 | 0 | 2 |
| T1059 | 1 | 3 |
| T1059.001 | 3 | 8 |
| T1059.003 | 0 | 3 |
| T1059.005 | 0 | 1 |
| T1059.007 | 0 | 1 |
| T1068 | 0 | 7 |
| T1069.002 | 0 | 1 |
| T1070.004 | 1 | 1 |
| T1070.006 | 0 | 1 |
| T1071.004 | 0 | 3 |
| T1078 | 1 | 3 |
| T1078.002 | 0 | 1 |
| T1078.003 | 0 | 1 |
| T1082 | 2 | 3 |
| T1083 | 2 | 4 |
| T1087 | 0 | 2 |
| T1087.001 | 2 | 2 |
| T1087.002 | 0 | 1 |
| T1090 | 1 | 1 |
| T1098 | 3 | 4 |
| T1098.004 | 0 | 2 |
| T1105 | 1 | 3 |
| T1110 | 0 | 1 |
| T1110.003 | 0 | 4 |
| T1112 | 1 | 3 |
| T1119 | 0 | 1 |
| T1134 | 1 | 5 |
| T1134.001 | 0 | 1 |
| T1134.005 | 1 | 1 |
| T1135 | 0 | 3 |
| T1136.001 | 1 | 2 |
| T1136.002 | 0 | 1 |
| T1185 | 0 | 2 |
| T1187 | 0 | 1 |
| T1190 | 1 | 3 |
| T1195.002 | 0 | 1 |
| T1197 | 1 | 2 |
| T1202 | 0 | 1 |
| T1204 | 0 | 1 |
| T1204.002 | 1 | 2 |
| T1207 | 1 | 2 |
| T1218 | 1 | 8 |
| T1218.005 | 0 | 1 |
| T1218.007 | 1 | 1 |
| T1218.010 | 0 | 1 |
| T1218.011 | 5 | 6 |
| T1218.014 | 0 | 1 |
| T1219 | 1 | 2 |
| T1220 | 1 | 1 |
| T1222.001 | 0 | 1 |
| T1222.002 | 0 | 1 |
| T1482 | 0 | 1 |
| T1484 | 0 | 1 |
| T1484.001 | 1 | 3 |
| T1485 | 0 | 3 |
| T1489 | 0 | 2 |
| T1490 | 1 | 2 |
| T1497 | 0 | 2 |
| T1505.001 | 0 | 2 |
| T1505.003 | 0 | 1 |
| T1542.001 | 0 | 1 |
| T1542.003 | 0 | 1 |
| T1543.003 | 0 | 2 |
| T1546 | 0 | 1 |
| T1546.005 | 0 | 1 |
| T1546.008 | 1 | 1 |
| T1546.011 | 1 | 1 |
| T1546.015 | 2 | 2 |
| T1547 | 0 | 1 |
| T1547.001 | 3 | 3 |
| T1547.006 | 0 | 3 |
| T1548.002 | 13 | 19 |
| T1548.003 | 1 | 3 |
| T1550.002 | 0 | 1 |
| T1552.001 | 0 | 2 |
| T1552.004 | 0 | 1 |
| T1555.005 | 0 | 1 |
| T1556 | 0 | 1 |
| T1556.003 | 0 | 1 |
| T1558 | 1 | 2 |
| T1558.003 | 0 | 2 |
| T1560.001 | 1 | 1 |
| T1560.002 | 0 | 2 |
| T1563.002 | 0 | 1 |
| T1564 | 0 | 1 |
| T1564.004 | 1 | 1 |
| T1566 | 0 | 1 |
| T1567 | 0 | 1 |
| T1569.002 | 0 | 3 |
| T1569.003 | 0 | 1 |
| T1570 | 0 | 1 |
| T1572 | 3 | 4 |
| T1574.001 | 5 | 8 |
| T1574.006 | 0 | 1 |
| T1595 | 0 | 1 |
| T1620 | 0 | 1 |
| T1649 | 0 | 1 |
| T1652 | 0 | 2 |
| T1659 | 0 | 1 |
| T1685 | 7 | 12 |
| T1685.001 | 1 | 2 |
| T1685.004 | 0 | 1 |
| T1685.005 | 0 | 2 |
| T1685.006 | 1 | 1 |
| T1686 | 1 | 1 |
| T1690 | 0 | 2 |

Top cross-firing rules: Potential Arbitrary Command Execution Via FTP.EXE (240); Non Interactive PowerShell Process Spawned (99); User Logoff Event (69); Suspicious High IntegrityLevel Conhost Legacy Option (58); Suspicious SQL Query (35); Windows Shell/Scripting Processes Spawning Suspicious Programs (29); Important Windows Event Auditing Disabled (28); Suspicious Redirection to Local Admin Share (23).

## Headline sets side by side (held out)

The frozen set is the B1 test split, unchanged since B1 so B1 and B2 comparisons stay valid (sha256 of its sorted id list `163ebf88eaba`). The expanded test split adds captures assigned later with the same seed, before any rule ran on them.

| Set | Captures | Detection, headline | Detection, strict | Any alert |
|:-|-:|:-|:-|:-|
| Frozen B1 test set | 130 | 38 of 130 (29.2%, 95% CI 22.1% to 37.6%) | 33 of 130 (25.4%, 95% CI 18.7% to 33.5%) | 76 of 130 (58.5%, 95% CI 49.9% to 66.6%) |
| Expanded test split | 461 | 121 of 461 (26.2%, 95% CI 22.4% to 30.4%) | 103 of 461 (22.3%, 95% CI 18.8% to 26.4%) | 264 of 461 (57.3%, 95% CI 52.7% to 61.7%) |

### Per corpus, test split

| Corpus | Captures | Detection, headline | Detection, strict | Any alert |
|:-|-:|:-|:-|:-|
| attack_data | 307 | 78 of 307 (25.4%, 95% CI 20.9% to 30.6%) | 65 of 307 (21.2%, 95% CI 17.0% to 26.1%) | 166 of 307 (54.1%, 95% CI 48.5% to 59.6%) |
| evtx_attack_samples | 154 | 43 of 154 (27.9%, 95% CI 21.4% to 35.5%) | 38 of 154 (24.7%, 95% CI 18.5% to 32.0%) | 98 of 154 (63.6%, 95% CI 55.8% to 70.8%) |

### Per corpus, dev split

| Corpus | Captures | Detection, headline | Detection, strict | Any alert |
|:-|-:|:-|:-|:-|
| attack_data | 181 | 54 of 181 (29.8%, 95% CI 23.6% to 36.9%) | 47 of 181 (26.0%, 95% CI 20.1% to 32.8%) | 102 of 181 (56.4%, 95% CI 49.1% to 63.4%) |
| citadel_captures | 30 | 14 of 30 (46.7%, 95% CI 30.2% to 63.9%) | 14 of 30 (46.7%, 95% CI 30.2% to 63.9%) | 27 of 30 (90.0%, 95% CI 74.4% to 96.5%) |
| evtx_attack_samples | 98 | 38 of 98 (38.8%, 95% CI 29.7% to 48.7%) | 28 of 98 (28.6%, 95% CI 20.6% to 38.2%) | 67 of 98 (68.4%, 95% CI 58.6% to 76.7%) |

## SigmaHQ regression suite

| Metric | Value | Basis |
|:-|:-|:-|
| Rule regression pass rate, headline | 187 of 187 (100.0%, 95% CI 98.0% to 100.0%) | evaluable SigmaHQ regression_data EVTX cases (10 skipped), Sigma r2026-07-01, ATT&CK 20.1, SigmaHQ criterion: at least the expected matches |
| Rule regression pass rate, strict | 183 of 187 (97.9%, 95% CI 94.6% to 99.2%) | evaluable SigmaHQ regression_data EVTX cases (10 skipped), Sigma r2026-07-01, ATT&CK 20.1, strict: exactly the expected matches |

The headline follows SigmaHQ's own runner: a case passes with at least the expected number of matches, and 4 case(s) passed with more than expected (SigmaHQ warns on those). The strict rate requires exactly the expected count.

Skipped by reason: rule not in the loaded ruleset (rules-emerging-threats): 9; rule not in the loaded ruleset (rules-threat-hunting): 1.

| Logsource | Passed | Failed |
|:-|-:|-:|
| windows/file_event | 18 | 0 |
| windows/image_load | 3 | 0 |
| windows/process_access | 2 | 0 |
| windows/process_creation | 128 | 0 |
| windows/registry_delete | 5 | 0 |
| windows/registry_event | 1 | 0 |
| windows/registry_set | 26 | 0 |
| windows/security | 1 | 0 |
| windows/sysmon | 1 | 0 |
| windows/taskscheduler | 1 | 0 |
| windows/wmi | 1 | 0 |

## Benign replay, evtx-baseline goodware

| Hosts | Host-days scanned | Events | Alerts | Alerts per host-day | Medium+ per host-day | Budget | Within budget |
|-:|-:|-:|-:|-:|-:|-:|:-|
| 1 | 31.23 | 224797 | 494 | 15.82 | 13.80 | 20.0 | yes |

| Rule | Level | Alerts | Per host-day | On known-FPs list |
|:-|:-|-:|-:|:-|
| Suspicious SQL Query | medium | 414 | 13.26 | no |
| Modification of IE Registry Settings | low | 56 | 1.79 | no |
| WMI Persistence | medium | 5 | 0.16 | no |
| Antivirus - Relevant File Paths Alerts Signature | high | 5 | 0.16 | no |
| Suspicious Non PowerShell WSMAN COM Provider | medium | 4 | 0.13 | no |
| Potential Defense Evasion Via Raw Disk Access By Uncommon Tools | low | 3 | 0.10 | yes |
| Disable Windows Defender Functionalities Via Registry Keys | high | 2 | 0.06 | yes |
| User Logoff Event | informational | 1 | 0.03 | no |
| Suspicious High IntegrityLevel Conhost Legacy Option | informational | 1 | 0.03 | no |
| Load Of RstrtMgr.DLL By An Uncommon Process | low | 1 | 0.03 | no |
| Remote PowerShell Session (PS Classic) | low | 1 | 0.03 | no |
| EventLog EVTX File Deleted | medium | 1 | 0.03 | no |

## Own-lab background outside run windows (Citadel)

| Hosts | Host-days scanned | Events | Alerts | Alerts per host-day | Medium+ per host-day | Budget | Within budget |
|-:|-:|-:|-:|-:|-:|-:|:-|
| 5 | 12.75 | 3896 | 712 | 55.84 | 15.84 | 20.0 | no |

Notes: citadel-lab/network-2026-09-22: scanned span under one hour, floored to one hour.

| Rule | Level | Alerts | Per host-day | On known-FPs list |
|:-|:-|-:|-:|:-|
| System Shutdown/Reboot - Linux | informational | 310 | 24.31 | no |
| Creation Of An User Account | medium | 170 | 13.33 | no |
| Service Reload or Start - Linux | low | 40 | 3.14 | no |
| System Information Discovery | informational | 40 | 3.14 | no |
| System Owner or User Discovery - Linux | low | 40 | 3.14 | no |
| System Information Discovery - Auditd | low | 40 | 3.14 | no |
| System Network Discovery - Linux | informational | 35 | 2.74 | no |
| Suspicious SQL Query | medium | 25 | 1.96 | no |
| File Deletion | informational | 5 | 0.39 | no |
| Linux Reverse Shell Indicator | critical | 5 | 0.39 | no |
| Execution Of Script Located In Potentially Suspicious Directory | medium | 2 | 0.16 | no |

## Tri-state evaluation: not evaluable, never no match

A rule that did not match, and whose answer depended on a field the event's source does not carry, is counted here and never as a no match or as coverage (START_PROMPT section 3, rule 3). Grammar-unsupported rules are listed under Rules.

Rule-event pairs not evaluable: 1938572 (benign 1299344, fixture 46, positive 639182, regression 0). Rules not evaluable at least once: 883, of which 799 alerting class.

Separately, 19271072 rule-event pairs on 1444 rules were outside the rule's source: the event carries none of the fields the rule reads, because Bastion does not route that logsource yet (B3). Those are not evaluable either, and never a no match. By logsource (product/category/service): /proxy/ 9873079, /dns/ 2383157, /antivirus/ 2299804, /webserver/ 1702255, windows/file_access/ 973623, linux/process_creation/ 826470, /firewall/ 340451, windows/file_rename/ 313803, windows/driver_load/ 149650, windows//powershell-classic 88572, linux/file_event/ 82200, linux/network_connection/ 52450, linux//auditd 47650, windows/process_creation/ 43130, linux// 42432.

| Missing field (reason) | Rule-event pairs |
|:-|-:|
| FileName | 624337 |
| OriginalFileName | 468458 |
| cs-method | 340549 |
| cs-uri-query | 340451 |
| NewName | 279774 |
| Description | 111028 |
| Hashes | 94361 |
| ParentImage | 76733 |
| Product | 67793 |
| ParentCommandLine | 33878 |
| Details | 27154 |
| CommandLine | 24339 |
| Company | 23831 |
| SamAccountName | 18226 |
| Data | 14980 |
| Provider_Name | 8291 |
| ServiceName | 7578 |
| Image | 6506 |
| a5 | 4551 |
| a6 | 4548 |
| a7 | 4548 |
| a4 | 4547 |
| TargetFilename | 4300 |
| ParentUser | 3933 |
| ImagePath | 3789 |

Labelled captures, held out split, not detected while an alerting rule tagged to the label was not evaluable on some event: 60.
Labelled captures, development split, not detected while an alerting rule tagged to the label was not evaluable on some event: 49.

## Evidence ladder (strongest evidence per enterprise technique)

| Held-out-proven | Sample-proven | Fixture-proven | Rule-only | None |
|-:|-:|-:|-:|-:|
| 78 | 24 | 3 | 275 | 326 |

## Robustness (Summiting the Pyramid)

0 of 3150 rules scored; 3150 unscored. Scoring starts in B4.

## Captures

1322 captures evaluated: regression 187, positive 796, benign 335, fixture 4. Unlabelled positive captures (scanned, in no rate): 26. Skipped: 0.

Pins: sigma r2026-07-01, sigma_commit 552f3fee420ef232a8e5790c4fae591847e32347, attack 20.1, corpus:regression_data 552f3fee420ef232a8e5790c4fae591847e32347, corpus:evtx_attack_samples 4ceed2f4706daf601c212a8f91c113dd85349a2c, corpus:evtx_baseline v0.8.5, corpus:attack_data b4573ed3b6bf05473b01048dd36380dbd52288c0, corpus:citadel_captures 2026-09-26.
