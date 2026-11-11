# ATT&CK Enterprise 19.1 to 20.1: what changed for Bastion

Computed on 2026-11-10 from the two STIX bundles themselves, not from release notes:
`enterprise-attack-19.1.json` (the B1 pin) and `enterprise-attack-20.1.json` (attack-stix-data
commit `f59b03e`, sha256 `539a843a...b910b5`, published 2026-11-05). ATT&CK 20.0 was published
on 2026-10-13; 20.1 is the latest release. Lever b of `docs/milestones/B2.md`.

## Denominators

| Count (live, not revoked, not deprecated) | 19.1 | 20.1 |
|:-|-:|-:|
| Enterprise techniques and sub-techniques | 697 | 706 |
| Listing Windows | 474 | 479 |
| Listing Linux | 355 | 356 |
| Tactics | 15 | 15 |

The tactic list is identical in both releases, including Stealth (TA0005) and Defense
Impairment (TA0112), which replaced Defense Evasion in 19.0.

## Every technique-level change

| Change | Count | Techniques |
|:-|-:|:-|
| Added | 9 | T1608.007 AI Result Poisoning (resource-development); T1685.007 Impair Autonomous Defenses (defense-impairment); T1696 Anti-Automation Evasion, T1696.001 Automate CAPTCHA Completion, T1696.002 Avoid CAPTCHA (stealth); T1697 Steal Application Specific Passwords (credential-access); T1698 Indirect Prompt Injection, T1699 Direct Prompt Injection (execution); T1700 AI-Enabled Exfiltration (exfiltration) |
| Revoked | 0 | none |
| Deprecated | 0 | none |
| Moved tactics | 0 | none |
| Renamed | 0 | none |
| Platform list changed | 2 | T1021.004 SSH gains Windows (now ESXi, Linux, Windows, macOS); T1059.001 PowerShell gains Linux and macOS (now Linux, Windows, macOS) |

Deprecated with no successor in 20.1 (all already deprecated in 19.1): T1026, T1034, T1043,
T1051, T1053.004, T1061, T1062, T1064, T1108, T1149, T1153, T1175. No loaded rule (Sigma
`r2026-04-01` plus the local pack) tags any of them, so none is excluded from a count today;
any that a future rule tags is excluded and listed under `tag_resolution` in every output.

## Rule tags resolved through revoked-by

Before B2 a rule tag naming a revoked technique matched nothing: the detection carried no
technique and the claim counted for nothing. B2 follows ATT&CK's `revoked-by` relationships to
the live successor (`attack.resolve_rule_tags`); the rule files are not edited. On Sigma
`r2026-04-01` plus the local pack, the same 12 tags on 220 rules resolve under 19.1 and 20.1:

| Tag in the rule | Counts as | Rules |
|:-|:-|-:|
| T1070.001 | T1685.005 | 6 |
| T1070.002 | T1685.006 | 4 |
| T1562 | T1685 | 26 |
| T1562.001 | T1685 | 126 |
| T1562.002 | T1685.001 | 26 |
| T1562.003 | T1690 | 1 |
| T1562.004 | T1686 | 26 |
| T1562.006 | T1685 | 7 |
| T1562.007 | T1686.001 | 3 |
| T1562.008 | T1685.002 | 3 |
| T1562.010 | T1689 | 1 |
| T1562.012 | T1685.004 | 1 |

Techniques that become claimable by this: T1685, T1685.001, T1685.002, T1685.005, T1685.006,
T1686, T1686.001, T1689, T1690 (9). Bench before and after: `docs/milestones/B2.md` section 5.
