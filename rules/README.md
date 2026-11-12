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
