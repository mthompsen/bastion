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

These are experimental, single-host detections written against the log shapes Bastion ingests
(auth.log/syslog text and Sysmon process creation). Review the false-positive notes inside
each rule before relying on them. Licensed MIT with the rest of the repository.
