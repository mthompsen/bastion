# Sample logs

Small, inert log samples used in the README walkthrough. They are records of attack-like
activity kept for detection testing: plain text and event data, nothing executable.

- `auth_sample.log`: synthetic Linux `auth.log` excerpt, hand-written for this project. An
  SSH brute-force pattern, an accepted login, and a suspicious `sudo` read of `/etc/shadow`.
- `syslog_attack_sample.log`: synthetic syslog excerpt recording a small intrusion. SSH brute
  force, then shell-audit lines capturing a reverse-shell one-liner and command-history
  tampering.
- `sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx` and
  `Sysmon_13_1_UACBypass_SDCLTBypass.evtx`: real Sysmon telemetry of a BITS-job persistence
  technique (regsvr32 with a remote .sct) and an SDCLT UAC bypass, from the public
  [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) corpus by
  [@sbousseaden](https://github.com/sbousseaden), used with attribution.

The committed run in `examples/output/` was produced from the BITS-job sample with
`bastion report examples/logs/sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx -o examples/output`.
