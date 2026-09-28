# Draft upstream issue texts for the open tag disputes

Drafts only, for Mason's review. Nothing here has been filed with SigmaHQ. Each draft
follows the SigmaHQ issue conventions: the rule by id and title, the tag as carried, the tag the
evidence points at, the evidence, and the ask. The evidence is one public capture each from
EVTX-ATTACK-SAMPLES (GPL-3.0, sbousseaden) evaluated by Bastion against Sigma `r2026-04-01`
and ATT&CK 19.1 on 2026-09-26; see `docs/tag-disputes.md` for the ledger entries.

## 1. Potential Dropper Script Execution Via WScript/CScript/MSHTA

Title: ATT&CK tag for "Potential Dropper Script Execution Via WScript/CScript/MSHTA" omits
T1218.005 when the image is mshta.exe

Body:

The rule tags `attack.t1059.005` and `attack.t1059.007` (VBScript, JavaScript). Its image
selection also includes `mshta.exe`, and when it fires on an mshta invocation the behaviour
is System Binary Proxy Execution: Mshta (T1218.005), not a scripting interpreter. On the
public capture `Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.evtx`
(EVTX-ATTACK-SAMPLES), the rule fires on the mshta launch and the capture is labelled
T1218.005 by the corpus author; an evaluation keyed on the rule's tags records this as a miss
for T1218.005 and a hit for T1059.005. Would the maintainers consider adding
`attack.t1218.005`, or splitting the mshta branch into its own rule with that tag?

## 2. PowerShell Credential Prompt

Title: "PowerShell Credential Prompt" is tagged T1059.001 only; the detected behaviour is
T1056.002 GUI Input Capture

Body:

The rule detects `Get-Credential` and `PromptForCredential` in script block logging, which
is the credential prompt technique ATT&CK files under Input Capture: GUI Input Capture
(T1056.002). It carries only `attack.t1059.001` (PowerShell), which describes the execution
medium rather than the behaviour. On the public capture
`Credential Access/phish_windows_credentials_powershell_scriptblockLog_4104.evtx`
(EVTX-ATTACK-SAMPLES, labelled T1056.002 by the author), the rule fires and a tag-keyed
evaluation counts it against T1059.001 only. Would you consider adding `attack.t1056.002` and
`attack.credential-access`?

## 3. RottenPotato Like Attack Pattern

Title: "RottenPotato Like Attack Pattern" tagged T1557.001 (LLMNR/NBT-NS poisoning); the
potato family is token impersonation, T1134.001

Body:

The rule looks for a 4624 logon with type 3, ANONYMOUS LOGON and a loopback source, which
is the RottenPotato and JuicyPotato local privilege escalation pattern (NTLM relay to a local
COM listener, then token impersonation). ATT&CK files that under Access Token Manipulation:
Token Impersonation/Theft (T1134.001); the LLMNR/NBT-NS Poisoning and SMB Relay tag
(T1557.001) describes network-level poisoning that this pattern does not involve. On the
public capture `Privilege Escalation/4624 LT3 AnonymousLogon Localhost - JuicyPotato.evtx`
(EVTX-ATTACK-SAMPLES, labelled T1134 by the author) the rule fires and a tag-keyed evaluation
records a miss for T1134. Would the maintainers consider `attack.t1134.001` and
`attack.privilege-escalation` in place of, or beside, `attack.t1557.001`?

## 4. Creation Exe for Service with Unquoted Path

Title: "Creation Exe for Service with Unquoted Path" tagged T1547.009 (Shortcut Modification);
unquoted service paths are T1574.009

Body:

The rule detects an executable written into a path that exploits an unquoted service
binary path (for example `C:\Program.exe`). ATT&CK files that under Hijack Execution Flow:
Path Interception by Unquoted Path (T1574.009). The rule carries `attack.t1547.009`, which is
Boot or Logon Autostart Execution: Shortcut Modification and does not describe this
behaviour. On the public capture `Privilege Escalation/privesc_unquoted_svc_sysmon_1_11.evtx`
(EVTX-ATTACK-SAMPLES, labelled T1574 by the author) the rule fires and a tag-keyed evaluation
records a miss for T1574. Would you consider `attack.t1574.009` with
`attack.persistence` and `attack.privilege-escalation`?
