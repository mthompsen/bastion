# B1 appendix: held-out captures that alerted but were not detected

Companion to `docs/milestones/B1.md` section 4. Held-out split of run `b1-baseline`, Sigma
`r2026-04-01` plus 8 local rules, ATT&CK 19.1, seed 20260926. 130 labelled captures; 75 had
at least one alerting-class rule fire; 33 were detected under the headline (parent-aware)
definition, 29 under the strict definition. The 42 below alerted without being detected.
Bucket assignments are the reviewer's reading of one capture each, listed so any one of them
can be disputed. Labels are the live ATT&CK 19.1 ids after `revoked-by` resolution; the raw
sheet id follows in brackets where it differs.

## A. Side activity: label and firing rule both plausible, for different behaviour (30)

| Capture | Label | Rules that fired (tag) |
|:-|:-|:-|
| tunna_iis_rdp_smb_tunneling_sysmon_3.evtx | T1090 | Outbound RDP Connections Over Non-Standard Tools (T1021.001) |
| CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx | T1003 | HackTool - Mimikatz Kirbi File Creation (T1558) |
| sysmon17_18_kekeo_tsssp_default_np.evtx | T1550.003 [T1097] | Raw Disk Access By Uncommon Tools (T1006) |
| DSE_bypass_BYOV_TDL_dummydriver_sysmon_6_7_13.evtx | T1014 | Vulnerable Driver Load (T1543.003, T1068), UACMe Akagi (T1548.002), T1006 |
| Sysmon_10_Evasion_Suspicious_NtOpenProcess_CallTrace.evtx | T1055 | Potential Direct Syscall of NtOpenProcess (T1106) |
| Sysmon_12_DE_AntiForensics_MRU_DeleteKey.evtx | T1685 [T1089] | T1006 |
| evasion_codeinj_odzhan_conhost_sysmon_10_1.evtx | T1055 | Uncommon Child Process Of Conhost.EXE (T1202), T1006 |
| evasion_codeinj_odzhan_spoolsv_sysmon_10_1.evtx | T1055 | T1006 |
| sysmon_2_11_evasion_timestomp_MACE.evtx | T1070.006 [T1099] | Startup Folder Persistence, Startup Folder File Write (T1547.001) |
| Exec_sysmon_meterpreter_reversetcp_msipackage.evtx | T1218 | Always Install Elevated MSI (T1548.002), Local Accounts Discovery (T1033, T1087.001), T1006 |
| sysmon_1_11_rundll32_cpl_ostap.evtx | T1218.002 [T1196] | Script Interpreter From Suspicious Folder (T1059), Cscript/Wscript Uncommon Extension (T1059.005, T1059.007) |
| sysmon_lolbin_bohops_vshadow_exec.evtx | T1218 | T1006 (vshadow does read the raw disk) |
| LM_sysmon_1_12_13_3_tsclient_SharpRdp.evtx | T1021.001 [T1076] | T1006 |
| powercat_revShell_sysmon_1_3.evtx | T1059.001 [T1086] | Suspicious Execution of Systeminfo (T1082), Local Accounts Discovery (T1033) |
| remote_file_copy_system_proc_file_write_sysmon_11.evtx | T1021.002 [T1077] | PsExec Service File Creation (T1569.002), PsExec Service Execution (untagged), T1006 |
| persist_firefox_comhijack_sysmon_11_13_7_1.evtx | T1546.015 [T1122] | Suspicious File Characteristics (T1059.006), T1006 |
| persist_valid_account_guest_rid_hijack.evtx | T1078 | PUA Sysinternals Tool Execution (T1588.002), T1006 |
| persistence_accessibility_features_osk_sysmon1.evtx | T1546.008 [T1015] | Local Accounts Discovery, Whoami.EXE rules (T1033) |
| persistence_pendingGPO_sysmon_13.evtx | T1037.001 | T1006 |
| sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx | T1197 | Regsvr32 HTTP/FTP Pattern, Regsvr32 Flag Anomaly, Network Connection By Regsvr32 (T1218.010) |
| PrivEsc_Imperson_NetSvc_to_Sys_Decoder_Sysmon_1_17_18.evtx | T1134 | Local Accounts Discovery, Whoami (T1033), T1006 |
| RogueWinRM.evtx | T1068 | Local Accounts Discovery, Whoami (T1033), T1006 |
| privesc_rotten_potato_from_webshell_metasploit_sysmon_1_8_3.evtx | T1134 | Remote Thread rules (T1055, T1055.003), Network Connection Via Notepad (T1055) |
| privesc_seimpersonate_tosys_spoolsv_sysmon_17_18.evtx | T1134 | EfsPotato Named Pipe (T1055), Whoami (T1033), T1006 |
| sysmon_13_1_12_11_perfmonUACBypass.evtx | T1548.002 [T1088] | T1006 |
| sysmon_1_7_11_mcx2prov_uacbypass.evtx | T1548.002 [T1088] | System DLL Sideloading (T1574.001), Wusa cab extraction (untagged), T1006 |
| sysmon_1_7_11_sysprep_uacbypass.evtx | T1548.002 [T1088] | Wusa cab extraction (untagged), T1006 |
| sysmon_privesc_from_admin_to_system_handle_inheritance.evtx | T1134 | Unusual Parent For Cmd.EXE (T1059), Abused Debug Privilege (T1548), T1006 |
| attack_data T1068 kern.log (linux_secure) | T1068 | Modifying Crontab (T1053.003), Suspicious SQL Query (T1190, T1505.001), Suspicious Log Entries (untagged) |
| attack_data T1552.004 auditd | T1552.004 | System Shutdown/Reboot - Linux (T1529), Suspicious SQL Query (T1190, T1505.001) |

## B. Rule tag disputes: the rule fired on the labelled behaviour, its tag names another technique (4)

Recorded as open entries in `docs/tag-disputes.md`.

| Capture | Label | Rule (tag) |
|:-|:-|:-|
| sysmon_mshta_sharpshooter_stageless_meterpreter.evtx | T1218.005 [T1170] | Potential Dropper Script Execution Via WScript/CScript/MSHTA (T1059.005, T1059.007) |
| phish_windows_credentials_powershell_scriptblockLog_4104.evtx | T1056.002 [T1141] | PowerShell Credential Prompt (T1059.001) |
| 4624 LT3 AnonymousLogon Localhost - JuicyPotato.evtx | T1134 | RottenPotato Like Attack Pattern (T1557.001) |
| privesc_unquoted_svc_sysmon_1_11.evtx | T1574 | Creation Exe for Service with Unquoted Path (T1547.009) |

## C. Label quality: the corpus label is coarse or wrong and the firing rule names the closer technique (8)

Left as the corpus wrote them; the bench never edits upstream labels.

| Capture | Label | Rule (tag) | Reading |
|:-|:-|:-|:-|
| sysmon_11_1_lolbas_downldr_desktopimgdownldr.evtx | T1218 | Suspicious Desktopimgdownldr Command and Target File (T1105) | Download-cradle LOLBAS; the sheet gives the sibling file T1105 |
| persistence_security_dcshadow_4742.evtx | T1546.011 [T1138] | Possible DC Shadow Attack (T1207) | Sheet row mislabelled: the capture is DCShadow |
| CA_keefarce_keepass_credump.evtx | T1003 | Remote Thread Created In KeePass.EXE (T1555.005) | Password-manager credential theft |
| CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx | T1003 | Remote Thread Created In KeePass.EXE (T1555.005) | Same |
| LM_wmi_PoisonHandler_Mr-Un1k0d3r_sysmon_1_13.evtx | T1021 | WmiPrvSE Spawned A Process, Suspicious WmiPrvSE Child (T1047) | WMI lateral movement |
| remote task update 4624 4702 same logonid.evtx | T1021 | Suspicious Scheduled Task Update (T1053.005) | Remote scheduled task |
| attack_data T1083 auditd (hidden file) | T1083 | Hidden Files and Directories (T1564.001) | Dataset is a hidden-file search |
| security_4624_4673_token_manip.evtx | T1548.002 [T1088] | Overpass the Hash, Pass the Hash Activity 2 (T1550.002), Outgoing Logon with New Credentials (T1550) | Logon type 9 with new credentials; ambiguous, counted here |

## No alerting rule fired (55)

Not part of the 42 above. attack_data: 33 datasets, 24 with no EXECVE record (no
`CommandLine`), 9 with EXECVE and no rule fired. EVTX-ATTACK-SAMPLES: 22 files, listed in the
`b1-baseline` summary under captures with zero alerting rules.
