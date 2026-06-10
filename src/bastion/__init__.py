"""Bastion: a Sigma/ATT&CK detection engine for host log files.

Bastion ingests Windows EVTX or Linux auth/syslog files, evaluates them
against the public Sigma ruleset, enriches matches with MITRE ATT&CK
technique context, and reports both detections and honest coverage.
"""

__version__ = "0.1.0"
