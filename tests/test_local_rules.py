"""Tests for the hand-written rule pack shipped under rules/."""

from __future__ import annotations

from pathlib import Path

import pytest

from bastion.models import Event, FieldValue
from bastion.sigma.correlation import load_correlations
from bastion.sigma.loader import load_rules
from bastion.sigma.matcher import match

LOCAL_RULES_DIR = Path(__file__).parent.parent / "rules"
LOCAL_RULES = load_rules(LOCAL_RULES_DIR)


def make_event(platform: str, **fields: FieldValue) -> Event:
    return Event(
        platform=platform,  # type: ignore[arg-type]
        source="test",
        fields=dict(fields),
        raw=" ".join(str(v) for v in fields.values() if v is not None),
    )


def test_every_rule_file_loads() -> None:
    """Single-event rules load as rules; correlation files load through the correlation loader."""
    rule_files = list(LOCAL_RULES_DIR.rglob("*.yml"))
    correlations = load_correlations(LOCAL_RULES_DIR)
    assert not correlations.errors and not correlations.unsupported
    assert len(LOCAL_RULES) + len(correlations.rules) == len(rule_files)
    assert len(LOCAL_RULES) >= 8


def test_every_rule_has_required_metadata() -> None:
    for rule in LOCAL_RULES:
        assert rule.attack_techniques, f"{rule.title} has no technique tag"
        assert rule.attack_tactics, f"{rule.title} has no tactic tag"
        assert rule.logsource.get("product") in ("linux", "windows"), rule.title
        assert rule.description, f"{rule.title} has no description"


def test_every_rule_is_evaluable() -> None:
    """No rule in our own pack may use grammar the matcher cannot evaluate."""
    linux_event = make_event("linux", process="sudo", message="benign activity")
    windows_event = make_event("windows", EventID=1, Image="C:\\x.exe", CommandLine="benign")
    for rule in LOCAL_RULES:
        event = windows_event if rule.logsource.get("product") == "windows" else linux_event
        match(rule, event)  # raises UnsupportedRuleError on grammar problems


@pytest.mark.parametrize(
    ("title", "message"),
    [
        (
            "Shadow File Read Attempt",
            "  alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        ),
        (
            "Systemd Timer Unit Creation Or Activation",
            "  bob : USER=root ; COMMAND=/usr/bin/systemctl enable evil-backup.timer",
        ),
        (
            "SSH Authorized Keys File Modification",
            "shell command executed by alice: echo ssh-rsa AAAA... >> /root/.ssh/authorized_keys",
        ),
        (
            "PAM Configuration Modification",
            "shell command executed by alice: sed -i 's/sufficient/required/' /etc/pam.d/sshd",
        ),
        (
            "Crypto Miner Indicators In Logs",
            "shell command executed by alice: ./xmrig -o stratum+tcp://pool.example:3333",
        ),
        (
            "Host Log Enumeration",
            "shell command executed by alice: utmpdump /var/log/wtmp",
        ),
    ],
)
def test_linux_rules_fire_on_attack_traces(title: str, message: str) -> None:
    rules = {rule.title: rule for rule in LOCAL_RULES}
    event = make_event("linux", process="sudo", message=message)
    result = match(rules[title], event)
    assert result.matched, f"{title} did not fire on: {message}"
    assert result.matched_fields


def test_linux_rules_stay_quiet_on_benign_lines() -> None:
    benign = make_event(
        "linux",
        process="sshd",
        message="Accepted password for alice from 10.0.0.5 port 51022 ssh2",
    )
    for rule in LOCAL_RULES:
        if rule.logsource.get("product") == "linux":
            assert not match(rule, benign).matched, f"{rule.title} fired on a benign login"


@pytest.mark.parametrize(
    ("title", "image", "command_line"),
    [
        (
            "Wi-Fi Profile Enumeration Via Netsh",
            "C:\\Windows\\System32\\netsh.exe",
            "netsh wlan show profile name=corp key=clear",
        ),
        (
            "System Language And Location Discovery",
            "C:\\Windows\\System32\\reg.exe",
            "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language",
        ),
        (
            "System Language And Location Discovery",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell -c Get-WinHomeLocation",
        ),
    ],
)
def test_windows_rules_fire_on_attack_traces(title: str, image: str, command_line: str) -> None:
    rules = {rule.title: rule for rule in LOCAL_RULES}
    event = make_event("windows", EventID=1, Image=image, CommandLine=command_line)
    assert match(rules[title], event).matched


def test_windows_rules_stay_quiet_on_benign_process() -> None:
    benign = make_event(
        "windows",
        EventID=1,
        Image="C:\\Windows\\System32\\notepad.exe",
        CommandLine="notepad.exe C:\\notes.txt",
    )
    for rule in LOCAL_RULES:
        if rule.logsource.get("product") == "windows":
            assert not match(rule, benign).matched, f"{rule.title} fired on notepad"


# --- B4 lever a: Linux writable-gap rules (experimental, hunting class) ----------------------

B4_LINUX = {
    "RC Script Modified From The Command Line": (
        [("/usr/bin/tee", "tee -a /etc/rc.local"), ("/usr/bin/chmod", "chmod +x /etc/rc.local")],
        [("/usr/bin/cat", "cat /etc/rc.local"), ("/usr/bin/tee", "tee -a /etc/hosts")],
    ),
    "Loaded Kernel Module Enumeration": (
        [
            ("/usr/bin/kmod", "lsmod"),
            ("/usr/sbin/modinfo", "modinfo e1000"),
            ("/usr/bin/cat", "cat /proc/modules"),
            ("/usr/bin/kmod", "kmod list"),
        ],
        [("/usr/bin/kmod", "kmod static-nodes"), ("/usr/bin/cat", "cat /proc/cpuinfo")],
    ),
    "Shared Object Compiled With A Load-Time Initialiser": (
        [
            (
                "/usr/bin/x86_64-linux-gnu-gcc-13",
                "gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c",
            )
        ],
        [
            ("/usr/bin/gcc", "gcc -shared -fPIC -o libfoo.so foo.c"),
            ("/usr/bin/gcc", "gcc -Wl,-init,x -o prog prog.c"),
        ],
    ),
}


@pytest.mark.parametrize("title", sorted(B4_LINUX))
def test_b4_linux_process_rules_fire_and_stay_quiet(title: str) -> None:
    rule = next(r for r in LOCAL_RULES if r.title == title)
    assert rule.status == "experimental"
    positives, negatives = B4_LINUX[title]
    for image, command_line in positives:
        event = make_event("linux", Image=image, CommandLine=command_line)
        assert match(rule, event).matched, (title, command_line)
    for image, command_line in negatives:
        event = make_event("linux", Image=image, CommandLine=command_line)
        assert not match(rule, event).matched, (title, command_line)


# --- B4b: Windows procedure-variant rules (experimental until benign evidence holds) ---------

B4B_WINDOWS: dict[str, tuple[list[dict[str, FieldValue]], list[dict[str, FieldValue]]]] = {
    "PowerShell Runs Code Stored In An Environment Variable": (
        [
            {"EventID": 4104, "ScriptBlockText": "IEX $env:INTERNAL_DB_CACHE"},
            {"EventID": 4104, "ScriptBlockText": "Invoke-Expression ($env:Payload)"},
        ],
        [
            {"EventID": 4104, "ScriptBlockText": "Write-Output $env:USERNAME"},
            {"EventID": 4104, "ScriptBlockText": "IEX (Get-Content .\\setup.ps1 -Raw)"},
        ],
    ),
    "PowerShell Invokes A Command Name Built From Concatenated Fragments": (
        [
            {
                "EventID": 4104,
                "ScriptBlockText": "&('ne'+'w-'+'item') $env:temp -itemtype Directory",
            },
            {"EventID": 4104, "ScriptBlockText": '. ( "Invo" + "ke-Item" ) $x'},
        ],
        [
            {"EventID": 4104, "ScriptBlockText": "& 'C:\\tools\\run.ps1' -Verbose"},
            {"EventID": 4104, "ScriptBlockText": "$path = 'C:\\' + 'logs'; & $cmd $path"},
        ],
    ),
    "AdminSDHolder Security Descriptor Modified": (
        [
            {
                "EventID": 5136,
                "ObjectDN": "CN=AdminSDHolder,CN=System,DC=corp,DC=local",
                "AttributeLDAPDisplayName": "nTSecurityDescriptor",
            }
        ],
        [
            {
                "EventID": 5136,
                "ObjectDN": "CN=AdminSDHolder,CN=System,DC=corp,DC=local",
                "AttributeLDAPDisplayName": "description",
            },
            {
                "EventID": 5136,
                "ObjectDN": "CN=Users,DC=corp,DC=local",
                "AttributeLDAPDisplayName": "nTSecurityDescriptor",
            },
        ],
    ),
    "Auto-Elevating Binary Opened By A Program Outside System Folders": (
        [
            {
                "EventID": 10,
                "SourceImage": "C:\\Temp\\loader.exe",
                "TargetImage": "C:\\Windows\\System32\\ComputerDefaults.exe",
                "GrantedAccess": "0x12367b",
            }
        ],
        [
            {
                "EventID": 10,
                "SourceImage": "C:\\Windows\\System32\\svchost.exe",
                "TargetImage": "C:\\Windows\\System32\\fodhelper.exe",
                "GrantedAccess": "0x1000",
            },
            {
                "EventID": 10,
                "SourceImage": "C:\\Temp\\loader.exe",
                "TargetImage": "C:\\Windows\\System32\\notepad.exe",
                "GrantedAccess": "0x1fffff",
            },
        ],
    ),
    "PsExec-Style Service Redirection Pipes Under Any Service Name": (
        [
            {
                "EventID": 17,
                "Image": "C:\\Windows\\svchost.exe",
                "PipeName": "\\svchost-WS01-8116-stdin",
            },
            {
                "EventID": 17,
                "Image": "C:\\Windows\\PSEXESVC.exe",
                "PipeName": "\\PSEXESVC-WS01-42-stderr",
            },
        ],
        [
            {"EventID": 17, "Image": "C:\\Windows\\svchost.exe", "PipeName": "\\svchost"},
            {"EventID": 17, "Image": "C:\\x.exe", "PipeName": "\\mojo.1234.5678.stdin"},
        ],
    ),
}


@pytest.mark.parametrize("title", sorted(B4B_WINDOWS))
def test_b4b_windows_rules_fire_and_stay_quiet(title: str) -> None:
    rule = next(r for r in LOCAL_RULES if r.title == title)
    positives, negatives = B4B_WINDOWS[title]
    for fields in positives:
        assert match(rule, make_event("windows", **fields)).matched, (title, fields)
    for fields in negatives:
        assert not match(rule, make_event("windows", **fields)).matched, (title, fields)


# --- B4b batch 2: Windows procedure-variant rules ---------------------------------------------

B4B_WINDOWS_2: dict[str, tuple[list[dict[str, FieldValue]], list[dict[str, FieldValue]]]] = {
    "MMC Opens A Console File From A User-Writable Folder": (
        [
            {
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\mmc.exe",
                "CommandLine": '"C:\\Windows\\system32\\mmc.exe" "C:\\Temp\\guide\\prompts.msc"',
            },
            {
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\mmc.exe",
                "CommandLine": 'mmc.exe "C:\\Users\\bob\\Downloads\\invoice.msc"',
            },
        ],
        [
            {
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\mmc.exe",
                "CommandLine": 'mmc.exe "C:\\Windows\\system32\\compmgmt.msc"',
            },
            {
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\notepad.exe",
                "CommandLine": "notepad.exe C:\\Temp\\notes.msc",
            },
        ],
    ),
    "WinRM TrustedHosts Changed From PowerShell": (
        [
            {
                "EventID": 4104,
                "ScriptBlockText": "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value '*'",
            }
        ],
        [
            {
                "EventID": 4104,
                "ScriptBlockText": "Get-Item WSMan:\\localhost\\Client\\TrustedHosts",
            },
            {"EventID": 4104, "ScriptBlockText": "Set-Item -Path Env:TrustedHostsNote -Value 1"},
        ],
    ),
    "Service Process Started From The Root Of The Windows Folder": (
        [
            {
                "EventID": 1,
                "Image": "C:\\Windows\\XSljVQla.exe",
                "ParentImage": "C:\\Windows\\System32\\services.exe",
            }
        ],
        [
            {
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "ParentImage": "C:\\Windows\\System32\\services.exe",
            },
            {
                "EventID": 1,
                "Image": "C:\\Windows\\explorer.exe",
                "ParentImage": "C:\\Windows\\System32\\userinit.exe",
            },
        ],
    ),
    "RDP Client Control Loaded By A Program Outside System Folders": (
        [
            {
                "EventID": 7,
                "Image": "C:\\ProgramData\\USOShared\\SharpRDP.exe",
                "ImageLoaded": "C:\\Windows\\SysWOW64\\mstscax.dll",
            }
        ],
        [
            {
                "EventID": 7,
                "Image": "C:\\Windows\\System32\\mstsc.exe",
                "ImageLoaded": "C:\\Windows\\System32\\mstscax.dll",
            },
            {
                "EventID": 7,
                "Image": "C:\\ProgramData\\tool.exe",
                "ImageLoaded": "C:\\Windows\\System32\\kernel32.dll",
            },
        ],
    ),
    "File System Transaction Used By A Program Outside System Folders": (
        [{"EventID": 4985, "ProcessName": "C:\\ProgramData\\proc_doppel64.exe"}],
        [
            {"EventID": 4985, "ProcessName": "C:\\Windows\\System32\\msiexec.exe"},
            {"EventID": 4688, "ProcessName": "C:\\ProgramData\\proc_doppel64.exe"},
        ],
    ),
    "Registry Symbolic Link Created By A Program Outside System Folders": (
        [
            {
                "EventID": 13,
                "Image": "C:\\Users\\u\\Desktop\\exploit.exe",
                "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\DRM\\DEMO2\\SymbolicLinkValue",
                "Details": "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ABC",
            }
        ],
        [
            {
                "EventID": 13,
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "TargetObject": "HKLM\\SOFTWARE\\Classes\\x\\SymbolicLinkValue",
                "Details": "\\Registry\\Machine\\Software\\Classes\\y",
            },
            {
                "EventID": 13,
                "Image": "C:\\Users\\u\\Desktop\\tool.exe",
                "TargetObject": "HKCU\\Software\\Tool\\Setting",
                "Details": "1",
            },
        ],
    ),
    "Printer CopyFiles Module Registered To A Non-Default Library": (
        [
            {
                "EventID": 13,
                "Image": "C:\\Windows\\System32\\spoolsv.exe",
                "TargetObject": (
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers"
                    "\\Microsoft XPS Document Writer v4\\CopyFiles\\Module"
                ),
                "Details": "C:\\Windows\\system32\\spool\\DRIVERS\\x64\\4\\Test.dll",
            }
        ],
        [
            {
                "EventID": 13,
                "Image": "C:\\Windows\\System32\\spoolsv.exe",
                "TargetObject": (
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers"
                    "\\HP LaserJet\\CopyFiles\\ICM\\Module"
                ),
                "Details": "mscms.dll",
            }
        ],
    ),
    "Service Installed With A Bare Executable Name": (
        [
            {"EventID": 7045, "ServiceName": "remotesvc", "ImagePath": "calc.exe"},
            {"EventID": 7045, "ServiceName": "x", "ImagePath": "cmd.exe /c whoami > out.txt"},
        ],
        [
            {
                "EventID": 7045,
                "ServiceName": "Spooler",
                "ImagePath": "C:\\Windows\\System32\\spoolsv.exe",
            },
            {
                "EventID": 7045,
                "ServiceName": "svc",
                "ImagePath": '"C:\\Program Files\\Vendor\\agent.exe" -service',
            },
        ],
    ),
}


# Promoted to `test` (alerting) after b4b-2: fixtures here, goodware holding the Sysmon events they
# read, and no goodware firing. The rest stay experimental (docs/milestones/B4b.md, promotion).
B4B_PROMOTED = frozenset(
    {
        "Auto-Elevating Binary Opened By A Program Outside System Folders",
        "PsExec-Style Service Redirection Pipes Under Any Service Name",
        "MMC Opens A Console File From A User-Writable Folder",
        "RDP Client Control Loaded By A Program Outside System Folders",
        "Registry Symbolic Link Created By A Program Outside System Folders",
        "Printer CopyFiles Module Registered To A Non-Default Library",
    }
)


@pytest.mark.parametrize("title", sorted({*B4B_WINDOWS, *B4B_WINDOWS_2}))
def test_b4b_rule_status_follows_the_promotion_decision(title: str) -> None:
    rule = next(r for r in LOCAL_RULES if r.title == title)
    assert rule.status == ("test" if title in B4B_PROMOTED else "experimental")


@pytest.mark.parametrize("title", sorted(B4B_WINDOWS_2))
def test_b4b_batch2_windows_rules_fire_and_stay_quiet(title: str) -> None:
    rule = next(r for r in LOCAL_RULES if r.title == title)
    positives, negatives = B4B_WINDOWS_2[title]
    for fields in positives:
        assert match(rule, make_event("windows", **fields)).matched, (title, fields)
    for fields in negatives:
        assert not match(rule, make_event("windows", **fields)).matched, (title, fields)
