# Bastion

A command-line detection engine that ingests host security logs (Windows Sysmon/EVTX or Linux
auth/syslog), evaluates them against the public [Sigma](https://github.com/SigmaHQ/sigma)
detection ruleset, maps every matching rule to its [MITRE ATT&CK](https://attack.mitre.org/)
technique, and produces an alert report plus an honest **coverage map** of which ATT&CK
techniques the loaded ruleset can — and cannot — detect.

Bastion is fully defensive: it reads log files you own and recognizes traces of known attack
techniques. It never generates, executes, or assists attacks.

> **Status:** under construction, built phase by phase per [SPEC.md](SPEC.md).
> Phase 1 (scaffold, data models, log ingestion) is complete.

## Quick start

```console
pip install -e .
bastion --help
bastion scan examples/logs/auth_sample.log
```

## Development

```console
pip install -e ".[dev]"
ruff check .
mypy
pytest
```

A full README (architecture, real sample run, dashboard screenshot) lands in Phase 6.

## License

MIT — see [LICENSE](LICENSE).
