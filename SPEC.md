# Bastion - Sigma/ATT&CK Detection Engine

Design specification: architecture, domain logic, and the reasoning behind the main choices.
For usage and a worked example, start with [README.md](README.md).

As-built data pins: Sigma release `r2026-07-01`, ATT&CK enterprise STIX `v20.1`. The supported
Sigma grammar subset is documented in
[`src/bastion/sigma/matcher.py`](src/bastion/sigma/matcher.py).

---

## 1. One-line description

A command-line detection engine that ingests host security logs (Windows Sysmon/EVTX or Linux
auth/syslog, auto-selected by host OS with manual override), evaluates them against the public
Sigma detection ruleset, maps each matching rule to its MITRE ATT&CK technique, and produces an
alert report plus a coverage map of which ATT&CK techniques the loaded ruleset can and cannot
detect. Output formats: CLI, JSON, and a static HTML dashboard.

## 2. Goals

- Cover detection engineering end to end: ingest telemetry, evaluate detection logic,
  enrich with adversary-technique context, report.
- Work against the real ecosystem standards (the actual SigmaHQ ruleset and official MITRE
  ATT&CK data) rather than invented formats.
- Report coverage accurately: state which ATT&CK techniques are covered by the loaded rules and
  which are not, rather than implying total visibility.
- Be self-contained, fully defensive (it reads logs you own and detects known-bad patterns; it
  never attacks anything), deterministic, and offline after a one-time data fetch.

## 3. Non-goals

- Not a live agent, real-time stream processor, or SIEM. It analyzes log files in batch.
- Not an attack tool, payload generator, or C2. It consumes telemetry of attacks that already
  happened; it never produces malicious activity.
- Not a Sigma authoring tool and not a full Sigma backend. It implements a correct evaluator
  for a defined subset of Sigma's detection grammar. Grammar breadth is a stretch goal;
  correctness and accurate coverage reporting are the core.
- Not a rewrite of `sigma-cli`/pySigma into a SIEM query. This tool matches rules against logs
  directly, in-process.

## 4. Domain background

- Sigma: an open, vendor-neutral YAML format for log-based detections. A rule has a
  `logsource` (category/product/service), a `detection` block of named search identifiers
  combined by a `condition` expression, and metadata including `tags`. Detection identifiers
  are maps of field to value(s) with optional value modifiers (`contains`, `startswith`,
  `endswith`, `re`, `all`, etc.). Maintained at SigmaHQ/sigma on GitHub.
- Sigma to ATT&CK linkage: Sigma rules carry tags like `attack.t1059.001` (technique id) and
  tactic tags like `attack.execution`. The tag is the authoritative, rule-author-provided
  mapping; the tool reads it rather than guessing.
- MITRE ATT&CK: the public knowledge base of adversary tactics (Execution, Persistence, ...)
  and techniques (T1059 Command and Scripting Interpreter, T1059.001 PowerShell, ...).
  Published as STIX 2.1 JSON (the `enterprise-attack.json` bundle in
  mitre-attack/attack-stix-data). Each technique has an id, name, tactics, and description.
- Sysmon / EVTX: Windows System Monitor writes security telemetry (process creation with
  command lines is Event ID 1, network connections 3, image loads 7, etc.) to the Windows
  event log. Sample malicious telemetry is available as `.evtx` files in public corpora such
  as sbousseaden/EVTX-ATTACK-SAMPLES.
- Linux auth/syslog: `/var/log/auth.log`, `/var/log/syslog`, journald exports. Text logs of
  authentication, sudo, ssh, cron, and service activity.

## 5. Data sources

Two external datasets, both fetched once and cached locally so the core flow runs offline.
`scripts/fetch_data.py` (shared with the `bastion fetch` CLI command) downloads and caches
them. Exact paths and filenames were verified against the live repositories at build time
rather than trusting hardcoded URLs.

1. Sigma ruleset: a pinned release of SigmaHQ/sigma (the `rules/` tree), tag `r2026-07-01`.
   Cached under `data/sigma/`.
2. ATT&CK STIX bundle: `enterprise-attack-20.1.json` from mitre-attack/attack-stix-data.
   Cached under `data/attack/`. Used to resolve technique ids to names and tactics.

Sample logs for the worked example and tests are bundled under `examples/logs/` with
attribution: a few EVTX-ATTACK-SAMPLES files plus synthetic Linux logs. These are records of
attacks used for detection testing, not live malware.

## 6. Users and primary use cases

1. "Here's a batch of logs from a host; what known-bad activity is in them?" ->
   `bastion scan LOGFILE`.
2. "What can my current ruleset actually detect?" -> `bastion coverage`.
3. "Give me one report and a dashboard of everything found and everything I'm blind to." ->
   `bastion report LOGFILE -o out/`.

## 7. Tech stack

- Python 3.11+
- Typer (CLI), Pydantic v2 (models), PyYAML (rule parsing), Jinja2 (templating),
  python-evtx (EVTX parsing), httpx (data fetch), rich (terminal output)
- pytest + pytest-cov, ruff, mypy --strict; all must pass clean
- Packaging via `pyproject.toml`; `pip install -e .` exposes the `bastion` entry point
- Stretch: `stix2` for richer ATT&CK parsing; otherwise parse the STIX JSON directly

Dependencies are kept minimal. No database. No network in the core flow after the one-time
fetch. Builds and runs natively on Windows (it parses log files; it does not scan a host).

## 8. Repository layout

```
bastion/
├── README.md
├── SPEC.md
├── pyproject.toml
├── LICENSE                       # MIT
├── .github/workflows/ci.yml
├── data/
│   ├── sigma/                    # cached SigmaHQ rules (gitignored; fetched)
│   └── attack/                   # cached ATT&CK STIX bundle (gitignored; fetched)
├── examples/
│   ├── logs/                     # small committed sample logs (evtx + linux), attributed
│   └── output/                   # committed real sample run (report + dashboard + json + sarif)
├── rules/                        # hand-written local rule pack (loaded alongside the cache)
├── scripts/
│   └── fetch_data.py
├── src/bastion/
│   ├── __init__.py
│   ├── cli.py                    # Typer app
│   ├── models.py                 # Pydantic models (section 9)
│   ├── attack.py                 # load ATT&CK STIX -> technique lookup
│   ├── sigma/
│   │   ├── __init__.py
│   │   ├── loader.py             # parse Sigma YAML -> SigmaRule objects
│   │   ├── matcher.py            # evaluate a rule's detection/condition vs an event
│   │   └── modifiers.py          # value modifiers: contains, startswith, re, all, ...
│   ├── ingest/
│   │   ├── __init__.py
│   │   ├── base.py               # LogSource protocol -> normalized Event stream
│   │   ├── evtx.py               # Windows EVTX -> Event
│   │   └── linux.py              # auth/syslog -> Event
│   ├── engine.py                 # run rules over events -> Detections
│   ├── coverage.py               # ruleset -> ATT&CK technique coverage map
│   ├── report.py                 # CLI + JSON + HTML dashboard
│   └── templates/                # dashboard.html.j2, report.md.j2
└── tests/
    ├── fixtures/                 # sample events, rules, mini STIX bundle
    ├── test_sigma_matcher.py
    ├── test_modifiers.py
    ├── test_ingest.py
    ├── test_attack.py
    ├── test_engine.py
    └── test_coverage.py
```

## 9. Data models (Pydantic v2)

Enums / aliases:
- `Platform = Literal["windows", "linux"]`
- `Severity = Literal["informational", "low", "medium", "high", "critical"]` (Sigma `level`)

`Event` - a single normalized log record (the common shape both ingesters emit)
- `timestamp: datetime | None`
- `platform: Platform`
- `source: str` (e.g. "sysmon", "auth.log")
- `fields: dict[str, str | int | None]` - normalized field map (e.g. `Image`, `CommandLine`)
- `raw: str` - original record text, kept for evidence

`SigmaRule` - parsed from a Sigma YAML file
- `id: str`, `title: str`, `level: Severity`, `description: str`
- `logsource: dict[str, str]` (category/product/service)
- `detection: dict` (the raw detection block: identifiers plus `condition`)
- `attack_techniques: list[str]` (parsed from `tags`, e.g. `["T1059.001"]`)
- `attack_tactics: list[str]`
- `file_path: str`

`Detection` - one rule firing on one event
- `rule_id: str`, `rule_title: str`, `level: Severity`
- `event: Event`
- `matched_fields: dict[str, str]` - the field/value pairs that triggered it
- `techniques: list[TechniqueRef]`

`TechniqueRef` - enriched ATT&CK context
- `id: str` (e.g. T1059.001), `name: str`, `tactics: list[str]`

`CoverageEntry` - per-technique coverage status
- `technique: TechniqueRef`
- `rule_count: int` - how many loaded rules tag this technique
- `covered: bool`

`ScanResult` - the full output of a run
- `detections: list[Detection]`
- `events_scanned: int`, `rules_loaded: int`
- `coverage: list[CoverageEntry]`

## 10. Component specifications

### 10.1 `ingest/`
- `base.LogSource`: protocol with `parse(path) -> Iterator[Event]`. Read-only; never writes.
- `evtx.EvtxSource`: parse Windows `.evtx`, normalize common Sysmon fields (`Image`,
  `CommandLine`, `ParentImage`, `User`, `DestinationIp`, `EventID`, ...) into `Event.fields`.
- `linux.LinuxLogSource`: parse `auth.log`/`syslog`-style lines into normalized fields
  (`process`, `user`, `message`, `pid`, ...).
- OS auto-selection: a `select_source(path, platform_override)` helper picks the ingester by
  file type/extension and, when ambiguous, by the host OS (`platform.system()`), with an
  explicit `--platform` override. Default is the OS the tool is running on.
- Malformed records are skipped with a warning; they never crash the parse.

### 10.2 `sigma/`
- `loader.load_rules(dir) -> list[SigmaRule]`: walk the cached Sigma `rules/` tree, parse
  YAML, extract `attack.tXXXX` tags into `attack_techniques`/`attack_tactics`. Skip rules
  whose `logsource` names a different platform, so Windows rules are not run on Linux logs.
- `modifiers.py`: implement Sigma value modifiers; at minimum `contains`, `startswith`,
  `endswith`, `all`, `re` (regex), and base equality (case-insensitive per the Sigma spec).
  Each is a pure function with unit tests.
- `matcher.evaluate(rule, event) -> bool`: evaluate one rule's `detection` against one
  `Event`. Support field maps (a field equals/contains a value or any of a list), the
  `selection`/`filter` identifier pattern, and `condition` expressions with
  `and`/`or`/`not`/`1 of them`/`all of them`. The supported subset of the Sigma condition
  grammar must be documented explicitly; unsupported constructs raise a clear, recorded error
  rather than crashing, so coverage reporting reflects what was actually evaluable.

### 10.3 `attack.py`
- `load_attack(stix_path) -> dict[str, TechniqueRef]`: parse the enterprise-attack STIX
  bundle into a lookup of technique id to name/tactics. Handle techniques and sub-techniques.
- Resolve `SigmaRule.attack_techniques` ids to enriched `TechniqueRef`s. If a tag references
  an unknown or deprecated id, record it rather than dropping it silently.

### 10.4 `engine.py`
- `scan(events, rules, attack_lookup) -> list[Detection]`: for each event, evaluate each
  applicable rule; on a match, build a `Detection` capturing the matched field/value pairs and
  the enriched techniques.
- A rule that errors on an event is recorded as an error and skipped; a failing rule must not
  abort the scan.
- Performance: pre-filter rules by `logsource`/platform so the engine is not evaluating every
  rule against every event.

### 10.5 `coverage.py`
- `compute_coverage(rules_loaded, attack_lookup) -> list[CoverageEntry]`: for the techniques
  represented across the loaded ruleset, count how many rules tag each; mark `covered=True`
  where at least one rule exists.
- The report must also state what is not covered. The tool knows the full ATT&CK technique
  list from the STIX bundle, so it can state "the loaded ruleset references N of M enterprise
  techniques" and name the tactics with thin or no coverage. The output must never imply
  total visibility.

### 10.6 `report.py`
- CLI (`rich`): a table of detections (rule, level, technique, evidence snippet) and a
  coverage summary line ("X detections across Y techniques; ruleset covers Z of the
  enterprise matrix").
- JSON: full `ScanResult` serialized, plus a SARIF 2.1.0 log of the detections.
- HTML dashboard (Jinja2, single self-contained file): detections grouped by ATT&CK tactic,
  severity colour-coding, a coverage view that shows both covered and uncovered areas, and
  per-detection evidence (the matched fields plus the raw log line). No external network
  calls in the rendered page; inline CSS.

## 11. CLI specification (Typer)

```
bastion fetch                                  # download + cache Sigma rules and ATT&CK STIX
bastion scan LOGFILE [--platform windows|linux]    # detections to the terminal
bastion coverage [--platform ...]              # ATT&CK coverage map of the loaded ruleset
bastion report LOGFILE [-o OUTDIR] [--platform ...]  # report.md + result.json + dashboard.html
bastion rules list [--platform ...]            # loaded rules + their ATT&CK techniques
```

Every command is `--help`-documented and exits non-zero on error. `report` is the headline
command and produces the committed sample artifacts.

## 12. Output artifacts

After `bastion report examples/logs/<sample> -o out/`: `report.md`, `result.json`,
`result.sarif`, `dashboard.html`. The README shows a real run against committed sample attack
telemetry, with
`examples/output/` committed so the detections and the coverage map are visible without
running anything.

## 13. Testing and quality

- pytest covers: each modifier, the matcher across condition forms, both ingesters (fixture
  logs), ATT&CK resolution, engine detection and evidence capture, coverage computation.
  Target at least 80% line coverage.
- `ruff` and `mypy --strict` clean. CI runs lint, type-check, and tests with a coverage gate.
- No network in tests (mini fixtures for Sigma rules and STIX), no host access, no secrets.
  All tests OS-independent and offline.

## 14. Capabilities as built

- `pip install -e .`; `bastion --help` works, all subcommands documented.
- `bastion fetch` caches the real Sigma ruleset and ATT&CK STIX bundle; the flow then runs
  offline.
- `bastion scan` parses a real sample log and reports detections, each with the matched
  fields and the resolved ATT&CK technique name.
- The matcher correctly evaluates the documented Sigma grammar subset. Unsupported
  constructs are reported, not crashed on, and do not inflate coverage. (2,454 of 2,456
  upstream Windows rules evaluable at the pinned release; the remaining aggregation rules
  disclosed.)
- `bastion coverage` reports covered techniques and blind spots, without implying total
  visibility. (385/697 techniques at the pinned datasets including the local pack; 312
  uncovered techniques named.)
- One bad rule or malformed record never aborts a scan.
- `bastion report` emits report.md, result.json, and a self-contained dashboard.html from
  a real committed sample run (`examples/output/`, produced from EVTX-ATTACK-SAMPLES
  telemetry).
- Lint, strict type-check, and tests green (coverage ~96% against an 80% gate). The CI
  workflow runs the same gates on Ubuntu/Windows across Python 3.11/3.12. README includes the
  architecture diagram, sample output, and a dashboard screenshot.

## 15. Implementation notes

- The Sigma release and ATT&CK STIX version are pinned so detections and coverage numbers are
  reproducible and exact figures can be cited.
- Correctness and accurate coverage reporting take priority over a big detection count.
  "This ruleset covers 140 of the enterprise techniques; here are the tactics where coverage
  is thin" is more credible and more useful than implying full coverage.
- Every detection must carry its matched-fields evidence. An alert that cannot show why it
  fired is not verifiable. Each alert is tied to the specific log content that triggered it.
- The sample logs are inert records of past attacks, used to test detection. The tool never
  generates, executes, or assists attacks; it only recognizes their traces. That boundary is
  kept clean in code and in the README.
- The README leads with the background a reader needs: what detection-as-code is, why
  mapping to ATT&CK matters, why coverage reporting matters, then the diagram and the
  sample run.
