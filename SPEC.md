# Bastion — Sigma/ATT&CK Detection Engine

> **Design & build specification.** Source of truth for building the tool. Built phase by phase. As with its sibling project, the repository itself is the deliverable, and engineering hygiene is part of the point. The defensive complement to a compliance scanner: that tool asks *is this host configured to the controls?*; this one asks *can I detect an adversary already operating inside?*

*(Working codename "Bastion" — a fortified projection from which defenders watch the approaches. Rename freely; the CLI below assumes `bastion`.)*

---

## 1. One-line description

A command-line detection engine that ingests host security logs (Windows Sysmon/EVTX or Linux auth/syslog, auto-selected by host OS with manual override), evaluates them against the public **Sigma** detection ruleset, maps every matching rule to its **MITRE ATT&CK** technique, and produces an alert report plus an honest **coverage map** of which ATT&CK techniques the loaded ruleset can and cannot detect — emitting CLI output, machine-readable JSON, and a static HTML dashboard.

## 2. Goals

- Demonstrate detection engineering end to end: ingest telemetry → evaluate detection logic → enrich with adversary-technique context → report.
- Work against the *real* ecosystem standards (the actual SigmaHQ ruleset and official MITRE ATT&CK data), not reinvented toy formats.
- Be honest about coverage: state plainly which ATT&CK techniques are covered by the loaded rules and which are blind spots, rather than implying total visibility.
- Be self-contained, fully **defensive** (it reads logs you own and detects known-bad patterns — it never attacks anything), deterministic, and offline after a one-time data fetch.

## 3. Non-goals

- Not a live agent, not a real-time stream processor, not a SIEM. It analyzes log files/batches, not live event streams.
- Not an attack tool, payload generator, or C2. It consumes telemetry of attacks that already happened; it never produces malicious activity.
- Not a Sigma *authoring* tool and not a full Sigma backend. It implements a correct evaluator for a defined subset of Sigma's detection grammar — breadth of grammar is a stretch goal; correctness and the ATT&CK coverage honesty are the core.
- Not a rewrite of `sigma-cli`/pySigma into a SIEM query — this tool *matches rules against logs directly*, in-process.

## 4. Domain background (so the implementation is accurate)

- **Sigma** — an open, vendor-neutral YAML format for describing log-based detections. A rule has a `logsource` (category/product/service it applies to), a `detection` block of named search-identifiers combined by a `condition` expression, plus metadata including `tags`. Detection identifiers are maps of field→value(s) with optional value-modifiers (`contains`, `startswith`, `endswith`, `re`, `all`, etc.). Maintained at **SigmaHQ/sigma** on GitHub (thousands of rules).
- **Sigma → ATT&CK linkage** — Sigma rules carry `tags` like `attack.t1059.001` (a technique/sub-technique id) and tactic tags like `attack.execution`. This tag is the authoritative, rule-author-provided mapping; the tool reads it rather than guessing. This is the detection-world analog of a control mapping.
- **MITRE ATT&CK** — the public knowledge base of adversary tactics (the "why", e.g. Execution, Persistence) and techniques (the "how", e.g. T1059 Command and Scripting Interpreter, T1059.001 PowerShell). Published as machine-readable **STIX 2.1 JSON** (the `enterprise-attack.json` bundle in **mitre-attack/attack-stix-data**) and via the MITRE CTI repo. Each technique has an id, name, tactic(s), and description.
- **Sysmon / EVTX** — Windows System Monitor writes rich security telemetry (process creation with command lines = Event ID 1, network connections = 3, image loads = 7, etc.) to the Windows event log. Sample malicious telemetry is available as `.evtx` files in public corpora (e.g. **sbousseaden/EVTX-ATTACK-SAMPLES**) and as the logs bundled with Sigma's own tests.
- **Linux auth/syslog** — `/var/log/auth.log`, `/var/log/syslog`, journald exports: text logs of authentication, sudo, ssh, cron, service activity.

## 5. Data sources

Two external datasets, both fetched once and cached locally so the core flow runs offline. Write `scripts/fetch_data.py` (shared with a `bastion fetch` CLI command) to download and cache them; **verify exact paths/filenames against the live repos at build time** rather than trusting hardcoded URLs.

1. **Sigma ruleset** — clone/download a pinned release of **SigmaHQ/sigma** (the `rules/` tree). Cache under `data/sigma/`. Pin to a specific release tag for reproducibility.
2. **ATT&CK STIX bundle** — download `enterprise-attack.json` from **mitre-attack/attack-stix-data**. Cache under `data/attack/`. Used to resolve technique ids → names/tactics/descriptions for enrichment.

For sample logs used in the worked example and tests, bundle a small set of **safe, public attack-telemetry samples** (a handful of EVTX-ATTACK-SAMPLES `.evtx` files and/or Sigma's test logs) under `examples/logs/`, clearly attributed. These contain *records of* attacks for detection testing — they are inert log data, not live malware.

## 6. Users & primary use cases

1. *"Here's a batch of logs from a host — what known-bad activity is in them?"* → `bastion scan LOGFILE`.
2. *"What can my current ruleset actually detect?"* → `bastion coverage`.
3. *"Give me one report and a dashboard of everything found and everything I'm blind to."* → `bastion report LOGFILE -o out/`.

## 7. Tech stack

- **Python 3.11+**
- **Typer** — CLI
- **Pydantic v2** — data models / validation
- **PyYAML** — parsing Sigma rule files
- **Jinja2** — HTML dashboard + report templating
- **python-evtx** (or `evtx`) — parsing Windows `.evtx` files
- **httpx** — fetching Sigma/ATT&CK data
- **rich** — CLI tables/colour
- **pytest** + **pytest-cov**, **ruff**, **mypy --strict** — must pass clean
- Packaging via `pyproject.toml`; `pip install -e .` exposes the `bastion` entry point.
- *(Stretch)* `stix2` for richer ATT&CK parsing; otherwise parse the STIX JSON directly.

Keep dependencies minimal. No database. No network in the core flow after the one-time fetch. **Builds and runs fully on Windows** (it parses log files; it does not scan a host), so no WSL needed.

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
│   └── output/                   # committed real sample run (report + dashboard + json)
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

**Enums / aliases**
- `Platform = Literal["windows", "linux"]`
- `Severity = Literal["informational", "low", "medium", "high", "critical"]`  (Sigma `level`)

**`Event`** — a single normalized log record (the common shape both ingesters emit)
- `timestamp: datetime | None`
- `platform: Platform`
- `source: str` (e.g. "sysmon", "auth.log")
- `fields: dict[str, str | int | None]` — normalized field map (e.g. `Image`, `CommandLine`, `User`)
- `raw: str` — original record text/representation (for evidence)

**`SigmaRule`** — parsed from a Sigma YAML file
- `id: str`, `title: str`, `level: Severity`, `description: str`
- `logsource: dict[str, str]` (category/product/service)
- `detection: dict` (the raw detection block: identifiers + `condition`)
- `attack_techniques: list[str]` (parsed from `tags`, e.g. `["T1059.001"]`)
- `attack_tactics: list[str]`
- `file_path: str`

**`Detection`** — one rule firing on one event
- `rule_id: str`, `rule_title: str`, `level: Severity`
- `event: Event`
- `matched_fields: dict[str, str]` — which field/value pairs triggered it (evidence)
- `techniques: list[TechniqueRef]`

**`TechniqueRef`** — enriched ATT&CK context
- `id: str` (e.g. T1059.001), `name: str`, `tactics: list[str]`

**`CoverageEntry`** — per-technique coverage status
- `technique: TechniqueRef`
- `rule_count: int` — how many loaded rules tag this technique
- `covered: bool`

**`ScanResult`** — the full output of a run
- `detections: list[Detection]`
- `events_scanned: int`, `rules_loaded: int`
- `coverage: list[CoverageEntry]`

## 10. Component specifications

### 10.1 `ingest/`
- `base.LogSource`: protocol with `parse(path) -> Iterator[Event]`. Read-only; never writes.
- `evtx.EvtxSource`: parse Windows `.evtx`, normalize common Sysmon fields (`Image`, `CommandLine`, `ParentImage`, `User`, `DestinationIp`, `EventID`, …) into `Event.fields`.
- `linux.LinuxLogSource`: parse `auth.log`/`syslog`-style lines into normalized fields (`process`, `user`, `message`, `pid`, …).
- **OS auto-selection:** a `select_source(path, platform_override)` helper picks the ingester by file type/extension and, when ambiguous, by the host OS (`platform.system()`), with an explicit `--platform` override. Default = the OS the tool is running on.
- Malformed records are skipped with a warning, never crash the parse.

### 10.2 `sigma/`
- `loader.load_rules(dir) -> list[SigmaRule]`: walk the cached Sigma `rules/` tree, parse YAML, extract `attack.tXXXX` tags into `attack_techniques`/`attack_tactics`. Skip rules whose `logsource` doesn't apply to the active platform (don't try to run Windows rules on Linux logs).
- `modifiers.py`: implement Sigma value-modifiers — at minimum `contains`, `startswith`, `endswith`, `all`, `re` (regex), and base equality (case-insensitive per Sigma spec). Each is a pure function; each has unit tests.
- `matcher.evaluate(rule, event) -> bool`: evaluate one rule's `detection` against one `Event`. Support: field maps (a field equals/contains a value or any of a list), the `selection`/`filter` identifier pattern, and `condition` expressions with `and`/`or`/`not`/`1 of them`/`all of them`. **Document explicitly which subset of the Sigma condition grammar is supported**; raise a clear, recorded error (not a crash) for unsupported constructs so coverage stays honest about what was actually evaluable.

### 10.3 `attack.py`
- `load_attack(stix_path) -> dict[str, TechniqueRef]`: parse the enterprise-attack STIX bundle into a lookup of technique id → name/tactics. Handle both techniques and sub-techniques.
- Resolve `SigmaRule.attack_techniques` ids to enriched `TechniqueRef`s; if a tag references an unknown/deprecated id, record it rather than dropping silently.

### 10.4 `engine.py`
- `scan(events, rules, attack_lookup) -> list[Detection]`: for each event, evaluate each applicable rule; on a match, build a `Detection` capturing the matched field/value pairs (evidence) and the enriched techniques.
- A rule that errors on an event is recorded as an error and skipped for that event; one bad rule never aborts the scan (sibling of the compliance tool's runner rule).
- Performance: pre-filter rules by `logsource`/platform so you're not evaluating every rule against every event.

### 10.5 `coverage.py` — the honesty core
- `compute_coverage(rules_loaded, attack_lookup) -> list[CoverageEntry]`: for the techniques represented across the loaded ruleset, count how many rules tag each; mark `covered=True` where ≥1 rule exists.
- Crucially, the report must also state **what is *not* covered**: the tool knows the full ATT&CK technique list from the STIX bundle, so it can honestly say "the loaded ruleset references N of M enterprise techniques; here are notable tactics with thin or no coverage." **Never imply total visibility.** This is the direct analog of the compliance tool's `not_assessed` rule — be loud about blind spots.

### 10.6 `report.py`
- **CLI** (`rich`): a table of detections (rule, level, technique, evidence snippet) and a coverage summary line ("X detections across Y techniques; ruleset covers Z of the enterprise matrix").
- **JSON**: full `ScanResult` serialized; also offer a SARIF-shaped option as a stretch.
- **HTML dashboard** (Jinja2, single self-contained file): detections grouped by ATT&CK tactic, severity colour-coding, a coverage view that visibly shows both covered and uncovered areas, and per-detection evidence (the matched fields + raw log line). No external network calls in the rendered page; inline CSS.

## 11. CLI specification (Typer)

```
bastion fetch                                  # download + cache Sigma rules and ATT&CK STIX
bastion scan LOGFILE [--platform windows|linux]    # detections to the terminal
bastion coverage [--platform ...]              # ATT&CK coverage map of the loaded ruleset
bastion report LOGFILE [-o OUTDIR] [--platform ...]  # full run: report.md + result.json + dashboard.html
bastion rules list [--platform ...]            # loaded rules + their ATT&CK techniques
```

Every command `--help`-documented, exits non-zero on error. `report` is the headline command and produces the committed sample artifacts.

## 12. Output artifacts

After `bastion report examples/logs/<sample> -o out/`: `report.md`, `result.json`, `dashboard.html`. The README shows a **real run against committed sample attack telemetry** (EVTX-ATTACK-SAMPLES / Sigma test logs), with `examples/output/` committed so a reviewer sees real detections and a real coverage map without running anything.

## 13. Build phases (do in order)

1. **Scaffold + models + ingest.** Repo, packaging, `models.py`, the `Event` shape, both ingesters (Linux first — simpler — then EVTX), fixture logs, tests. CLI skeleton. Green CI.
2. **ATT&CK.** `fetch_data.py` (ATT&CK half), `attack.py` STIX parsing + technique lookup + tests against a mini STIX fixture.
3. **Sigma loading + matching.** `loader.py`, `modifiers.py`, `matcher.py` with a clearly-documented supported grammar subset; extensive matcher/modifier unit tests against fixture rules+events. This is the technical heart — test it hard.
4. **Engine + coverage.** `engine.py` (rules over events → detections with evidence), `coverage.py` (the honesty layer). `scan` and `coverage` commands.
5. **Report + dashboard.** `report.py`: CLI, JSON, and the HTML dashboard. `report` end to end. Capture the committed real sample run.
6. **Polish.** README (lead with *what detection engineering is and why coverage honesty matters*, architecture diagram, the real sample run + a dashboard screenshot), docstrings, `--help`, coverage ≥80%.
7. *(Stretch)* SARIF output; more of the Sigma condition grammar; a small hand-written rule or two of your own mapped to ATT&CK; timeline view in the dashboard.

## 14. Testing & quality requirements

- pytest covers: each modifier, the matcher across condition forms, both ingesters (fixture logs), ATT&CK resolution, engine detection + evidence capture, coverage computation. Target ≥80%.
- `ruff` and `mypy --strict` clean. CI runs lint + type-check + tests with a coverage gate.
- No network in tests (mini fixtures for Sigma rules and STIX), no host access, no secrets. All tests OS-independent and offline.

## 15. Acceptance criteria

- [ ] `pip install -e .`; `bastion --help` works, all subcommands documented.
- [ ] `bastion fetch` caches the real Sigma ruleset and ATT&CK STIX bundle; the flow then runs offline.
- [ ] `bastion scan` parses a real sample log and reports detections, each with the matched fields (evidence) and resolved ATT&CK technique name.
- [ ] The matcher correctly evaluates the documented Sigma grammar subset; unsupported constructs are reported, not crashed on, and don't silently inflate coverage.
- [ ] `bastion coverage` reports both covered techniques **and** blind spots, never implying total visibility.
- [ ] One bad rule or malformed record never aborts a scan.
- [ ] `bastion report` emits report.md + result.json + a self-contained dashboard.html, from a real committed sample run.
- [ ] CI green; coverage ≥80%; README with architecture diagram, real sample output, and a dashboard screenshot.

## 16. Notes to the implementer

- Pin the Sigma release and record the ATT&CK STIX version, so detections and coverage numbers are reproducible and you can cite exact figures.
- Prefer correctness and honest coverage over a big detection count. "This ruleset covers 140 of the enterprise techniques; here are the tactics where I'm thin" is more credible and more useful than implying full coverage — the same principle that governs an honest compliance report.
- The matched-fields evidence on every detection is non-negotiable: a detection that can't show *why* it fired is just an unverifiable alert. Tie every alert to the specific log content that triggered it.
- The sample logs are inert records of past attacks, used to test detection. The tool never generates, executes, or assists attacks; it only recognizes their traces. Keep that boundary clean in code and in the README.
- Write the README for a human reviewer: what detection-as-code is, why mapping to ATT&CK matters, why honest coverage matters, then the diagram and the real run.
