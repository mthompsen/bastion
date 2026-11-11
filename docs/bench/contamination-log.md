# Contamination log

Policy (START_PROMPT section 3, rule 5). Rules and tuning are developed against the dev split
only. Headline numbers come from the held-out test split. Nobody tunes on test data. When a
test-split failure has to be inspected to diagnose a bug in the engine (not in a rule), the
inspection is logged here with the capture, what was looked at, and what changed as a result.
An entry is not a violation; an uninspected look is.

The split itself is recorded in `bench/manifest.toml` (seed 20260926, stratified by primary
technique, single-capture techniques go to test, Citadel own-lab captures are dev only).

| Date | Who | Capture(s) looked at | Why | What changed |
|:-|:-|:-|:-|:-|
| 2026-09-26 | B1 session | Held-out split, every labelled capture, aggregate view only (`gap_analysis.py`: label vs fired rule tags) | Diagnose the gap between detection rate and any-alert rate for the B1 report, at Mason's request | No rule, tag, label or engine change. Findings recorded in `docs/milestones/B1.md` section 4 and `docs/tag-disputes.md` |
| 2026-09-26 | B1 session | Held-out split, run once for the baseline (`bench/results/b1-baseline`) | First honest baseline on the unchanged engine | Nothing could be tuned: B1 changes no detection logic |
| 2026-11-10 | B2 session, lever a | All 65 attack_data auditd captures, test and dev, at the record-format level only: line counts, whether each line parses, record types, and fields present per event (`parse_completeness.py`, outside the repo). No rule outcome was looked at | Lever a's goal is that these captures parse completely, which can only be checked on every capture. The format defects (interpreted `ausearch -i` records, the `\x1d` enriched split, values with spaces) were first seen in B1's held-out no-alert analysis | Parser and normalizer only (`ingest/auditd.py`, `bench/corpora/attack_data.py`). No rule, tag, label or alias was added; `proctitle` was deliberately not aliased to `CommandLine` (a B3 field-mapping decision) |
| 2026-11-10 | B2 session | Goodware replay only (`win2022-evtx`), the Raw Disk Access rule's Event ID 9 matches | Diagnose the T1006 goodware volume (decision B1-3) | Category routing fix `0421b02`; benign data, not the held-out split |
| 2026-11-11 | B2 session, after all lever runs | Held-out split, capture-level outcome flips between consecutive runs (`compare_runs.py`, outside the repo), the held-out "not evaluable" example list in `b2-after-d` and `b2-after-e`, and the per-rule goodware and own-lab background breakdowns | Write the per-lever before and after tables and attribute each change, as the B2 report requires; looked at only after every lever was committed and benchmarked | No rule, tag, label, alias or engine change. Findings F1 to F3 in `docs/milestones/B2.md` section 9 are left for B3 |
| 2026-11-11 | B2 session | Own-lab benign background `chain-2026-09-19` and the r2026-07-01 regression sample `d4f1a2b3` (not held out), event by event for one rule each | Explain the "System Shutdown/Reboot - Linux" change in lever a and the one lever e regression failure | None; recorded as findings F1 and F3 |
