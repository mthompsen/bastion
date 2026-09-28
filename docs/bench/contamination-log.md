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
