# B4b: Procedure variants

Started 2026-11-13. Prepared by Claude Code for Mason Thompsen. Follows `docs/milestones/B4.md`
(tag `b4`, pushed). Baseline run: `b4-final` (`LATEST`).

## Scope (Mason, 2026-11-13)

Lever a of B4, widened: techniques where rules exist but miss their dev captures (procedure
variants).

**Guardrails:**

- **Rules:** new local rules only, never edits to upstream rules. A loosened copy of an upstream
  rule counts as an edit and is not written.
- **Logic:** behavior-level, Summiting the Pyramid level 3 or higher. A candidate that can only be
  written at level 1 or 2 is dropped with its reason. Every rule goes into
  `bench/stp-scores.csv`.
- **Development:** on dev captures only. Only the fields a rule keys on are read, and every read
  is logged (B4 hygiene rule, confirmed by Mason). Test captures stay off-limits, and the B1 gap
  appendix is not opened during rule work.
- **Tags:** each rule is tagged to the behaviour it detects, never to a parent only to match a
  coarse label.
- **Class:** new rules stay `experimental` (hunting) until they have true-positive and
  true-negative fixtures (the B2 standard: `tests/test_local_rules.py`) and benign evidence
  that contains the events they read. Benign evidence is checked per rule: the goodware must
  hold the rule's channel and EventID with the fields it reads populated. A promotion goes in
  its own commit and its own run, after the hunting-only run, so both numbers exist.
- **Reporting:** gains on the frozen 130, and separately on never-inspected expanded-set
  captures from a corpus other than the rule's dev capture. Hunting-class held-out results are
  reported beside the headline.
- **Priority:** techniques by how many held-out captures they cover.
- **Process:** benchmark one run at a time, commit per batch of rules, tag `b4b` locally, do
  not push, stop and report.

## Selection, before any rule

`scripts/b4b_candidates.py` (output `bench/b4b/candidates-dev.csv`) reads the manifest, ATT&CK,
the loaded rules and the **dev** outcomes of `b4-final`; no test outcome is read.

- **Candidate:** a labelled dev positive capture the headline misses, whose label already has an
  alerting-class rule tagged to it.
- **Miss reason:** from the capture's own outcome record.

| Miss reason | Dev captures |
|:-|-:|
| Evaluated, no match (a procedure variant: B4b material) | 171 |
| A tagged alerting rule was not evaluable (missing field: a telemetry gap, not B4b) | 43 |
| A hunting or emerging rule tagged to the label already fires (a class question, not B4b) | 19 |

The 233 rows cover 123 techniques.

**Priority** is held-out captures on the dev capture's own platform, from manifest labels only:

- **Order:** first by the count from a corpus other than the dev capture's, then by the total.
- **Columns beside it:** the exact-label count (what a specific rule could cover) and the
  frozen-130 count.
- **Why platform matters:** a Linux rule cannot hit a Windows capture, so counts across
  platforms would mislead.

**Cut line, fixed before any rule:** the first 18 techniques of the "evaluated, no match" rows,
in that order. Batch 1 is techniques 1 to 9, batch 2 is techniques 10 to 18. A technique is
dropped, with its reason, when:

- its dev capture does not show the behaviour in a field Bastion reads;
- or the only workable rule would be below STP level 3;
- or the rule would be a loosened copy of an upstream rule.

All 18 are Windows; the first Linux candidate ranks lower.

| # | Technique | Held out, other corpus | Held out, same platform | Exact label | Frozen 130 | Dev captures |
|-:|:-|-:|-:|-:|-:|-:|
| 1 | T1548.002 Bypass User Account Control | 22 | 22 | 22 | 14 | 2 |
| 2 | T1218 System Binary Proxy Execution | 17 | 29 | 9 | 11 | 2 |
| 3 | T1021 Remote Services | 15 | 22 | 4 | 7 | 2 |
| 4 | T1685 Disable or Modify Tools | 10 | 18 | 12 | 5 | 1 |
| 5 | T1059.001 PowerShell | 10 | 13 | 9 | 2 | 5 |
| 6 | T1003 OS Credential Dumping | 9 | 21 | 9 | 8 | 2 |
| 7 | T1685.001 Disable or Modify Windows Event Log | 8 | 15 | 3 | 5 | 1 |
| 8 | T1003.004 LSA Secrets | 8 | 10 | 1 | 8 | 1 |
| 9 | T1134.001 Token Impersonation/Theft | 8 | 8 | 1 | 7 | 1 |
| 10 | T1546 Event Triggered Execution | 7 | 13 | 2 | 6 | 1 |
| 11 | T1036 Masquerading | 7 | 8 | 4 | 1 | 3 |
| 12 | T1685.005 Clear Windows Event Logs | 6 | 15 | 3 | 5 | 1 |
| 13 | T1218.014 MMC | 6 | 10 | 1 | 4 | 1 |
| 14 | T1574.001 DLL | 6 | 10 | 8 | 2 | 3 |
| 15 | T1021.001 Remote Desktop Protocol | 6 | 9 | 5 | 5 | 4 |
| 16 | T1055 Process Injection | 6 | 9 | 8 | 4 | 2 |
| 17 | T1021.006 Windows Remote Management | 6 | 8 | 4 | 4 | 2 |
| 18 | T1078 Valid Accounts | 6 | 8 | 4 | 2 | 2 |

**Inspected test captures.** `scripts/b4b_inspected.py` writes `bench/b4b/inspected-test.txt`
(ids only): test captures named in the contamination log or the B1 gap appendix. That is 49
captures, 39 of them in the frozen 130. A gain on one of these is reported as not clean.

## Batches

Sections below are filled in as each batch completes.
