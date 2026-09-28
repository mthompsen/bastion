# Sigma filter documents

Environment exclusions live here as Sigma filter documents (the Sigma filters
specification's meta filter), never as edits to upstream rules. Bastion loads every
`.yml` under this directory for `bastion scan`, `bastion report` and `bastion bench run`
(override with `--filters-dir`).

A filter names the rule ids it applies to, a `logsource`, one or more selections and a
`condition`; when the condition matches an event, detections from the named rules on that
event are suppressed. Every suppression is counted and disclosed: in the CLI caveats, in
`result.json` under `filtered_detections`, and in the bench summary under
`rules.suppressed_by_filters`. A filter the matcher cannot evaluate fails open, so a broken
filter can never hide a detection.

Every filter document must carry a `justification` field stating why the exclusion is
correct, what evidence it rests on (a goodware replay, a SigmaHQ known-FPs entry), and what
recall it could cost. Adding a filter is a rule change under START_PROMPT section 6 lever 8:
re-measure recall after it and report a drop rather than hiding it.

Example:

```yaml
title: Filter Administrator account
id: 7b8b3e4a-1c2d-4e5f-9a6b-0c1d2e3f4a5b
description: The valid administrator accounts start with adm_
justification: >
    Measured on the goodware replay of 2026-09-26: every match of the two rules below on
    goodware carried an adm_ user. Recall cost: none on the labelled corpora (no capture is
    labelled with these techniques under an adm_ user).
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - 6f3e2987-db24-4c78-a860-b4f4095a7095
    selection:
        User|startswith: 'adm_'
    condition: selection
```

No filter documents ship today. The T1006 goodware volume measured in B1 turned out to be a
routing defect in Bastion (see `docs/milestones/B2.md`), not a property of the rule, so no
filter was written for it.
