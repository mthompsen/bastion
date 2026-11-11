# Superseded

This run is kept for the record and is not a baseline. Do not compare against it.

- It re-summarized the `b1-baseline` outcomes (run key `eval 1ffd3c6819ba`), so every
  detection in it comes from the engine before the category routing fix (`0421b02`). It still
  shows the 63,482 Raw Disk Access alerts on goodware that the fix removes.
- It promoted all 8 local rules to `test`. Mason's decision B1-5 promoted only the 2 Windows
  rules (`f2081bb`).

Superseded by `b2-postfix`, the first run after the routing fix. See `docs/milestones/B2.md`
sections 1 to 3.
