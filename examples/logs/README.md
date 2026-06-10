# Sample logs

Small, inert log samples used in the README walkthrough. They are *records of*
attack-like activity for detection testing — plain text/event data, nothing
executable.

- `auth_sample.log` — synthetic Linux `auth.log` excerpt (hand-written for this
  project): an SSH brute-force pattern, an accepted login, and a suspicious
  `sudo` read of `/etc/shadow`.
- Windows EVTX samples (from the public
  [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
  corpus, with attribution) are added in Phase 5 alongside the committed
  sample report run.
