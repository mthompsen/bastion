"""Local SQLite store: scans, detections, bench run records, triage state, filter documents
and tag disputes (START_PROMPT section 8 item 6; store decision B0 section 10.2).

Standard library ``sqlite3`` in WAL mode, one file per workspace, JSON in TEXT columns. The
store is a record of what Bastion produced and what the analyst decided; nothing in the
engine or the bench reads it, so it cannot change a detection:

- filter documents are recorded from the ``filters/`` directory; the engine keeps loading
  filters from that directory, never from the store;
- a tag dispute is a ledger entry; it never retags a rule;
- a bench run is recorded at summary level (``summary.json``); no capture event is stored.
"""

from bastion.store.db import (
    DISPUTE_STATUSES,
    SCHEMA_VERSION,
    STORE_ENV,
    TRIAGE_STATUSES,
    NotFoundError,
    Store,
    StoreError,
    default_store_path,
)

__all__ = [
    "DISPUTE_STATUSES",
    "SCHEMA_VERSION",
    "STORE_ENV",
    "TRIAGE_STATUSES",
    "NotFoundError",
    "Store",
    "StoreError",
    "default_store_path",
]
