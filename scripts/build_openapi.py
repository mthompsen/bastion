"""Write the API contract, docs/api/openapi.json (B6).

Usage::

    python scripts/build_openapi.py [OUT_FILE]

The document is generated from ``bastion.api.create_app`` over an empty temporary store;
``tests/test_api.py`` fails when the committed file differs from what the code serves.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from bastion.api import create_app, openapi_document
from bastion.store import Store

DEFAULT_OUT = Path(__file__).resolve().parent.parent / "docs" / "api" / "openapi.json"


def main(argv: list[str]) -> int:
    out = Path(argv[1]) if len(argv) > 1 else DEFAULT_OUT
    with tempfile.TemporaryDirectory() as tmp:
        document = openapi_document(create_app(Store(Path(tmp) / "store.sqlite3")))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(document, encoding="utf-8", newline="\n")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
