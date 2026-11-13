"""List test captures that were ever inspected (B4b): ids only, never the surrounding text.

A test capture counts as inspected when the contamination log or the B1 gap appendix names
it. A capture id is matched when its path below the corpus directory, or its final file or
directory name for evtx_attack_samples, appears in either document. Only the matched ids are
written, so the documents' contents (which pair captures with fired rules) are not printed.

usage: python scripts/b4b_inspected.py <out.txt>
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path


def main(out: Path) -> None:
    repo = Path.cwd()
    text = "\n".join(
        (repo / doc).read_text(encoding="utf-8")
        for doc in ("docs/bench/contamination-log.md", "docs/bench/b1-gap-appendix.md")
    )
    manifest = tomllib.loads((repo / "bench" / "manifest.toml").read_text(encoding="utf-8"))
    inspected = []
    for entry in manifest["capture"]:
        if entry["split"] != "test":
            continue
        cid = entry["id"]
        parts = cid.split("/")
        keys = {"/".join(parts[1:])}
        if entry["corpus"] == "evtx_attack_samples":
            keys.add(parts[-1])
        else:
            keys.add("/".join(parts[1:3]))  # technique/dataset, as the log names attack_data
        if any(key and key in text for key in keys):
            inspected.append(cid)
    out.write_text("\n".join(sorted(inspected)) + "\n", encoding="utf-8")
    print(f"{len(inspected)} inspected test captures -> {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
