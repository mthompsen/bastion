"""Rebuild the schema fixtures in tests/fixtures/standards (B5).

Usage::

    python scripts/build_standards_fixtures.py OUT_DIR

Downloads, at the pinned versions in src/bastion/data/PINS.toml:

- the OCSF 1.9.0 JSON Schema of each class Bastion emits, with the ``host`` profile
  applied, from the OCSF schema server (``https://schema.ocsf.io/schema/1.9.0/classes/<class>?profiles=host``);
- ECS 9.5.0 ``generated/ecs/ecs_flat.yml``, reduced to field names and types plus the
  allowed values of ``event.kind``, ``event.category`` (with expected types), ``event.type``
  and ``event.outcome``.

Each is written gzip compressed. The schema server is slow (about a minute per class).
"""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

import httpx
import yaml

OCSF_CLASSES = {
    "base_event": "base_event",
    "process_activity": "process_activity",
    "network_activity": "network_activity",
    "authentication": "authentication",
    "file_activity": "file_activity",
    "registry_key_activity": "win/registry_key_activity",
    "registry_value_activity": "win/registry_value_activity",
    "detection_finding": "detection_finding",
}
OCSF_URL = "https://schema.ocsf.io/schema/1.9.0/classes/{path}?profiles=host"
ECS_URL = "https://raw.githubusercontent.com/elastic/ecs/v9.5.0/generated/ecs/ecs_flat.yml"


def _write(path: Path, payload: object) -> None:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    path.write_bytes(gzip.compress(text.encode("utf-8"), mtime=0))


def main(out: Path) -> None:
    ocsf_dir = out / "ocsf-1.9.0"
    ocsf_dir.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=300, follow_redirects=True) as client:
        for name, path in OCSF_CLASSES.items():
            response = client.get(OCSF_URL.format(path=path))
            response.raise_for_status()
            _write(ocsf_dir / f"{name}.schema.json.gz", response.json())
        flat = yaml.safe_load(client.get(ECS_URL).raise_for_status().text)
    allowed: dict[str, object] = {}
    for key in ("event.kind", "event.type", "event.outcome"):
        allowed[key] = [item["name"] for item in flat[key]["allowed_values"]]
    allowed["event.category"] = {
        item["name"]: item.get("expected_event_types", [])
        for item in flat["event.category"]["allowed_values"]
    }
    fields = {name: spec["type"] for name, spec in flat.items()}
    _write(
        out / "ecs-9.5.0-fields.json.gz", {"version": "9.5.0", "fields": fields, "allowed": allowed}
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]))
