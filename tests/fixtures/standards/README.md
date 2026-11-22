# Standards test fixtures (B5)

Small excerpts of pinned public standards data, kept so the B5 tests run offline. Versions
are the pins in `src/bastion/data/PINS.toml`. `scripts/build_standards_fixtures.py`
rebuilds the schema files.

| File | Source | License |
|:-|:-|:-|
| `ocsf-1.9.0/*.schema.json.gz` | OCSF schema 1.9.0, JSON Schema of each class with the `host` profile, from `https://schema.ocsf.io/schema/1.9.0/classes/<class>?profiles=host` (retrieved 2026-11-22) | Apache-2.0, OCSF project |
| `ecs-9.5.0-fields.json.gz` | Elastic Common Schema v9.5.0, `generated/ecs/ecs_flat.yml`, reduced to field names and types and the `event.*` categorization allowed values | Apache-2.0, Elasticsearch B.V. |
| `d3fend-1.6.0-mappings-excerpt.csv`, `d3fend-1.6.0-techniques-excerpt.csv` | Four rows of MITRE D3FEND 1.6.0 `d3fend-full-mappings.csv` and the matching rows of `d3fend.csv` | MIT, MITRE D3FEND (terms of use at d3fend.mitre.org) |
| `ctid-800-53-attack-16.1-excerpt.json` | Five mapping objects and the metadata of CTID Mappings Explorer `nist_800_53-rev5_attack-16.1-enterprise.json` at `69c2e8e0` | Apache-2.0, MITRE Engenuity CTID |
| `car-excerpt/analytics/*.yaml` | Two analytics of MITRE CAR at `1b922fe1` | Apache-2.0, MITRE |
| `dettect-*.yaml` | Written for these tests in the DeTT&CT 2.2.0 file formats; no DeTT&CT content copied | Bastion |
