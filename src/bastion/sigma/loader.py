"""Load Sigma YAML rule files into SigmaRule models.

Walks a rules tree (the cached SigmaHQ ``rules/`` directory), parses each
``.yml``/``.yaml`` file, and extracts the ATT&CK technique/tactic tags.
Files that fail to parse or validate are skipped with a warning so that a
broken file cannot stop the rest of the tree from loading. When a platform
is given, rules whose ``logsource.product`` names a different platform are
skipped; rules with no ``product`` are kept, and the engine's logsource
pre-filter narrows further at scan time.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, get_args

import yaml
from pydantic import ValidationError

from bastion.models import Platform, Severity, SigmaRule

logger = logging.getLogger(__name__)

_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

#: ATT&CK tactic names as they appear in tags (normalized to hyphens).
_TACTIC_NAMES = {
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}

_VALID_LEVELS = frozenset(get_args(Severity))


def load_rules(rules_dir: Path, platform: Platform | None = None) -> list[SigmaRule]:
    """Parse every Sigma rule under ``rules_dir`` (recursively).

    ``platform`` filters out rules whose ``logsource.product`` is a
    different platform, so Windows rules are never run against Linux logs.
    """
    rules: list[SigmaRule] = []
    paths = sorted(p for p in rules_dir.rglob("*") if p.suffix.lower() in (".yml", ".yaml"))
    for path in paths:
        rule = _load_rule_file(path)
        if rule is None:
            continue
        product = rule.logsource.get("product", "").lower()
        if platform is not None and product and product != platform:
            continue
        rules.append(rule)
    return rules


def _load_rule_file(path: Path) -> SigmaRule | None:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        logger.warning("%s: skipping unparseable rule file: %s", path, exc)
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("detection"), dict):
        logger.warning("%s: skipping file without a detection block", path)
        return None

    techniques, tactics = _attack_tags(doc.get("tags") or [])
    level = str(doc.get("level", "medium")).lower()
    if level not in _VALID_LEVELS:
        logger.warning("%s: unknown level %r, treating as 'medium'", path, level)
        level = "medium"
    try:
        return SigmaRule(
            id=str(doc.get("id") or path.stem),
            title=str(doc.get("title") or path.stem),
            level=level,  # type: ignore[arg-type]  # validated against _VALID_LEVELS above
            description=str(doc.get("description") or ""),
            logsource=_logsource(doc),
            detection=doc["detection"],
            attack_techniques=techniques,
            attack_tactics=tactics,
            file_path=str(path),
        )
    except ValidationError as exc:
        logger.warning("%s: skipping invalid rule: %s", path, exc)
        return None


def _logsource(doc: dict[str, Any]) -> dict[str, str]:
    logsource = doc.get("logsource")
    if not isinstance(logsource, dict):
        return {}
    return {str(key): str(value) for key, value in logsource.items() if value is not None}


def _attack_tags(tags: object) -> tuple[list[str], list[str]]:
    """Extract (techniques, tactics) from a rule's tag list.

    Technique tags look like ``attack.t1059.001``; tactic tags like
    ``attack.execution`` (older rules use underscores, e.g.
    ``attack.defense_evasion``; both forms are normalized).
    """
    techniques: list[str] = []
    tactics: list[str] = []
    if not isinstance(tags, list):
        return techniques, tactics
    for tag in tags:
        text = str(tag).strip()
        if match := _TECHNIQUE_TAG_RE.match(text):
            techniques.append(match.group(1).upper())
            continue
        if text.lower().startswith("attack."):
            candidate = text[len("attack.") :].lower().replace("_", "-")
            if candidate in _TACTIC_NAMES:
                tactics.append(candidate)
    return techniques, tactics
