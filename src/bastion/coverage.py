"""ATT&CK coverage of the loaded ruleset.

Coverage is computed against the full enterprise technique list from the
STIX bundle, not just the techniques the ruleset happens to mention. Every
technique gets a CoverageEntry whether covered or not, so uncovered
techniques appear in the output alongside covered ones. Technique tags
that don't resolve against ATT&CK (deprecated or unknown ids) are reported
separately and excluded from the coverage counts.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

from bastion.models import CoverageEntry, SigmaRule, TechniqueRef


@dataclass
class CoverageSummary:
    """Aggregated coverage statistics for reporting."""

    entries: list[CoverageEntry] = field(default_factory=list)
    covered_count: int = 0
    total_count: int = 0
    #: tactic name -> (covered techniques, total techniques)
    tactic_totals: dict[str, tuple[int, int]] = field(default_factory=dict)
    #: technique ids tagged by rules but unknown to ATT&CK (deprecated, typos)
    unknown_technique_ids: list[str] = field(default_factory=list)


def compute_coverage(
    rules: Sequence[SigmaRule], attack_lookup: dict[str, TechniqueRef]
) -> list[CoverageEntry]:
    """One entry per enterprise technique: how many loaded rules tag it."""
    counts = Counter(
        technique_id.upper() for rule in rules for technique_id in rule.attack_techniques
    )
    return [
        CoverageEntry(
            technique=technique,
            rule_count=counts.get(technique_id, 0),
            covered=counts.get(technique_id, 0) > 0,
        )
        for technique_id, technique in sorted(attack_lookup.items())
    ]


def summarize_coverage(
    rules: Sequence[SigmaRule], attack_lookup: dict[str, TechniqueRef]
) -> CoverageSummary:
    """Coverage entries plus the aggregate numbers reports lead with."""
    entries = compute_coverage(rules, attack_lookup)
    covered = sum(1 for entry in entries if entry.covered)

    tactic_covered: Counter[str] = Counter()
    tactic_total: Counter[str] = Counter()
    for entry in entries:
        for tactic in entry.technique.tactics:
            tactic_total[tactic] += 1
            if entry.covered:
                tactic_covered[tactic] += 1
    tactic_totals = {
        tactic: (tactic_covered.get(tactic, 0), total)
        for tactic, total in sorted(tactic_total.items())
    }

    tagged = {
        technique_id.upper() for rule in rules for technique_id in rule.attack_techniques
    }
    unknown = sorted(tagged - set(attack_lookup))

    return CoverageSummary(
        entries=entries,
        covered_count=covered,
        total_count=len(entries),
        tactic_totals=tactic_totals,
        unknown_technique_ids=unknown,
    )
