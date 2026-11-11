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

#: ATT&CK platform names a host-log scanner can observe.
HOST_PLATFORMS = frozenset({"windows", "linux"})

#: ATT&CK log source names Bastion can actually read: any Windows event
#: log channel (EVTX ingestion carries whatever the file contains), Linux
#: auditd records, and plain Linux syslog/auth/journald text.
_READABLE_PREFIXES = ("wineventlog:", "auditd:")
_READABLE_NAMES = frozenset({"linux:syslog"})


def telemetry_readable(technique: TechniqueRef) -> bool:
    """Do any of ATT&CK's detection strategies for this technique rely on a
    log source Bastion ingests?

    Techniques without detection-strategy metadata count as readable, so
    the writable-gap count never understates the work remaining.
    """
    if not technique.log_sources:
        return True
    return any(
        source.lower().startswith(_READABLE_PREFIXES) or source.lower() in _READABLE_NAMES
        for source in technique.log_sources
    )


def host_relevant(technique: TechniqueRef) -> bool:
    """Can this technique, per ATT&CK's platform metadata, occur on a
    Windows or Linux host at all?

    Techniques whose platforms are exclusively cloud control planes,
    identity providers, network devices, ESXi, or pre-compromise (PRE)
    leave no trace in host logs, so an uncovered one is a telemetry
    limitation rather than a missing rule. Techniques without platform
    metadata are treated as host-relevant so the gap count never
    understates the work remaining.
    """
    if not technique.platforms:
        return True
    return any(platform.lower() in HOST_PLATFORMS for platform in technique.platforms)


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
    #: uncovered techniques observable in the telemetry Bastion reads
    uncovered_gap_count: int = 0
    #: uncovered host techniques whose detection needs other telemetry
    uncovered_beyond_telemetry_count: int = 0
    #: uncovered techniques with no Windows/Linux component in ATT&CK
    uncovered_beyond_host_count: int = 0


def compute_coverage(
    rules: Sequence[SigmaRule], attack_lookup: dict[str, TechniqueRef]
) -> list[CoverageEntry]:
    """One entry per enterprise technique: how many loaded rules tag it."""
    counts = Counter(
        technique_id.upper() for rule in rules for technique_id in rule.technique_ids()
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
    uncovered_entries = [entry for entry in entries if not entry.covered]
    on_host = [entry for entry in uncovered_entries if host_relevant(entry.technique)]
    writable = sum(1 for entry in on_host if telemetry_readable(entry.technique))

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
        technique_id.upper() for rule in rules for technique_id in rule.technique_ids()
    }
    unknown = sorted(tagged - set(attack_lookup))

    return CoverageSummary(
        entries=entries,
        covered_count=covered,
        total_count=len(entries),
        tactic_totals=tactic_totals,
        unknown_technique_ids=unknown,
        uncovered_gap_count=writable,
        uncovered_beyond_telemetry_count=len(on_host) - writable,
        uncovered_beyond_host_count=len(uncovered_entries) - len(on_host),
    )
