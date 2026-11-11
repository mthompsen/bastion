"""Render a bench summary as Markdown. Every number carries its basis and the pins."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _rate_line(rate: Mapping[str, Any]) -> str:
    n, d = rate["numerator"], rate["denominator"]
    if d == 0:
        return f"{n} of {d} (no captures)"
    if rate.get("suppressed"):
        return f"{n} of {d} (percentage suppressed, fewer than 5 captures)"
    return f"{n} of {d} ({n / d:.1%}, 95% CI {rate['low']:.1%} to {rate['high']:.1%})"


def _rate_row(label: str, rate: Mapping[str, Any]) -> str:
    return f"| {label} | {_rate_line(rate)} | {rate['basis']} |"


def render_report(summary: Mapping[str, Any]) -> str:
    pins = summary["pins"]
    rules = summary["rules"]
    lines: list[str] = []
    add = lines.append
    add("# Bastion bench results")
    add("")
    add(
        f"Run `{summary['run']}`, Bastion {summary['bastion']['version']} at commit "
        f"`{summary['bastion']['commit']}`. Sigma `{pins['sigma']}` "
        f"(`{pins['sigma_commit'][:7]}`), "
        f"ATT&CK {pins['attack']}. Split seed {summary['seed']}. Splits evaluated: "
        f"{', '.join(summary['splits_evaluated'])}."
    )
    if summary.get("event_cap_per_capture"):
        add(f"Event cap per capture: {summary['event_cap_per_capture']} (stated on affected rows).")
    add("")
    add(
        "Every rate below is numerator of denominator with a Wilson 95% interval and its basis. "
        "Hunting class (status experimental, unsupported, deprecated, or the threat-hunting tree) "
        "never raises a headline number."
    )
    add("")
    add("## Rules")
    add("")
    add("| Loaded | Alerting class | Hunting class | Not evaluable (grammar) |")
    add("|-:|-:|-:|-:|")
    add(
        f"| {rules['loaded']} | {rules['alerting']} | {rules['hunting']} | "
        f"{rules['not_evaluable']} |"
    )
    if rules["not_evaluable_by_reason"]:
        add("")
        add(
            "Not evaluable by reason: "
            + ", ".join(f"{k} {v}" for k, v in rules["not_evaluable_by_reason"].items())
            + ". Files: "
            + ", ".join(rules["not_evaluable_files"])
            + "."
        )
    resolution = rules.get("tag_resolution")
    if resolution:
        remapped = resolution["remapped"]
        pairs = ", ".join(f"{tag} to {entry['to']}" for tag, entry in remapped.items())
        add("")
        add(
            f"Technique tags resolved through ATT&CK revoked-by: {len(remapped)} retired tags on "
            f"{resolution['rules_remapped']} rules now count as their live successor"
            + (f" ({pairs})." if pairs else ".")
        )
        excluded = {**resolution["deprecated_excluded"], **resolution["unknown_excluded"]}
        if excluded:
            add(
                "Excluded from every count (deprecated with no successor, or unknown to this "
                "ATT&CK release): "
                + ", ".join(f"{tag} ({n} rules)" for tag, n in excluded.items())
                + f". Rules left with no live tag: {resolution['rules_without_live_tag']}."
            )
    if rules["local_rules_hunting"]:
        add("")
        add(
            f"Local pack: {len(rules['local_rule_ids'])} rules, of which "
            f"{len(rules['local_rules_hunting'])} are hunting class by status."
        )
    if rules.get("filters_loaded"):
        suppressed = sum(rules.get("suppressed_by_filters", {}).values())
        add("")
        add(
            f"Filter documents loaded: {', '.join(rules['filters_loaded'])}. Detections suppressed "
            f"by them across every capture: {suppressed} (per rule in summary.json)."
        )
    add("")
    add("## Coverage (claim-by-tag, not validated detection)")
    add("")
    add("| Metric | Value | Basis |")
    add("|:-|:-|:-|")
    for name, rate in summary["coverage"].items():
        add(_rate_row(name, rate))
    gaps = summary["blind_spots_alerting_class"]
    add("")
    add(
        f"Uncovered by the alerting class: {gaps['uncovered']} techniques, of which "
        f"{gaps['beyond_host']} have no Windows or Linux component, {gaps['beyond_telemetry']} "
        f"need telemetry Bastion does not read, and {gaps['writable_gaps']} are writable gaps."
    )
    for split in ("test", "dev"):
        block = summary["rates"][split]
        add("")
        add(
            f"## Detection on labelled captures, {split} split"
            + (" (held out)" if split == "test" else " (development)")
        )
        add("")
        add("| Metric | Value | Basis |")
        add("|:-|:-|:-|")
        add(_rate_row("Detection rate (technique recall), headline", block["detection_rate"]))
        add(_rate_row("Detection rate, strict (exact tag)", block["detection_rate_strict"]))
        add(_rate_row("Any-alert rate", block["any_alert_rate"]))
        add(_rate_row("Validated coverage, headline", block["validated_coverage_over_labelled"]))
        add(
            _rate_row(
                "Validated coverage, strict (exact tag)",
                block["validated_coverage_strict_over_labelled"],
            )
        )
        add(_rate_row("Validated coverage, full matrix", block["validated_coverage_over_matrix"]))
        add("")
        add(
            f"Captures: {block['captures']}. Hits counted only through parent/sub-technique "
            f"hierarchy: {block['hierarchical_hits']}. Cross-firing: "
            f"{block['cross_firing']['cross_fired_alerts']} alerts on "
            f"{block['cross_firing']['captures_with_cross_firing']} captures from rules tagged to "
            "another technique."
        )
        if block["per_tactic"]:
            add("")
            add("| Tactic | Detection rate | Captures |")
            add("|:-|:-|-:|")
            for tactic, rate in block["per_tactic"].items():
                add(f"| {tactic} | {_rate_line(rate)} | {rate['denominator']} |")
        if block["per_technique"]:
            add("")
            add("| Technique | Detected | Captures |")
            add("|:-|-:|-:|")
            for technique, rate in block["per_technique"].items():
                add(f"| {technique} | {rate['numerator']} | {rate['denominator']} |")
        offenders = block["cross_firing"]["top_offenders"]
        if offenders:
            add("")
            add(
                "Top cross-firing rules: "
                + "; ".join(f"{o['title']} ({o['alerts']})" for o in offenders[:8])
                + "."
            )
    frozen = summary["rates"].get("test_frozen_b1")
    if frozen is not None:
        add("")
        add("## Headline sets side by side (held out)")
        add("")
        add(
            "The frozen set is the B1 test split, unchanged since B1 so B1 and B2 comparisons "
            "stay valid (sha256 of its sorted id list `"
            + frozen["capture_ids_sha256"][:12]
            + "`). The expanded test split adds captures assigned later with the same seed, "
            "before any rule ran on them."
        )
        add("")
        add("| Set | Captures | Detection, headline | Detection, strict | Any alert |")
        add("|:-|-:|:-|:-|:-|")
        for label, block in (
            ("Frozen B1 test set", frozen),
            ("Expanded test split", summary["rates"]["test"]),
        ):
            add(
                f"| {label} | {block['captures']} | {_rate_line(block['detection_rate'])} | "
                f"{_rate_line(block['detection_rate_strict'])} | "
                f"{_rate_line(block['any_alert_rate'])} |"
            )
    by_corpus = summary.get("rates_by_corpus") or {}
    for split, corpora in by_corpus.items():
        if not corpora:
            continue
        add("")
        add(f"### Per corpus, {split} split")
        add("")
        add("| Corpus | Captures | Detection, headline | Detection, strict | Any alert |")
        add("|:-|-:|:-|:-|:-|")
        for corpus, block in corpora.items():
            add(
                f"| {corpus} | {block['captures']} | {_rate_line(block['detection_rate'])} | "
                f"{_rate_line(block['detection_rate_strict'])} | "
                f"{_rate_line(block['any_alert_rate'])} |"
            )
    reg = summary["regression"]
    add("")
    add("## SigmaHQ regression suite")
    add("")
    add("| Metric | Value | Basis |")
    add("|:-|:-|:-|")
    add(_rate_row("Rule regression pass rate, headline", reg["pass_rate"]))
    add(_rate_row("Rule regression pass rate, strict", reg["pass_rate_strict"]))
    add("")
    add(
        "The headline follows SigmaHQ's own runner: a case passes with at least the expected "
        f"number of matches, and {reg['more_than_expected']} case(s) passed with more than "
        "expected (SigmaHQ warns on those). The strict rate requires exactly the expected count."
    )
    if reg["skipped_by_reason"]:
        add("")
        add(
            "Skipped by reason: "
            + "; ".join(f"{k}: {v}" for k, v in reg["skipped_by_reason"].items())
            + "."
        )
    if reg["by_logsource"]:
        add("")
        add("| Logsource | Passed | Failed |")
        add("|:-|-:|-:|")
        for key, counts in reg["by_logsource"].items():
            add(f"| {key} | {counts['passed']} | {counts['failed']} |")
    if reg["failures"]:
        add("")
        add("| Failing rule | Logsource | Expected | Actual | Events |")
        add("|:-|:-|-:|-:|-:|")
        for failure in reg["failures"][:60]:
            expected = "1 or more" if failure["expected"] is None else failure["expected"]
            add(
                f"| {failure['rule_title']} | {failure['logsource']} | {expected} | "
                f"{failure['actual']} | {failure['events']} |"
            )
        if len(reg["failures"]) > 60:
            add(f"| and {len(reg['failures']) - 60} more, see summary.json | | | | |")
    for label, key in (
        ("Benign replay, evtx-baseline goodware", "evtx_baseline"),
        ("Own-lab background outside run windows (Citadel)", "citadel_background"),
    ):
        volume = summary["benign"][key]
        add("")
        add(f"## {label}")
        add("")
        if volume["hosts"] == 0:
            add("No captures scanned.")
            continue
        rate = volume["per_host_day"]
        rate_medium = volume["per_host_day_medium_plus"]
        add(
            "| Hosts | Host-days scanned | Events | Alerts | Alerts per host-day | "
            "Medium+ per host-day | Budget | Within budget |"
        )
        add("|-:|-:|-:|-:|-:|-:|-:|:-|")
        add(
            f"| {volume['hosts']} | {volume['host_days']:.2f} | {volume['events']} | "
            f"{volume['alerts']} | {rate:.2f} | {rate_medium:.2f} | {volume['budget']} | "
            f"{'yes' if volume['within_budget'] else 'no'} |"
        )
        if volume["notes"]:
            add("")
            add("Notes: " + "; ".join(volume["notes"]) + ".")
        if volume["per_rule"]:
            add("")
            add("| Rule | Level | Alerts | Per host-day | On known-FPs list |")
            add("|:-|:-|-:|-:|:-|")
            for entry in volume["per_rule"][:25]:
                add(
                    f"| {entry['title']} | {entry['level']} | {entry['alerts']} | "
                    f"{entry['per_host_day']:.2f} | {'yes' if entry['known_fp'] else 'no'} |"
                )
    ladder = summary["ladder"]["distribution"]
    add("")
    tri = summary.get("not_evaluable")
    if tri:
        add("## Tri-state evaluation: not evaluable, never no match")
        add("")
        add(
            "A rule that did not match, and whose answer depended on a field the event's source "
            "does not carry, is counted here and never as a no match or as coverage "
            "(START_PROMPT section 3, rule 3). Grammar-unsupported rules are listed under Rules."
        )
        add("")
        kinds = ", ".join(f"{k} {v}" for k, v in tri["rule_event_pairs_by_capture_kind"].items())
        add(
            f"Rule-event pairs not evaluable: {tri['rule_event_pairs']} ({kinds}). Rules not "
            f"evaluable at least once: {tri['rules_not_evaluable_at_least_once']}, of which "
            f"{tri['alerting_rules_not_evaluable_at_least_once']} alerting class."
        )
        add("")
        add(
            f"Separately, {tri['outside_source_pairs']} rule-event pairs on "
            f"{tri['outside_source_rules']} rules were outside the rule's source: the event "
            "carries none of the fields the rule reads, because Bastion does not route that "
            "logsource yet (B3). Those are not evaluable either, and never a no match. By "
            "logsource (product/category/service): "
            + ", ".join(f"{k} {v}" for k, v in tri["outside_source_by_logsource"].items())
            + "."
        )
        add("")
        add("| Missing field (reason) | Rule-event pairs |")
        add("|:-|-:|")
        for name, pairs in tri["by_missing_field"].items():
            add(f"| {name} | {pairs} |")
        add("")
        for split, label in (("test", "held out"), ("dev", "development")):
            entry = tri["labelled"].get(split)
            if entry is not None:
                add(
                    f"Labelled captures, {label} split, not detected while an alerting rule tagged "
                    f"to the label was not evaluable on some event: "
                    f"{entry['undetected_with_tagged_rule_not_evaluable']}."
                )
        add("")
    add("## Evidence ladder (strongest evidence per enterprise technique)")
    add("")
    add("| Held-out-proven | Sample-proven | Fixture-proven | Rule-only | None |")
    add("|-:|-:|-:|-:|-:|")
    add(
        f"| {ladder['held-out-proven']} | {ladder['sample-proven']} | {ladder['fixture-proven']} "
        f"| {ladder['rule-only']} | {ladder['none']} |"
    )
    rob = summary["robustness"]
    add("")
    add("## Robustness (Summiting the Pyramid)")
    add("")
    add(
        f"{rob['scored']} of {rob['rules']} rules scored; {rob['unscored']} unscored. "
        "Scoring starts in B4."
    )
    caps = summary["captures"]
    add("")
    add("## Captures")
    add("")
    add(
        f"{caps['total']} captures evaluated: "
        + ", ".join(f"{k} {v}" for k, v in caps["by_kind"].items())
        + f". Unlabelled positive captures (scanned, in no rate): {caps['unlabelled_positive']}. "
        f"Skipped: {len(caps['skipped'])}."
    )
    if summary.get("notes"):
        add("")
        add("Notes: " + "; ".join(summary["notes"]) + ".")
    add("")
    add("Pins: " + ", ".join(f"{k} {v}" for k, v in pins.items()) + ".")
    return "\n".join(lines) + "\n"
