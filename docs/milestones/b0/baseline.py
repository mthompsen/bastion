"""B0 baseline: not-evaluable inventory and claimed coverage under section 4 definitions.

Read-only. Loads the cached SigmaHQ tree plus the local pack, statically checks each rule
against the matcher's grammar, reads each rule's status, and computes coverage variants.
Usage: python b0_baseline.py REPO_ROOT OUT_JSON [--auditd]
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from bastion.attack import load_attack_data
from bastion.coverage import summarize_coverage
from bastion.sigma import matcher
from bastion.sigma.loader import load_rules
from bastion.sigma.matcher import UnsupportedRuleError

root = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2])
auditd = "--auditd" in sys.argv
RULES = root / "data/sigma/rules"
LOCAL = root / "rules"
ATTACK = root / "data/attack/enterprise-attack.json"

HUNTING_STATUS = {"experimental", "unsupported", "deprecated"}
# Linux logsources Bastion can read from text logs today (auth.log / syslog family).
LINUX_TEXT_SERVICES = {
    "auth",
    "sshd",
    "sudo",
    "syslog",
    "cron",
    "pam",
    "su",
    "vsftpd",
    "guacamole",
    "modsecurity",
    "clamav",
}
# Linux categories that need auditd / Sysmon for Linux rather than syslog text.
LINUX_AUDIT_CATEGORIES = {
    "process_creation",
    "network_connection",
    "file_event",
    "file_delete",
    "file_rename",
    "file_change",
    "file_access",
}


def check_map(m: dict) -> None:
    for k, v in m.items():
        spec = matcher._parse_field_spec(str(k))
        vals = v if isinstance(v, list) else [v]
        if spec.has_transforms and any(x is None for x in vals):
            raise UnsupportedRuleError("null values cannot be combined with value transforms")
        if spec.predicate == "re":
            for x in vals:
                try:
                    re.compile(str(x))
                except re.error as exc:
                    raise UnsupportedRuleError(f"regex does not compile: {exc}") from exc


def check_identifier(val: object) -> None:
    if isinstance(val, dict):
        check_map(val)
    elif isinstance(val, list):
        if val and all(isinstance(i, dict) for i in val):
            for i in val:
                check_map(i)
        elif any(isinstance(i, (dict, list)) for i in val):
            raise UnsupportedRuleError("identifier mixes maps and scalars")
    elif isinstance(val, (str, int, float)):
        pass
    else:
        raise UnsupportedRuleError(f"unsupported identifier shape: {type(val).__name__}")


def classify(msg: str) -> str:
    m = re.search(r"unsupported modifier '([^']+)'", msg)
    if m:
        return f"modifier:{m.group(1).lower()}"
    keys = (
        "multiple encodings",
        "multiple base64",
        "multiple match modifiers",
        "utf16 encodings require",
        "cased' only applies",
        "value transforms require",
        "identifier mixes",
        "unsupported identifier shape",
        "null values cannot",
        "regex does not compile",
        "unknown identifier",
        "unbalanced",
        "unexpected token",
        "trailing tokens",
        "expected 'of'",
    )
    for key in keys:
        if key in msg:
            return "structure:" + key.replace("'", "").replace(" ", "-")
    return "other:" + msg[:40]


def evaluability(rule) -> tuple[str, str] | None:
    det = rule.detection
    if "timeframe" in det:
        return ("aggregation:timeframe", "timeframe key present")
    cond = det.get("condition")
    if cond is None:
        return ("structure:no-condition", "")
    conds = cond if isinstance(cond, list) else [cond]
    idents = {k: v for k, v in det.items() if k not in matcher._RESERVED_KEYS}
    if not idents:
        return ("structure:no-identifiers", "")
    for c in conds:
        c = str(c)
        if "|" in c:
            agg = c.split("|", 1)[1].strip()
            return ("aggregation:" + re.split(r"[ (]", agg, maxsplit=1)[0], c)
        try:
            matcher._eval_condition(c, list(idents), lambda n: True)
        except UnsupportedRuleError as exc:
            return (classify(str(exc)), str(exc))
    for val in idents.values():
        try:
            check_identifier(val)
        except UnsupportedRuleError as exc:
            return (classify(str(exc)), str(exc))
    return None


def read_status(path: str) -> str:
    try:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return str((doc or {}).get("status") or "missing").lower()
    except Exception:
        return "unreadable"


def feasible(rule) -> bool:
    """Can a telemetry source Bastion reads satisfy this rule's logsource? (B0 estimate)"""
    ls = {k.lower(): str(v).lower() for k, v in rule.logsource.items()}
    product = ls.get("product", "")
    category = ls.get("category", "")
    service = ls.get("service", "")
    if product == "windows":
        return True  # EVTX ingestion reads any channel the file carries
    if product == "linux":
        if category in LINUX_AUDIT_CATEGORIES or service == "auditd":
            return auditd
        return service in LINUX_TEXT_SERVICES or (category == "" and service == "")
    return False  # cloud, macOS, network, application, category-only (proxy, dns, webserver ...)


def on_platform(name: str) -> int:
    """How many enterprise techniques ATT&CK documents on this platform."""
    return sum(1 for t in techs.values() if name in {p.lower() for p in t.platforms})


attack = load_attack_data(ATTACK)
techs = attack.techniques
upstream = load_rules(RULES)
local = load_rules(LOCAL)
rules = upstream + local


def key(r) -> str:
    return r.id + r.file_path


info = {}
for r in upstream:
    info[key(r)] = ("sigmahq", read_status(r.file_path), evaluability(r))
for r in local:
    info[key(r)] = ("local", read_status(r.file_path), evaluability(r))

statuses = Counter(v[1] for v in info.values())
noneval = [(r, info[key(r)][2]) for r in rules if info[key(r)][2]]
noneval_by_reason = Counter(reason[0] for _, reason in noneval)
noneval_examples = defaultdict(list)
for r, reason in noneval:
    if len(noneval_examples[reason[0]]) < 3:
        noneval_examples[reason[0]].append(f"{Path(r.file_path).name}: {reason[1][:90]}")
noneval_tagged_techs = sorted({t.upper() for r, _ in noneval for t in r.attack_techniques})
products = Counter(r.logsource.get("product", "(none)").lower() for r in rules)
top_dirs = Counter(
    Path(r.file_path).relative_to(RULES).parts[0] if r.file_path.startswith(str(RULES)) else "local"
    for r in rules
)
levels = Counter(r.level for r in rules)
feasible_flags = {key(r): feasible(r) for r in rules}
prod_feasible = Counter(
    (r.logsource.get("product", "(none)").lower(), feasible_flags[key(r)]) for r in rules
)
linux_by_cat = Counter(
    (r.logsource.get("category", "") or "service:" + r.logsource.get("service", ""))
    for r in rules
    if r.logsource.get("product", "").lower() == "linux"
)


def is_hunting(r) -> bool:
    return info[key(r)][1] in HUNTING_STATUS


def cov(subset, platform: str | None = None) -> dict:
    """Coverage of `subset` rules against the full matrix or one platform's techniques."""
    denom = {
        tid: t
        for tid, t in techs.items()
        if platform is None or platform in {p.lower() for p in t.platforms}
    }
    if platform:
        subset = [r for r in subset if r.logsource.get("product", "").lower() in {platform, ""}]
    s = summarize_coverage(subset, denom)
    return {
        "rules": len(subset),
        "covered": s.covered_count,
        "total": s.total_count,
        "gap_writable": s.uncovered_gap_count,
        "gap_telemetry": s.uncovered_beyond_telemetry_count,
        "gap_beyond_host": s.uncovered_beyond_host_count,
        "unknown_tags": s.unknown_technique_ids,
    }


ok = [r for r in rules if not info[key(r)][2]]
claimed_rules = [r for r in ok if not is_hunting(r)]
feasible_rules = [r for r in claimed_rules if feasible_flags[key(r)]]
hunting_rules = [r for r in ok if is_hunting(r)]
windows_only_scan = [r for r in rules if r.logsource.get("product", "").lower() in {"windows", ""}]

result = {
    "auditd_readable": auditd,
    "attack_version": attack.version,
    "technique_total": len(techs),
    "technique_windows": on_platform("windows"),
    "technique_linux": on_platform("linux"),
    "rules_loaded": {"sigmahq": len(upstream), "local": len(local), "total": len(rules)},
    "rules_by_top_dir": dict(top_dirs.most_common()),
    "rules_by_product": dict(products.most_common(25)),
    "rules_by_level": dict(levels),
    "rules_by_status": dict(statuses.most_common()),
    "linux_rules_by_category_or_service": dict(linux_by_cat.most_common()),
    "rules_feasible_by_product": {
        f"{p}|{'feasible' if f else 'not'}": n for (p, f), n in prod_feasible.most_common()
    },
    "not_evaluable": {
        "count": len(noneval),
        "by_reason": dict(noneval_by_reason.most_common()),
        "examples": dict(noneval_examples),
        "techniques_tagged": noneval_tagged_techs,
    },
    "coverage": {
        "as_reported_today_all_rules": cov(rules),
        "as_reported_today_windows_scan_ruleset": cov(windows_only_scan),
        "claimed_sec4_evaluable_nonhunting": cov(claimed_rules),
        "claimed_sec4_windows_subset": cov(claimed_rules, "windows"),
        "claimed_sec4_linux_subset": cov(claimed_rules, "linux"),
        "telemetry_feasible_estimate": cov(feasible_rules),
        "telemetry_feasible_windows_subset": cov(feasible_rules, "windows"),
        "telemetry_feasible_linux_subset": cov(feasible_rules, "linux"),
        "hunting_class_only": cov(hunting_rules),
        "evaluable_incl_hunting": cov(ok),
    },
}
ok_tags = {t.upper() for r in ok for t in r.attack_techniques}
result["not_evaluable"]["techniques_tagged_only_by_them"] = sorted(
    t for t in noneval_tagged_techs if t not in ok_tags
)
claimed_tags = {t.upper() for r in claimed_rules for t in r.attack_techniques}
hunting_tags = {t.upper() for r in hunting_rules for t in r.attack_techniques}
hunting_only = sorted(hunting_tags - claimed_tags)
result["hunting_only_techniques_count"] = len(hunting_only)
result["hunting_only_techniques_in_attack"] = len([t for t in hunting_only if t in techs])
result["hunting_only_techniques"] = hunting_only
out.write_text(json.dumps(result, indent=2), encoding="utf-8")
print(json.dumps({k: v for k, v in result.items() if k != "hunting_only_techniques"}, indent=2))
