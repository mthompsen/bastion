"""Tests for the Sigma matcher across the documented condition grammar."""

from __future__ import annotations

from typing import Any

import pytest

from bastion.models import Event, FieldValue, SigmaRule
from bastion.sigma.matcher import UnsupportedRuleError, evaluate, match


def make_event(**fields: FieldValue) -> Event:
    return Event(
        platform="windows",
        source="test.evtx",
        fields=dict(fields),
        raw="raw line: " + " ".join(str(v) for v in fields.values() if v is not None),
    )


def make_rule(detection: dict[str, Any]) -> SigmaRule:
    return SigmaRule(id="test-rule", title="Test Rule", level="high", detection=detection)


PS_EVENT = make_event(
    EventID=1,
    Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgA",
    ParentImage=r"C:\Windows\System32\cmd.exe",
    User="VICTIM\\alice",
)


class TestFieldMaps:
    def test_simple_equality_and_evidence(self) -> None:
        rule = make_rule({"selection": {"EventID": 1}, "condition": "selection"})
        result = match(rule, PS_EVENT)
        assert result.matched
        assert result.matched_fields == {"EventID": "1"}

    def test_map_entries_are_anded(self) -> None:
        rule = make_rule(
            {"selection": {"EventID": 1, "User": "nosuchuser"}, "condition": "selection"}
        )
        assert not evaluate(rule, PS_EVENT)

    def test_value_list_is_ored(self) -> None:
        rule = make_rule(
            {
                "selection": {"Image|endswith": ["\\cmd.exe", "\\powershell.exe"]},
                "condition": "selection",
            }
        )
        assert evaluate(rule, PS_EVENT)

    def test_all_modifier_requires_every_value(self) -> None:
        both = {"CommandLine|contains|all": ["-nop", "-enc"]}
        one = {"CommandLine|contains|all": ["-nop", "-bypass"]}
        assert evaluate(make_rule({"s": both, "condition": "s"}), PS_EVENT)
        assert not evaluate(make_rule({"s": one, "condition": "s"}), PS_EVENT)

    def test_contains_startswith_endswith_re(self) -> None:
        rule = make_rule(
            {
                "selection": {
                    "CommandLine|contains": " -enc ",
                    "Image|startswith": "c:\\windows\\",
                    "ParentImage|endswith": "\\cmd.exe",
                    "CommandLine|re": r"-enc\s+[A-Za-z0-9+/=]+",
                },
                "condition": "selection",
            }
        )
        result = match(rule, PS_EVENT)
        assert result.matched
        assert set(result.matched_fields) == {"CommandLine", "Image", "ParentImage"}

    def test_wildcard_in_plain_value(self) -> None:
        rule = make_rule({"s": {"CommandLine": "*-w hidden*"}, "condition": "s"})
        assert evaluate(rule, PS_EVENT)

    def test_null_matches_missing_field(self) -> None:
        rule = make_rule({"s": {"NoSuchField": None}, "condition": "s"})
        result = match(rule, PS_EVENT)
        assert result.matched
        assert result.matched_fields == {"NoSuchField": "(absent)"}

    def test_missing_field_does_not_match_value(self) -> None:
        rule = make_rule({"s": {"NoSuchField": "x"}, "condition": "s"})
        assert not evaluate(rule, PS_EVENT)

    def test_list_of_maps_is_ored(self) -> None:
        rule = make_rule(
            {
                "selection": [
                    {"Image|endswith": "\\nosuch.exe"},
                    {"Image|endswith": "\\powershell.exe"},
                ],
                "condition": "selection",
            }
        )
        assert evaluate(rule, PS_EVENT)


class TestKeywords:
    def test_keyword_matches_raw_and_fields(self) -> None:
        event = make_event(message="Failed password for invalid user admin from 203.0.113.7")
        rule = make_rule(
            {"keywords": ["Failed password for invalid user"], "condition": "keywords"}
        )
        result = match(rule, event)
        assert result.matched
        assert result.matched_fields == {"keyword": "Failed password for invalid user"}

    def test_keyword_is_case_insensitive(self) -> None:
        event = make_event(message="FAILED PASSWORD for root")
        rule = make_rule({"keywords": ["failed password"], "condition": "keywords"})
        assert evaluate(rule, event)

    def test_keyword_with_wildcard(self) -> None:
        event = make_event(message="session opened for user root by (uid=0)")
        rule = make_rule({"keywords": ["session opened for user *"], "condition": "keywords"})
        assert evaluate(rule, event)

    def test_keywords_are_ored(self) -> None:
        event = make_event(message="nothing interesting")
        rule = make_rule({"keywords": ["alpha", "beta"], "condition": "keywords"})
        assert not evaluate(rule, event)


class TestConditions:
    def test_selection_and_not_filter(self) -> None:
        detection: dict[str, Any] = {
            "selection": {"Image|endswith": "\\powershell.exe"},
            "filter": {"ParentImage|endswith": "\\msbuild.exe"},
            "condition": "selection and not filter",
        }
        assert evaluate(make_rule(detection), PS_EVENT)
        filtered = make_event(
            Image=r"C:\x\powershell.exe", ParentImage=r"C:\x\msbuild.exe"
        )
        assert not evaluate(make_rule(detection), filtered)

    def test_or_and_parentheses(self) -> None:
        rule = make_rule(
            {
                "a": {"EventID": 999},
                "b": {"EventID": 1},
                "c": {"User|contains": "alice"},
                "condition": "(a or b) and c",
            }
        )
        assert evaluate(rule, PS_EVENT)

    def test_one_of_pattern(self) -> None:
        rule = make_rule(
            {
                "selection_img": {"Image|endswith": "\\powershell.exe"},
                "selection_other": {"EventID": 999},
                "condition": "1 of selection_*",
            }
        )
        assert evaluate(rule, PS_EVENT)

    def test_all_of_pattern(self) -> None:
        rule = make_rule(
            {
                "selection_img": {"Image|endswith": "\\powershell.exe"},
                "selection_other": {"EventID": 999},
                "condition": "all of selection_*",
            }
        )
        assert not evaluate(rule, PS_EVENT)

    def test_all_of_them(self) -> None:
        rule = make_rule(
            {
                "a": {"EventID": 1},
                "b": {"CommandLine|contains": "-enc"},
                "condition": "all of them",
            }
        )
        assert evaluate(rule, PS_EVENT)

    def test_one_of_them(self) -> None:
        rule = make_rule(
            {"a": {"EventID": 999}, "b": {"EventID": 1}, "condition": "1 of them"}
        )
        assert evaluate(rule, PS_EVENT)

    def test_two_of_pattern(self) -> None:
        rule = make_rule(
            {
                "s_a": {"EventID": 1},
                "s_b": {"CommandLine|contains": "-enc"},
                "s_c": {"User": "nobody"},
                "condition": "2 of s_*",
            }
        )
        assert evaluate(rule, PS_EVENT)

    def test_condition_list_is_ored(self) -> None:
        rule = make_rule(
            {"a": {"EventID": 999}, "b": {"EventID": 1}, "condition": ["a", "b"]}
        )
        assert evaluate(rule, PS_EVENT)

    def test_evidence_unions_contributing_identifiers(self) -> None:
        rule = make_rule(
            {
                "sel_img": {"Image|endswith": "\\powershell.exe"},
                "sel_cli": {"CommandLine|contains": "-enc"},
                "condition": "sel_img and sel_cli",
            }
        )
        result = match(rule, PS_EVENT)
        assert set(result.matched_fields) == {"Image", "CommandLine"}

    def test_no_match_has_no_evidence(self) -> None:
        rule = make_rule({"s": {"EventID": 999}, "condition": "s"})
        result = match(rule, PS_EVENT)
        assert not result.matched
        assert result.matched_fields == {}


class TestTransformsAndPredicates:
    def test_windash_contains(self) -> None:
        event = make_event(CommandLine="powershell.exe /nop /enc SQBFAFgA")
        rule = make_rule({"s": {"CommandLine|contains|windash": " -enc "}, "condition": "s"})
        assert evaluate(rule, event)

    def test_base64_contains(self) -> None:
        import base64 as b64

        encoded = b64.b64encode(b"http://evil.example/payload").decode()
        event = make_event(CommandLine=f"certutil -decode {encoded} out.bin")
        rule = make_rule(
            {"s": {"CommandLine|base64|contains": "http://evil.example/payload"}, "condition": "s"}
        )
        assert evaluate(rule, event)

    @pytest.mark.parametrize("prefix", ["", "X", "XY"])
    def test_base64offset_matches_any_alignment(self, prefix: str) -> None:
        import base64 as b64

        stream = b64.b64encode(f"{prefix}IEX (New-Object Net.WebClient)Z".encode()).decode()
        event = make_event(CommandLine=f"powershell -enc {stream}")
        rule = make_rule(
            {
                "s": {"CommandLine|base64offset|contains": "IEX (New-Object Net.WebClient)"},
                "condition": "s",
            }
        )
        assert evaluate(rule, event)

    def test_utf16le_base64offset(self) -> None:
        import base64 as b64

        payload = b64.b64encode("Invoke-Mimikatz".encode("utf-16-le")).decode()
        event = make_event(CommandLine=f"powershell -enc {payload}")
        rule = make_rule(
            {
                "s": {"CommandLine|utf16le|base64offset|contains": "Invoke-Mimikatz"},
                "condition": "s",
            }
        )
        assert evaluate(rule, event)

    def test_cased_contains(self) -> None:
        rule_hit = make_rule({"s": {"CommandLine|contains|cased": "-enc"}, "condition": "s"})
        rule_miss = make_rule({"s": {"CommandLine|contains|cased": "-ENC"}, "condition": "s"})
        assert evaluate(rule_hit, PS_EVENT)
        assert not evaluate(rule_miss, PS_EVENT)

    def test_cidr(self) -> None:
        event = make_event(DestinationIp="10.13.37.5")
        rule = make_rule({"s": {"DestinationIp|cidr": "10.13.37.0/24"}, "condition": "s"})
        assert evaluate(rule, event)
        miss = make_rule({"s": {"DestinationIp|cidr": "192.168.0.0/16"}, "condition": "s"})
        assert not evaluate(miss, event)

    def test_exists(self) -> None:
        present = make_rule({"s": {"CommandLine|exists": True}, "condition": "s"})
        absent = make_rule({"s": {"NoSuchField|exists": False}, "condition": "s"})
        wrong = make_rule({"s": {"NoSuchField|exists": True}, "condition": "s"})
        assert evaluate(present, PS_EVENT)
        assert evaluate(absent, PS_EVENT)
        assert not evaluate(wrong, PS_EVENT)

    def test_numeric_comparisons(self) -> None:
        event = make_event(EventID=4624)
        assert evaluate(make_rule({"s": {"EventID|gt": 4000}, "condition": "s"}), event)
        assert evaluate(make_rule({"s": {"EventID|gte": 4624}, "condition": "s"}), event)
        assert evaluate(make_rule({"s": {"EventID|lt": 5000}, "condition": "s"}), event)
        assert not evaluate(make_rule({"s": {"EventID|lte": 4623}, "condition": "s"}), event)

    def test_windash_with_all_modifier(self) -> None:
        event = make_event(CommandLine="net.exe user /add backdoor")
        rule = make_rule(
            {
                "s": {"CommandLine|contains|windash|all": [" -add", "backdoor"]},
                "condition": "s",
            }
        )
        assert evaluate(rule, event)


class TestUnsupportedGrammar:
    def test_aggregation_condition(self) -> None:
        rule = make_rule({"s": {"EventID": 1}, "condition": "s | count() > 5"})
        with pytest.raises(UnsupportedRuleError, match="aggregation"):
            evaluate(rule, PS_EVENT)

    def test_timeframe(self) -> None:
        rule = make_rule({"s": {"EventID": 1}, "timeframe": "5m", "condition": "s"})
        with pytest.raises(UnsupportedRuleError, match="timeframe"):
            evaluate(rule, PS_EVENT)

    def test_unknown_modifier(self) -> None:
        rule = make_rule({"s": {"CommandLine|fieldref": "OtherField"}, "condition": "s"})
        with pytest.raises(UnsupportedRuleError, match="modifier"):
            evaluate(rule, PS_EVENT)

    def test_two_match_modifiers(self) -> None:
        rule = make_rule({"s": {"CommandLine|contains|endswith": "x"}, "condition": "s"})
        with pytest.raises(UnsupportedRuleError, match="multiple match"):
            evaluate(rule, PS_EVENT)

    def test_utf16_without_base64(self) -> None:
        rule = make_rule({"s": {"CommandLine|utf16le|contains": "x"}, "condition": "s"})
        with pytest.raises(UnsupportedRuleError, match="base64"):
            evaluate(rule, PS_EVENT)

    def test_cased_with_non_string_predicate(self) -> None:
        rule = make_rule({"s": {"EventID|gt|cased": 1}, "condition": "s"})
        with pytest.raises(UnsupportedRuleError, match="cased"):
            evaluate(rule, PS_EVENT)

    def test_null_with_transform(self) -> None:
        rule = make_rule({"s": {"CommandLine|base64|contains": None}, "condition": "s"})
        with pytest.raises(UnsupportedRuleError, match="null"):
            evaluate(rule, PS_EVENT)

    def test_unknown_identifier_in_condition(self) -> None:
        rule = make_rule({"s": {"EventID": 1}, "condition": "s and missing"})
        with pytest.raises(UnsupportedRuleError, match="unknown identifier"):
            evaluate(rule, PS_EVENT)

    def test_quantifier_over_unknown_pattern(self) -> None:
        rule = make_rule({"s": {"EventID": 1}, "condition": "1 of nope_*"})
        with pytest.raises(UnsupportedRuleError, match="unknown identifier"):
            evaluate(rule, PS_EVENT)

    def test_missing_condition(self) -> None:
        rule = make_rule({"s": {"EventID": 1}})
        with pytest.raises(UnsupportedRuleError, match="no condition"):
            evaluate(rule, PS_EVENT)

    def test_no_identifiers(self) -> None:
        rule = make_rule({"condition": "selection"})
        with pytest.raises(UnsupportedRuleError, match="no search identifiers"):
            evaluate(rule, PS_EVENT)

    def test_unbalanced_parentheses(self) -> None:
        rule = make_rule({"s": {"EventID": 1}, "condition": "(s"})
        with pytest.raises(UnsupportedRuleError):
            evaluate(rule, PS_EVENT)

    def test_trailing_tokens(self) -> None:
        rule = make_rule({"s": {"EventID": 1}, "condition": "s s"})
        with pytest.raises(UnsupportedRuleError, match="trailing"):
            evaluate(rule, PS_EVENT)

    def test_mixed_identifier_list(self) -> None:
        rule = make_rule({"s": [{"EventID": 1}, "keyword"], "condition": "s"})
        with pytest.raises(UnsupportedRuleError, match="mixes"):
            evaluate(rule, PS_EVENT)
