"""Sigma rule loading and matching.

The supported subset of the Sigma specification is documented in
:mod:`bastion.sigma.matcher`. Anything outside it raises
:class:`~bastion.sigma.matcher.UnsupportedRuleError` so that scans stay
honest about what was actually evaluable.
"""

from bastion.sigma.loader import load_rules
from bastion.sigma.matcher import MatchResult, UnsupportedRuleError, evaluate, match

__all__ = ["MatchResult", "UnsupportedRuleError", "evaluate", "load_rules", "match"]
