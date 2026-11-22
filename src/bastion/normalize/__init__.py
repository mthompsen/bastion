"""Normalized views of an :class:`~bastion.models.Event` (START_PROMPT section 8, item 4).

Each view is a pure function of one event: it reads the event's fields and never changes
them, so no view can change what a rule matches. Fields a view has no place for are kept
(OCSF ``unmapped``, ECS ``bastion.unmapped``) together with the raw record, so a view is
never silently lossy.
"""

from bastion.normalize.ecs import ECS_VERSION, to_ecs
from bastion.normalize.ocsf import OCSF_VERSION, detection_finding, to_ocsf

__all__ = ["ECS_VERSION", "OCSF_VERSION", "detection_finding", "to_ecs", "to_ocsf"]
