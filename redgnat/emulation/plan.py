"""EmulationPlan — ordered execution schedule produced by ScenarioBuilder."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from redgnat.techniques.base import Scope

if TYPE_CHECKING:
    from redgnat.techniques.base import Technique


@dataclass
class PlannedStep:
    """
    One step in an EmulationPlan — a technique to execute.

    Parameters
    ----------
    technique_id : str
        ATT&CK technique ID.
    tactic : str
        ATT&CK tactic name.
    technique_name : str
        Human-readable technique name.
    technique_cls : type[Technique]
        The technique class to instantiate and execute.
    params : dict
        Per-step overrides passed to the technique as ctx.params.
    """

    technique_id: str
    tactic: str
    technique_name: str
    technique_cls: type  # type[Technique] — avoids circular import
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class EmulationPlan:
    """
    Complete ordered execution plan for one EmulationRun.

    Parameters
    ----------
    run_id : str
        Associated EmulationRun ID.
    scenario_id : str
        Parent EmulationScenario ID.
    feed_id : str
        Source IntelFeed ID (for traceability).
    scope : Scope
        Safe-harbor execution scope — passed to every TechniqueContext.
    steps : list[PlannedStep]
        Ordered list of techniques to execute.
    """

    run_id: str
    scenario_id: str
    feed_id: str
    scope: Scope
    steps: list[PlannedStep] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.steps)

    def __iter__(self):
        return iter(self.steps)
