"""
ScenarioBuilder — assembles EmulationPlans from EmulationScenarios.

The builder takes a stored EmulationScenario (a list of technique IDs and
scope overrides) and produces an EmulationPlan ready for the runner.
"""
from __future__ import annotations

import logging
from typing import Any

from redgnat.config import RedGNATConfig
from redgnat.emulation.plan import EmulationPlan, PlannedStep
from redgnat.orm.models import EmulationRun, EmulationScenario
from redgnat.scenarios.ttp_mapper import TTPMapper
from redgnat.techniques.base import Scope

logger = logging.getLogger(__name__)


class ScenarioBuilder:
    """
    Converts a stored EmulationScenario into an executable EmulationPlan.

    Parameters
    ----------
    config : RedGNATConfig
        Global configuration (provides base scope settings).
    """

    def __init__(self, config: RedGNATConfig) -> None:
        self.config = config
        self._mapper = TTPMapper()

    def build_plan(self, scenario: EmulationScenario, run: EmulationRun) -> EmulationPlan:
        """
        Build an EmulationPlan for execution.

        Parameters
        ----------
        scenario : EmulationScenario
            The scenario to execute.
        run : EmulationRun
            The run context (provides run_id for tracing).

        Returns
        -------
        EmulationPlan
        """
        from redgnat.techniques.registry import TECHNIQUE_REGISTRY

        scope = self._build_scope(scenario.scope_overrides)
        steps: list[PlannedStep] = []

        for tid in scenario.technique_ids:
            technique_cls = TECHNIQUE_REGISTRY.get(tid)
            if technique_cls is None:
                logger.warning(
                    "Technique %s in scenario %s has no registered module — skipping",
                    tid,
                    scenario.scenario_id,
                )
                continue

            info = self._mapper.get(tid)
            steps.append(
                PlannedStep(
                    technique_id=tid,
                    tactic=info.tactic if info else "unknown",
                    technique_name=info.name if info else tid,
                    technique_cls=technique_cls,
                    params={},
                )
            )

        if not steps:
            logger.warning(
                "Scenario %s produced no executable steps (no registered techniques)",
                scenario.scenario_id,
            )

        return EmulationPlan(
            run_id=run.run_id,
            scenario_id=scenario.scenario_id,
            feed_id=scenario.feed_id,
            scope=scope,
            steps=steps,
        )

    def _build_scope(self, overrides: dict[str, Any]) -> Scope:
        """Merge global scope config with per-scenario overrides."""
        return Scope(
            target_ranges=overrides.get("target_ranges", self.config.scope_target_ranges),
            excluded_ranges=overrides.get("excluded_ranges", self.config.scope_excluded_ranges),
            target_domains=overrides.get("target_domains", self.config.scope_target_domains),
            excluded_domains=overrides.get("excluded_domains", self.config.scope_excluded_domains),
            target_accounts=overrides.get("target_accounts", self.config.scope_target_accounts),
            max_rate_per_minute=overrides.get(
                "max_rate_per_minute", self.config.scope_max_rate_per_minute
            ),
            dry_run=overrides.get("dry_run", self.config.dry_run),
        )
