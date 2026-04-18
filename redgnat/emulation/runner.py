"""
EmulationRunner — executes an EmulationPlan step by step.

The runner dispatches each PlannedStep to its technique module, collects
TechniqueResults, persists them, and updates the EmulationRun status.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from redgnat.config import RedGNATConfig
from redgnat.emulation.plan import EmulationPlan
from redgnat.orm.models import EmulationRun, RunStatus, TechniqueResult
from redgnat.techniques.base import TechniqueContext

logger = logging.getLogger(__name__)


class EmulationRunner:
    """
    Executes an EmulationPlan and persists results.

    Parameters
    ----------
    config : RedGNATConfig
        Global configuration.
    """

    def __init__(self, config: RedGNATConfig) -> None:
        self.config = config

    def execute(self, run: EmulationRun, scenario: "object") -> list[TechniqueResult]:
        """
        Execute all steps in the scenario's plan and persist results.

        Parameters
        ----------
        run : EmulationRun
            The run being executed (mutated in-place with status + timestamps).
        scenario : EmulationScenario
            The scenario to execute.

        Returns
        -------
        list[TechniqueResult]
            All technique results from this run.
        """
        from redgnat.scenarios.builder import ScenarioBuilder
        from redgnat.scenarios.store import ScenarioStore

        store = ScenarioStore(self.config)
        builder = ScenarioBuilder(self.config)
        plan = builder.build_plan(scenario, run)

        run.status = RunStatus.RUNNING
        run.started_at = datetime.now(timezone.utc)
        store.upsert_run(run)

        results: list[TechniqueResult] = []

        try:
            for step in plan:
                result = self._execute_step(step, plan)
                results.append(result)
                store.insert_result(result)
                logger.info(
                    "run=%s technique=%s status=%s findings=%d",
                    run.run_id,
                    result.technique_id,
                    result.status.value,
                    len(result.findings),
                )
                # Respect global rate limit between techniques
                self._inter_technique_pause(plan)

        except Exception as exc:
            logger.exception("Unhandled error during run %s: %s", run.run_id, exc)
            run.status = RunStatus.FAILED
        else:
            run.status = RunStatus.COMPLETED
        finally:
            run.completed_at = datetime.now(timezone.utc)
            store.upsert_run(run)
            store.close()

        return results

    def _execute_step(self, step: "object", plan: EmulationPlan) -> TechniqueResult:
        from redgnat.techniques.base import TechniqueContext
        from redgnat.orm.models import ResultStatus, TechniqueResult as TR
        from redgnat.orm.base import new_uuid
        from datetime import datetime, timezone

        ctx = TechniqueContext(
            run_id=plan.run_id,
            scenario_id=plan.scenario_id,
            feed_id=plan.feed_id,
            scope=plan.scope,
            params=step.params,
        )

        try:
            technique = step.technique_cls()
            result = technique.execute(ctx)
        except Exception as exc:
            logger.exception(
                "Technique %s raised unhandled exception: %s", step.technique_id, exc
            )
            result = TR(
                run_id=plan.run_id,
                scenario_id=plan.scenario_id,
                feed_id=plan.feed_id,
                technique_id=step.technique_id,
                tactic=step.tactic,
                status=ResultStatus.ERROR,
                findings=[],
                evidence=[],
                error=str(exc),
                executed_at=datetime.now(timezone.utc),
            )

        return result

    @staticmethod
    def _inter_technique_pause(plan: EmulationPlan) -> None:
        """Brief pause between techniques to respect the per-minute rate limit."""
        if plan.scope.max_rate_per_minute > 0:
            # Simple throttle: spread budget evenly across techniques
            seconds_per_step = 60.0 / plan.scope.max_rate_per_minute
            time.sleep(min(seconds_per_step, 2.0))
