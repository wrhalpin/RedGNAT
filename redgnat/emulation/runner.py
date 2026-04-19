# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
EmulationRunner — executes an EmulationPlan step by step.

The runner dispatches each PlannedStep to its technique module, collects
TechniqueResults, persists them, and updates the EmulationRun status.

Two runner classes are provided:

  EmulationRunner    — Phase 1; checks kill switch between every step.
  EngagementRunner   — Phase 2; additionally checks the engagement token
                       between steps and aborts if it has expired.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from redgnat.config import RedGNATConfig
from redgnat.emulation.plan import EmulationPlan
from redgnat.orm.models import EmulationRun, ResultStatus, RunStatus, TechniqueResult
from redgnat.techniques.base import TechniqueContext

logger = logging.getLogger(__name__)


class EmulationRunner:
    """
    Executes an EmulationPlan and persists results.

    Checks the kill switch between every technique step. If the kill switch
    is active after a step completes, the run is halted and all remaining
    planned techniques are recorded as KILLED.

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
            All technique results from this run, including KILLED records
            for any techniques that did not execute due to a kill event.
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
        steps = list(plan)
        stop_reason: str | None = None

        try:
            for i, step in enumerate(steps):
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

                # Check safety gates between techniques; finish the last step cleanly
                if i < len(steps) - 1:
                    stop_reason = self._inter_technique_pause(plan)
                    if stop_reason:
                        logger.warning(
                            "run=%s halted after technique=%s reason=%s",
                            run.run_id,
                            step.technique_id,
                            stop_reason,
                        )
                        # Record unexecuted steps so the run is fully accounted for
                        killed_status = (
                            ResultStatus.EXPIRED
                            if stop_reason.startswith("expired")
                            else ResultStatus.KILLED
                        )
                        for remaining in steps[i + 1 :]:
                            killed = self._make_unexecuted_result(
                                plan, remaining, killed_status, stop_reason
                            )
                            results.append(killed)
                            store.insert_result(killed)
                        break
                else:
                    self._inter_technique_pause(plan)

        except Exception as exc:
            logger.exception("Unhandled error during run %s: %s", run.run_id, exc)
            run.status = RunStatus.FAILED
        else:
            run.status = RunStatus.KILLED if stop_reason else RunStatus.COMPLETED
        finally:
            run.completed_at = datetime.now(timezone.utc)
            store.upsert_run(run)
            store.close()

        return results

    def _execute_step(self, step: "object", plan: EmulationPlan) -> TechniqueResult:
        from redgnat.orm.base import new_uuid  # noqa: F401

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
            result = TechniqueResult(
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

    def _inter_technique_pause(self, plan: EmulationPlan) -> str | None:
        """
        Sleep to respect the rate limit, then check the kill switch.

        Returns
        -------
        str | None
            None to continue; a non-empty string to halt the run.
            The string value describes the stop reason (e.g. "kill").
        """
        if plan.scope.max_rate_per_minute > 0:
            seconds_per_step = 60.0 / plan.scope.max_rate_per_minute
            time.sleep(min(seconds_per_step, 2.0))

        try:
            from redgnat.engagement.kill_switch import KillSwitch

            if KillSwitch(self.config).is_active():
                return "kill"
        except Exception as exc:
            logger.warning("Runner: kill switch check failed (non-fatal): %s", exc)

        return None

    @staticmethod
    def _make_unexecuted_result(
        plan: EmulationPlan,
        step: "object",
        status: ResultStatus,
        reason: str,
    ) -> TechniqueResult:
        return TechniqueResult(
            run_id=plan.run_id,
            scenario_id=plan.scenario_id,
            feed_id=plan.feed_id,
            technique_id=step.technique_id,
            tactic=step.tactic,
            status=status,
            findings=[],
            evidence=[],
            error=reason,
            executed_at=datetime.now(timezone.utc),
        )


class EngagementRunner(EmulationRunner):
    """
    Phase 2 runner — identical to EmulationRunner but also checks the
    engagement token between every step.

    If the token expires mid-run the remaining techniques are recorded
    as EXPIRED and the run is halted cleanly.
    """

    def _inter_technique_pause(self, plan: EmulationPlan) -> str | None:
        # Kill switch check from parent
        stop = super()._inter_technique_pause(plan)
        if stop:
            return stop

        # Additional gate: engagement token validity
        try:
            from redgnat.engagement.gate import EngagementGate

            authorized, reason = EngagementGate(self.config).check()
            if not authorized:
                return f"expired:{reason}"
        except Exception as exc:
            logger.warning("EngagementRunner: gate check failed (non-fatal): %s", exc)

        return None
