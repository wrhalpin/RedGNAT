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
                # Safety gate BEFORE every technique — including the first and
                # single-step plans (e.g. probe runs). Fail-closed: if the gate
                # cannot confirm it is safe to proceed it returns a stop reason.
                stop_reason = self._safety_check(plan)
                if stop_reason:
                    logger.warning(
                        "run=%s halted before technique=%s reason=%s",
                        run.run_id,
                        step.technique_id,
                        stop_reason,
                    )
                    # Record this step and all remaining steps as unexecuted
                    # so the run is fully accounted for.
                    killed_status = (
                        ResultStatus.EXPIRED
                        if stop_reason.startswith("expired")
                        else ResultStatus.KILLED
                    )
                    for remaining in steps[i:]:
                        killed = self._make_unexecuted_result(
                            plan, remaining, killed_status, stop_reason
                        )
                        results.append(killed)
                        store.insert_result(killed)
                    break

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

                # Pace before the next step (rate limit only — the safety gate
                # is re-checked at the top of the next iteration).
                if i < len(steps) - 1:
                    self._rate_limit_pause(plan)

        except Exception as exc:
            logger.exception("Unhandled error during run %s: %s", run.run_id, exc)
            run.status = RunStatus.FAILED
        else:
            run.status = self._aggregate_status(stop_reason, results)
        finally:
            run.completed_at = datetime.now(timezone.utc)
            store.upsert_run(run)
            store.close()

        return results

    @staticmethod
    def _aggregate_status(
        stop_reason: str | None, results: list[TechniqueResult]
    ) -> RunStatus:
        """Roll technique outcomes up into a single run status."""
        if stop_reason:
            return RunStatus.EXPIRED if stop_reason.startswith("expired") else RunStatus.KILLED
        executed = [
            r
            for r in results
            if r.status not in (ResultStatus.KILLED, ResultStatus.EXPIRED)
        ]
        # A run whose every executed technique errored is a failed run, not a
        # clean completion — downstream consumers rely on run.status.
        if executed and all(r.status == ResultStatus.ERROR for r in executed):
            return RunStatus.FAILED
        return RunStatus.COMPLETED

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

    # Upper bound on a single inter-step pause so a pathologically low rate
    # limit cannot hang a worker indefinitely, while still honouring the
    # configured spacing for any realistic rate.
    _MAX_STEP_PAUSE_SECONDS = 300.0

    def _rate_limit_pause(self, plan: EmulationPlan) -> None:
        """Sleep to respect ``scope.max_rate_per_minute`` between steps."""
        if plan.scope.max_rate_per_minute > 0:
            seconds_per_step = 60.0 / plan.scope.max_rate_per_minute
            time.sleep(min(seconds_per_step, self._MAX_STEP_PAUSE_SECONDS))

    def _safety_check(self, plan: EmulationPlan) -> str | None:
        """
        Check the kill switch. Fail-closed.

        Returns
        -------
        str | None
            None to continue; a non-empty string to halt the run. The string
            value describes the stop reason (e.g. "kill").
        """
        try:
            from redgnat.engagement.kill_switch import KillSwitch

            if KillSwitch(self.config).is_active():
                return "kill"
        except Exception as exc:
            # Cannot confirm it is safe to proceed → halt.
            logger.critical(
                "Runner: kill switch check errored — failing closed (halt): %s", exc
            )
            return "kill:check-error"

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

    def _safety_check(self, plan: EmulationPlan) -> str | None:
        # Kill switch check from parent (fail-closed)
        stop = super()._safety_check(plan)
        if stop:
            return stop

        # Additional gate: full three-factor engagement authorization must
        # still hold before each Phase 2 step. Fail-closed on any error.
        try:
            from redgnat.engagement.gate import EngagementGate

            authorized, reason = EngagementGate(self.config).check()
            if not authorized:
                return f"expired:{reason}"
        except Exception as exc:
            logger.critical(
                "EngagementRunner: gate check errored — failing closed (halt): %s", exc
            )
            return f"expired:gate-check-error:{exc}"

        return None
