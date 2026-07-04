# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""EmulationRunner tests with a mocked store and in-memory techniques."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from redgnat.config import RedGNATConfig
from redgnat.emulation.plan import EmulationPlan, PlannedStep
from redgnat.emulation.runner import EmulationRunner, EngagementRunner
from redgnat.orm.models import EmulationRun, ResultStatus, RunStatus
from redgnat.techniques.base import Scope, Technique, TechniqueContext


class _OkTechnique(Technique):
    technique_id = "T1046"
    tactic = "discovery"
    name = "ok"

    def execute(self, ctx: TechniqueContext):
        return self._make_result(ctx, ResultStatus.SUCCESS, [{"ok": True}])


class _BoomTechnique(Technique):
    technique_id = "T9999"
    tactic = "discovery"
    name = "boom"

    def execute(self, ctx: TechniqueContext):
        raise RuntimeError("kaboom")


def _plan(*technique_classes):
    steps = [
        PlannedStep(
            technique_id=t.technique_id,
            tactic=t.tactic,
            technique_name=t.name,
            technique_cls=t,
        )
        for t in technique_classes
    ]
    return EmulationPlan(
        run_id="r1", scenario_id="s1", feed_id="f1",
        scope=Scope(max_rate_per_minute=0), steps=steps,
    )


@pytest.fixture
def store():
    return MagicMock()


@pytest.fixture
def runner(store):
    r = EmulationRunner(RedGNATConfig(path="/nope.ini"))
    return r


def _run_with_plan(runner, store, plan, kill_active=False):
    run = EmulationRun(run_id="r1", scenario_id="s1", status=RunStatus.QUEUED)
    builder = MagicMock()
    builder.build_plan.return_value = plan
    ks = MagicMock()
    ks.is_active.return_value = kill_active
    with patch("redgnat.scenarios.store.ScenarioStore", return_value=store), \
         patch("redgnat.scenarios.builder.ScenarioBuilder", return_value=builder), \
         patch("redgnat.engagement.kill_switch.KillSwitch", return_value=ks):
        results = runner.execute(run, object())
    return run, results


class TestEmulationRunner:
    def test_all_success_completes(self, runner, store):
        run, results = _run_with_plan(runner, store, _plan(_OkTechnique))
        assert run.status == RunStatus.COMPLETED
        assert results[0].status == ResultStatus.SUCCESS
        store.insert_result.assert_called()

    def test_all_error_marks_failed(self, runner, store):
        run, results = _run_with_plan(runner, store, _plan(_BoomTechnique))
        assert run.status == RunStatus.FAILED
        assert results[0].status == ResultStatus.ERROR

    def test_kill_switch_halts_before_first_step(self, runner, store):
        run, results = _run_with_plan(
            runner, store, _plan(_OkTechnique, _OkTechnique), kill_active=True
        )
        assert run.status == RunStatus.KILLED
        # no technique executed; both recorded KILLED
        assert all(r.status == ResultStatus.KILLED for r in results)

    def test_empty_plan_completes(self, runner, store):
        run, results = _run_with_plan(runner, store, _plan())
        assert run.status == RunStatus.COMPLETED
        assert results == []

    def test_safety_check_error_fails_closed(self, runner):
        plan = _plan(_OkTechnique)
        run = EmulationRun(run_id="r1", scenario_id="s1")
        store = MagicMock()
        builder = MagicMock()
        builder.build_plan.return_value = plan
        ks = MagicMock()
        ks.is_active.side_effect = RuntimeError("redis down")
        with patch("redgnat.scenarios.store.ScenarioStore", return_value=store), \
             patch("redgnat.scenarios.builder.ScenarioBuilder", return_value=builder), \
             patch("redgnat.engagement.kill_switch.KillSwitch", return_value=ks):
            runner.execute(run, object())
        assert run.status == RunStatus.KILLED


class TestEngagementRunner:
    def test_gate_denied_expires_run(self):
        runner = EngagementRunner(RedGNATConfig(path="/nope.ini"))
        plan = _plan(_OkTechnique)
        run = EmulationRun(run_id="r1", scenario_id="s1")
        store = MagicMock()
        builder = MagicMock()
        builder.build_plan.return_value = plan
        ks = MagicMock()
        ks.is_active.return_value = False
        gate = MagicMock()
        gate.check.return_value = (False, "token expired")
        with patch("redgnat.scenarios.store.ScenarioStore", return_value=store), \
             patch("redgnat.scenarios.builder.ScenarioBuilder", return_value=builder), \
             patch("redgnat.engagement.kill_switch.KillSwitch", return_value=ks), \
             patch("redgnat.engagement.gate.EngagementGate", return_value=gate):
            results = runner.execute(run, object())
        assert run.status == RunStatus.EXPIRED
        assert results[0].status == ResultStatus.EXPIRED

    def test_gate_check_error_fails_closed(self):
        # If the gate check itself raises, the engagement must halt (fail
        # closed), not proceed.
        runner = EngagementRunner(RedGNATConfig(path="/nope.ini"))
        plan = _plan(_OkTechnique)
        run = EmulationRun(run_id="r1", scenario_id="s1")
        store = MagicMock()
        builder = MagicMock()
        builder.build_plan.return_value = plan
        ks = MagicMock()
        ks.is_active.return_value = False
        gate = MagicMock()
        gate.check.side_effect = RuntimeError("redis down")
        with patch("redgnat.scenarios.store.ScenarioStore", return_value=store), \
             patch("redgnat.scenarios.builder.ScenarioBuilder", return_value=builder), \
             patch("redgnat.engagement.kill_switch.KillSwitch", return_value=ks), \
             patch("redgnat.engagement.gate.EngagementGate", return_value=gate):
            results = runner.execute(run, object())
        assert run.status == RunStatus.EXPIRED
        assert results[0].status == ResultStatus.EXPIRED


class TestRunnerTopLevelError:
    def test_store_error_during_loop_marks_failed(self):
        runner = EmulationRunner(RedGNATConfig(path="/nope.ini"))
        run = EmulationRun(run_id="r1", scenario_id="s1")
        store = MagicMock()
        # persisting a result mid-loop blows up -> outer handler -> FAILED
        store.insert_result.side_effect = RuntimeError("db gone")
        builder = MagicMock()
        builder.build_plan.return_value = _plan(_OkTechnique)
        ks = MagicMock()
        ks.is_active.return_value = False
        with patch("redgnat.scenarios.store.ScenarioStore", return_value=store), \
             patch("redgnat.scenarios.builder.ScenarioBuilder", return_value=builder), \
             patch("redgnat.engagement.kill_switch.KillSwitch", return_value=ks):
            runner.execute(run, object())
        assert run.status == RunStatus.FAILED
