# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Celery task-body tests (client/store/runner mocked)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from redgnat.emulation import tasks
from redgnat.orm.models import (
    EmulationRun,
    EmulationScenario,
    ResultStatus,
    RunStatus,
    ScenarioStatus,
    TechniqueResult,
)


def _run(**kw):
    return EmulationRun(run_id="r1", scenario_id="s1", status=RunStatus.COMPLETED, **kw)


def _scenario():
    return EmulationScenario(scenario_id="s1", name="n", status=ScenarioStatus.ACTIVE)


def _gap_result():
    return TechniqueResult(
        run_id="r1",
        scenario_id="s1",
        technique_id="T1046",
        tactic="discovery",
        status=ResultStatus.SUCCESS,
        findings=[{"open_ports": [80]}],
    )


class TestParseProbeDepth:
    def test_variants(self):
        assert tasks._parse_probe_depth("probe:x:d3") == 3
        assert tasks._parse_probe_depth("manual") == 0
        assert tasks._parse_probe_depth("") == 0


class TestRunScenarioTask:
    def test_run_not_found(self):
        client = MagicMock()
        client._get_store.return_value.get_run.return_value = None
        with patch("redgnat.client.RedGNATClient", return_value=client):
            out = tasks.run_scenario_task.run("missing")
        assert "error" in out

    def test_scenario_not_found(self):
        client = MagicMock()
        store = client._get_store.return_value
        store.get_run.return_value = _run()
        store.get_scenario.return_value = None
        with patch("redgnat.client.RedGNATClient", return_value=client):
            out = tasks.run_scenario_task.run("r1")
        assert "error" in out

    def test_happy_path_runs_and_feeds_back(self):
        client = MagicMock()
        store = client._get_store.return_value
        run = _run()
        store.get_run.return_value = run
        store.get_scenario.return_value = _scenario()
        with (
            patch("redgnat.client.RedGNATClient", return_value=client),
            patch("redgnat.emulation.runner.EmulationRunner") as Runner,
            patch.object(tasks, "_run_feedback") as fb,
        ):
            Runner.return_value.execute.return_value = [_gap_result()]
            out = tasks.run_scenario_task.run("r1")
        assert out["run_id"] == "r1"
        assert out["techniques_executed"] == 1
        fb.assert_called_once()


class TestRunFeedback:
    def _config(self, **over):
        cfg = MagicMock()
        cfg.feedback_enabled = True
        cfg.feedback_push_to_gnat = True
        cfg.feedback_probe_generation_enabled = True
        cfg.feedback_probe_model = "m"
        cfg.feedback_max_probes = 5
        cfg.feedback_max_probe_depth = 3
        for k, v in over.items():
            setattr(cfg, k, v)
        return cfg

    def test_disabled_short_circuits(self):
        cfg = self._config(feedback_enabled=False)
        tasks._run_feedback(cfg, _run(), [])  # no exception, returns early

    def test_no_gaps_returns(self):
        cfg = self._config()
        with patch("redgnat.feedback.gap_reporter.GapReporter") as GR:
            GR.return_value.build_report.return_value = MagicMock(gaps=[])
            tasks._run_feedback(cfg, _run(), [])
        GR.return_value.push_to_gnat.assert_not_called()

    def test_generates_probes_and_enqueues(self):
        cfg = self._config()
        report = MagicMock(gaps=[_gap_result()], gap_id="g1")
        probe = MagicMock()
        probe.depth = 0
        probe.to_dict.return_value = {"technique_id": "T1595"}
        with (
            patch("redgnat.feedback.gap_reporter.GapReporter") as GR,
            patch("redgnat.feedback.probe_generator.ProbeGenerator") as PG,
            patch.object(tasks.run_probe_task, "delay") as delay,
        ):
            GR.return_value.build_report.return_value = report
            PG.return_value.generate.return_value = [probe]
            tasks._run_feedback(cfg, _run(triggered_by="manual"), [_gap_result()])
        assert probe.depth == 1
        delay.assert_called_once()

    def test_depth_cap_stops_probes(self):
        cfg = self._config()
        report = MagicMock(gaps=[_gap_result()], gap_id="g1")
        with (
            patch("redgnat.feedback.gap_reporter.GapReporter") as GR,
            patch("redgnat.feedback.probe_generator.ProbeGenerator") as PG,
        ):
            GR.return_value.build_report.return_value = report
            # run already at max depth -> no probe generation
            tasks._run_feedback(cfg, _run(triggered_by="probe:x:d3"), [_gap_result()])
            PG.return_value.generate.assert_not_called()


class TestRunProbeTask:
    def test_unregistered_technique_skipped(self):
        client = MagicMock()
        client._normalizer.return_value.to_scenario.return_value = None
        with patch("redgnat.client.RedGNATClient", return_value=client):
            out = tasks.run_probe_task.run({"technique_id": "T9999", "probe_id": "p1"})
        assert out["skipped"] is True

    def test_probe_runs_scenario(self):
        client = MagicMock()
        client._normalizer.return_value.to_scenario.return_value = _scenario()
        client.run_scenario.return_value = _run()
        with patch("redgnat.client.RedGNATClient", return_value=client):
            out = tasks.run_probe_task.run({"technique_id": "T1046", "probe_id": "p1", "depth": 1})
        assert out["run_id"] == "r1"
        # depth threaded into triggered_by
        _, kwargs = client.run_scenario.call_args
        assert kwargs["triggered_by"].endswith(":d1")


class TestRunEngagementTask:
    def test_gate_denied(self):
        client = MagicMock()
        store = client._get_store.return_value
        store.get_run.return_value = _run()
        store.get_scenario.return_value = _scenario()
        gate = MagicMock()
        gate.check.return_value = (False, "no token")
        with (
            patch("redgnat.client.RedGNATClient", return_value=client),
            patch("redgnat.engagement.gate.EngagementGate", return_value=gate),
        ):
            out = tasks.run_engagement_task.run("r1")
        assert out["authorized"] is False

    def test_gate_allowed_runs(self):
        client = MagicMock()
        store = client._get_store.return_value
        store.get_run.return_value = _run()
        store.get_scenario.return_value = _scenario()
        gate = MagicMock()
        gate.check.return_value = (True, "ok")
        with (
            patch("redgnat.client.RedGNATClient", return_value=client),
            patch("redgnat.engagement.gate.EngagementGate", return_value=gate),
            patch("redgnat.emulation.runner.EngagementRunner") as Runner,
            patch.object(tasks, "_run_feedback"),
        ):
            Runner.return_value.execute.return_value = [_gap_result()]
            out = tasks.run_engagement_task.run("r1")
        assert out["authorized"] is True


class TestIngestIntelTask:
    def test_enqueues_active_scenarios(self):
        client = MagicMock()
        client.ingest_latest.return_value = []
        client.list_scenarios.return_value = [_scenario()]
        client.list_runs.return_value = []  # no existing runs -> enqueue
        with patch("redgnat.client.RedGNATClient", return_value=client):
            out = tasks.ingest_intel_task.run()
        assert out["runs_enqueued"] == 1
        client.run_scenario.assert_called_once()
