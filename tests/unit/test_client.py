# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""RedGNATClient facade tests with a mocked store."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from redgnat.client import RedGNATClient
from redgnat.orm.models import EmulationScenario, IntelFeed, IntelSource, ScenarioStatus


@pytest.fixture
def client():
    c = RedGNATClient(config_path="/nonexistent.ini")
    c._store = MagicMock()
    return c


def _scenario():
    return EmulationScenario(scenario_id="s1", name="n", status=ScenarioStatus.ACTIVE)


class TestScenarioManagement:
    def test_list_and_get_scenario(self, client):
        client._store.list_scenarios.return_value = [_scenario()]
        client._store.get_scenario.return_value = _scenario()
        assert client.list_scenarios()[0].scenario_id == "s1"
        assert client.get_scenario("s1").scenario_id == "s1"


class TestRunScenario:
    def test_missing_scenario_raises(self, client):
        client._store.get_scenario.return_value = None
        with pytest.raises(ValueError):
            client.run_scenario("missing")

    def test_async_enqueues_task(self, client):
        client._store.get_scenario.return_value = _scenario()
        task = MagicMock()
        task.id = "task-1"
        with patch("redgnat.emulation.tasks.run_scenario_task.delay", return_value=task):
            run = client.run_scenario("s1", async_=True)
        assert run.celery_task_id == "task-1"
        assert run.scenario_id == "s1"

    def test_sync_runs_inline(self, client):
        client._store.get_scenario.return_value = _scenario()
        with patch("redgnat.emulation.runner.EmulationRunner") as Runner:
            run = client.run_scenario("s1", async_=False)
        Runner.return_value.execute.assert_called_once()
        assert run.scenario_id == "s1"

    def test_list_and_get_run(self, client):
        client._store.list_runs.return_value = []
        client._store.get_run.return_value = None
        assert client.list_runs() == []
        assert client.get_run("x") is None


class TestIngestLatest:
    def test_ingest_builds_scenarios(self, client):
        feed = IntelFeed(feed_id="f1", source=IntelSource.GNAT, source_ref_id="c1")
        sub = MagicMock()
        sub.poll.return_value = [feed]
        normalizer = MagicMock()
        normalizer.to_scenario.return_value = _scenario()
        with (
            patch("redgnat.intake.gnat_subscriber.GNATSubscriber", return_value=sub),
            patch("redgnat.intake.sandgnat_subscriber.SandGNATSubscriber", return_value=sub),
            patch("redgnat.intake.normalizer.IntelNormalizer", return_value=normalizer),
        ):
            feeds = client.ingest_latest()
        # two subscribers, one feed each
        assert len(feeds) == 2
        client._store.upsert_feed.assert_called()
        client._store.upsert_scenario.assert_called()


def test_lazy_helpers_instantiate():
    c = RedGNATClient(config_path="/nonexistent.ini")
    assert c._get_store() is c._get_store()  # cached
    assert c._normalizer() is c._normalizer()
