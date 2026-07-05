# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Shared fixtures for API route tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from starlette.testclient import TestClient

from redgnat.api.app import create_app
from redgnat.orm.models import (
    EmulationRun,
    EmulationScenario,
    IntelFeed,
    IntelSource,
    ResultStatus,
    RunStatus,
    ScenarioStatus,
    TechniqueResult,
)

AUTH = {"X-API-Key": "test-key"}


@pytest.fixture
def scenario() -> EmulationScenario:
    return EmulationScenario(
        scenario_id="scn-1",
        name="Test Scenario",
        description="desc",
        feed_id="feed-1",
        technique_ids=["T1046", "T1110.003"],
        status=ScenarioStatus.ACTIVE,
    )


@pytest.fixture
def run() -> EmulationRun:
    return EmulationRun(
        run_id="run-1",
        scenario_id="scn-1",
        status=RunStatus.COMPLETED,
        triggered_by="manual",
        investigation_id="IC-2026-0001",
        hypothesis_id="HYP-2026-0001-01",
    )


@pytest.fixture
def results() -> list[TechniqueResult]:
    return [
        TechniqueResult(
            result_id="res-1",
            run_id="run-1",
            scenario_id="scn-1",
            feed_id="feed-1",
            technique_id="T1046",
            tactic="discovery",
            status=ResultStatus.SUCCESS,
            findings=[{"open_ports": [80, 443], "host": "10.0.0.5"}],
        ),
        TechniqueResult(
            result_id="res-2",
            run_id="run-1",
            scenario_id="scn-1",
            feed_id="feed-1",
            technique_id="T1110.003",
            tactic="credential-access",
            status=ResultStatus.DETECTED,
            findings=[{"successful_authentications": 0}],
        ),
    ]


@pytest.fixture
def feed() -> IntelFeed:
    return IntelFeed(
        feed_id="feed-1",
        source=IntelSource.GNAT,
        source_ref_id="campaign-1",
        attack_pattern_ids=["T1046"],
        confidence=0.9,
    )


@pytest.fixture
def fake_client(scenario, run, results, feed):
    store = MagicMock()
    store.list_runs.return_value = [run]
    store.list_results.return_value = results
    store.upsert_run.return_value = None

    client = MagicMock()
    client.config = MagicMock()
    client.config.gnat_api_base_url = ""
    client.config.gnat_api_key = ""
    client._get_store.return_value = store
    client.list_runs.return_value = [run]
    client.list_scenarios.return_value = [scenario]
    client.get_scenario.return_value = scenario
    client.get_run.return_value = run
    client.run_scenario.return_value = run
    client.ingest_latest.return_value = [feed]
    return client


@pytest.fixture
def api(monkeypatch, fake_client):
    """TestClient with the RedGNATClient factory patched to a fake."""
    monkeypatch.setattr("redgnat.client.RedGNATClient", lambda *a, **k: fake_client)
    app = create_app()
    return TestClient(app, raise_server_exceptions=True)
