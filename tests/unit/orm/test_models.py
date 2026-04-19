# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Unit tests for ORM model serialisation."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

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


class TestIntelFeed:
    def test_round_trip(self):
        feed = IntelFeed(
            source=IntelSource.SANDGNAT,
            source_ref_id="analysis-abc",
            campaign_name="Test Malware",
            attack_pattern_ids=["T1046", "T1566.002"],
            confidence=0.8,
        )
        restored = IntelFeed.from_dict(feed.to_dict())
        assert restored.feed_id == feed.feed_id
        assert restored.source == IntelSource.SANDGNAT
        assert restored.attack_pattern_ids == ["T1046", "T1566.002"]
        assert restored.confidence == 0.8


class TestEmulationScenario:
    def test_round_trip(self):
        s = EmulationScenario(
            name="Test Scenario",
            description="desc",
            feed_id="feed-1",
            technique_ids=["T1046"],
            status=ScenarioStatus.ACTIVE,
        )
        restored = EmulationScenario.from_dict(s.to_dict())
        assert restored.scenario_id == s.scenario_id
        assert restored.name == "Test Scenario"
        assert restored.status == ScenarioStatus.ACTIVE


class TestEmulationRun:
    def test_round_trip(self):
        run = EmulationRun(
            scenario_id="s-001",
            status=RunStatus.COMPLETED,
            triggered_by="manual",
        )
        restored = EmulationRun.from_dict(run.to_dict())
        assert restored.run_id == run.run_id
        assert restored.status == RunStatus.COMPLETED


class TestTechniqueResult:
    def test_round_trip(self):
        r = TechniqueResult(
            run_id="run-1",
            scenario_id="s-1",
            feed_id="f-1",
            technique_id="T1046",
            tactic="discovery",
            status=ResultStatus.SUCCESS,
            findings=[{"host": "192.168.1.5", "open_ports": [{"port": 22}]}],
        )
        restored = TechniqueResult.from_dict(r.to_dict())
        assert restored.result_id == r.result_id
        assert restored.status == ResultStatus.SUCCESS
        assert len(restored.findings) == 1

    def test_to_stix_sighting(self):
        r = TechniqueResult(
            run_id="run-1",
            scenario_id="s-1",
            feed_id="f-1",
            technique_id="T1046",
            tactic="discovery",
            status=ResultStatus.SUCCESS,
            findings=[{"host": "192.168.1.5"}],
        )
        sighting = r.to_stix_sighting()
        assert sighting["type"] == "sighting"
        assert "T1046" in sighting["sighting_of_ref"]
        assert sighting["x_redgnat_metadata"]["run_id"] == "run-1"
