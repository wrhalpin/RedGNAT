# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests — Phase 1: EmulationRun investigation fields and store persistence."""
from __future__ import annotations

from redgnat.orm.models import EmulationRun, RunStatus


def _make_run(**kwargs) -> EmulationRun:
    return EmulationRun(
        scenario_id="scenario-001",
        triggered_by="manual",
        **kwargs,
    )


class TestEmulationRunInvestigationFields:
    def test_defaults_are_none(self):
        run = _make_run()
        assert run.investigation_id is None
        assert run.hypothesis_id is None
        assert run.investigation_tenant_id is None
        assert run.investigation_validation_pending is False

    def test_fields_accepted(self):
        run = _make_run(
            investigation_id="IC-2026-0001",
            hypothesis_id="HYP-2026-0001-01",
            investigation_tenant_id="tenant-a",
            investigation_validation_pending=True,
        )
        assert run.investigation_id == "IC-2026-0001"
        assert run.hypothesis_id == "HYP-2026-0001-01"
        assert run.investigation_tenant_id == "tenant-a"
        assert run.investigation_validation_pending is True

    def test_to_dict_includes_fields(self):
        run = _make_run(
            investigation_id="IC-2026-0001",
            hypothesis_id="HYP-0001",
        )
        d = run.to_dict()
        assert d["investigation_id"] == "IC-2026-0001"
        assert d["hypothesis_id"] == "HYP-0001"
        assert d["investigation_tenant_id"] is None
        assert d["investigation_validation_pending"] is False

    def test_from_dict_round_trip(self):
        run = _make_run(
            investigation_id="IC-2026-0002",
            hypothesis_id="HYP-0002",
            investigation_tenant_id="tenant-b",
            investigation_validation_pending=True,
        )
        restored = EmulationRun.from_dict(run.to_dict())
        assert restored.investigation_id == "IC-2026-0002"
        assert restored.hypothesis_id == "HYP-0002"
        assert restored.investigation_tenant_id == "tenant-b"
        assert restored.investigation_validation_pending is True

    def test_from_dict_missing_fields_default_none(self):
        """Old records without investigation fields deserialise safely."""
        d = {
            "run_id": "run-001",
            "scenario_id": "scen-001",
            "status": "queued",
            "triggered_by": "scheduler",
        }
        run = EmulationRun.from_dict(d)
        assert run.investigation_id is None
        assert run.investigation_validation_pending is False
