# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""End-to-end route tests via the FastAPI TestClient (store/client mocked)."""
from __future__ import annotations

from unittest.mock import MagicMock

from tests.unit.api.conftest import AUTH


class TestHealthAndAuth:
    def test_health_no_auth(self, api):
        r = api.get("/api/v1/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_missing_api_key_rejected(self, api):
        r = api.get("/api/v1/scenarios")
        assert r.status_code in (401, 403)

    def test_api_key_accepted(self, api):
        r = api.get("/api/v1/scenarios", headers=AUTH)
        assert r.status_code == 200


class TestScenarioRoutes:
    def test_list_scenarios(self, api):
        r = api.get("/api/v1/scenarios", headers=AUTH)
        assert r.status_code == 200
        assert r.json()[0]["scenario_id"] == "scn-1"

    def test_get_scenario(self, api):
        r = api.get("/api/v1/scenarios/scn-1", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["name"] == "Test Scenario"

    def test_get_scenario_not_found(self, api, fake_client):
        fake_client.get_scenario.return_value = None
        r = api.get("/api/v1/scenarios/missing", headers=AUTH)
        assert r.status_code == 404

    def test_trigger_run(self, api):
        r = api.post("/api/v1/scenarios/scn-1/run", headers=AUTH, json={"triggered_by": "manual"})
        assert r.status_code == 200
        assert r.json()["run_id"] == "run-1"

    def test_trigger_run_unknown_scenario(self, api, fake_client):
        fake_client.run_scenario.side_effect = ValueError("no such scenario")
        r = api.post("/api/v1/scenarios/x/run", headers=AUTH, json={})
        assert r.status_code == 404

    def test_trigger_run_hypothesis_validation_invalid(self, api, fake_client, monkeypatch):
        fake_client.config.gnat_api_base_url = "http://gnat.test"
        monkeypatch.setattr(
            "redgnat.feedback.investigation_context.validate_hypothesis",
            lambda *a, **k: (False, "bad hypothesis"),
        )
        r = api.post(
            "/api/v1/scenarios/scn-1/run",
            headers=AUTH,
            json={"investigation_id": "IC-1", "hypothesis_id": "HYP-1"},
        )
        assert r.status_code == 400

    def test_trigger_run_hypothesis_validation_pending(self, api, fake_client, monkeypatch):
        fake_client.config.gnat_api_base_url = "http://gnat.test"
        monkeypatch.setattr(
            "redgnat.feedback.investigation_context.validate_hypothesis",
            lambda *a, **k: (None, "gnat unreachable"),
        )
        r = api.post(
            "/api/v1/scenarios/scn-1/run",
            headers=AUTH,
            json={"investigation_id": "IC-1", "hypothesis_id": "HYP-1"},
        )
        assert r.status_code == 200


class TestRunRoutes:
    def test_list_runs(self, api):
        r = api.get("/api/v1/runs", headers=AUTH)
        assert r.status_code == 200
        assert r.json()[0]["run_id"] == "run-1"

    def test_list_runs_filtered(self, api):
        r = api.get("/api/v1/runs?investigation_id=IC-2026-0001", headers=AUTH)
        assert r.status_code == 200

    def test_get_run(self, api):
        r = api.get("/api/v1/runs/run-1", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["investigation_id"] == "IC-2026-0001"

    def test_get_run_not_found(self, api, fake_client):
        fake_client.get_run.return_value = None
        r = api.get("/api/v1/runs/missing", headers=AUTH)
        assert r.status_code == 404

    def test_get_run_results(self, api):
        r = api.get("/api/v1/runs/run-1/results", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()) == 2

    def test_get_run_report(self, api):
        r = api.get("/api/v1/runs/run-1/report", headers=AUTH)
        assert r.status_code == 200
        assert "executive_summary" in r.json()

    def test_get_run_report_missing_run(self, api, fake_client):
        fake_client.get_run.return_value = None
        r = api.get("/api/v1/runs/x/report", headers=AUTH)
        assert r.status_code == 404

    def test_tag_run_with_investigation(self, api):
        r = api.post(
            "/api/v1/runs/run-1/investigation",
            headers=AUTH,
            json={"investigation_id": "IC-9", "hypothesis_id": "HYP-9"},
        )
        assert r.status_code == 200
        assert r.json()["investigation_id"] == "IC-9"

    def test_tag_run_requires_investigation_id(self, api):
        r = api.post("/api/v1/runs/run-1/investigation", headers=AUTH, json={})
        assert r.status_code == 400

    def test_tag_run_not_found(self, api, fake_client):
        fake_client.get_run.return_value = None
        r = api.post(
            "/api/v1/runs/x/investigation", headers=AUTH, json={"investigation_id": "IC-9"}
        )
        assert r.status_code == 404


class TestIntelRoutes:
    def test_trigger_ingest(self, api):
        r = api.post("/api/v1/intel/ingest", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["feeds_ingested"] == 1

    def test_probe_request_requires_technique(self, api):
        r = api.post("/api/v1/intel/probe-request", headers=AUTH, json={})
        assert r.status_code == 422

    def test_probe_request_queued(self, api, monkeypatch):
        fake_task = MagicMock()
        fake_task.id = "task-123"
        monkeypatch.setattr(
            "redgnat.emulation.tasks.run_probe_task.delay", lambda body: fake_task
        )
        r = api.post(
            "/api/v1/intel/probe-request", headers=AUTH, json={"technique_id": "T1621"}
        )
        assert r.status_code == 200
        assert r.json()["task_id"] == "task-123"

    def test_list_techniques(self, api):
        r = api.get("/api/v1/intel/techniques", headers=AUTH)
        assert r.status_code == 200
        assert any(t["technique_id"] == "T1046" for t in r.json())


class TestStixRoutes:
    def test_stix_results(self, api):
        r = api.get("/api/v1/stix/results", headers=AUTH)
        assert r.status_code == 200
        obj = r.json()[0]
        assert obj["type"] == "course-of-action"
        # investigation-scoped run should be stamped
        assert obj["x_gnat_investigation_id"] == "IC-2026-0001"

    def test_stix_result_by_id(self, api):
        r = api.get("/api/v1/stix/results/run-1", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["id"] == "course-of-action--run-1"

    def test_stix_result_not_found(self, api, fake_client):
        fake_client.get_run.return_value = None
        r = api.get("/api/v1/stix/results/x", headers=AUTH)
        assert r.status_code == 404

    def test_stix_sightings(self, api):
        r = api.get("/api/v1/stix/sightings", headers=AUTH)
        assert r.status_code == 200
        s = r.json()[0]
        assert s["type"] == "sighting"
        assert s["sighting_of_ref"].startswith("attack-pattern--")

    def test_stix_gaps(self, api):
        r = api.get("/api/v1/stix/gaps", headers=AUTH)
        assert r.status_code == 200
        # one SUCCESS result -> one gap note
        assert r.json()[0]["type"] == "note"

    def test_stix_groupings(self, api):
        r = api.get("/api/v1/stix/groupings", headers=AUTH)
        assert r.status_code == 200
        g = r.json()[0]
        assert g["type"] == "grouping"
        assert "note--" in " ".join(g["object_refs"])
