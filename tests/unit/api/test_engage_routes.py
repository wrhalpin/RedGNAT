# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Engagement route tests (gate / kill switch / authorize)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from starlette.testclient import TestClient

from redgnat.api.app import create_app

AUTH = {"X-API-Key": "test-key"}


@pytest.fixture
def api(monkeypatch):
    fake_client = MagicMock()
    monkeypatch.setattr("redgnat.client.RedGNATClient", lambda *a, **k: fake_client)
    app = create_app()
    return TestClient(app, raise_server_exceptions=True)


class TestEngageStatus:
    def test_status(self, api, monkeypatch):
        gate = MagicMock()
        gate.status.return_value = {"gate1": True, "gate2": False}
        monkeypatch.setattr("redgnat.engagement.gate.EngagementGate", lambda cfg: gate)
        r = api.get("/api/v1/engage/status", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["gate1"] is True


class TestAuthorize:
    def test_authorize_requires_kill_key_when_unset(self, api, monkeypatch):
        # deny_if_unset: no REDGNAT_KILL_KEY configured -> 403
        monkeypatch.delenv("REDGNAT_KILL_KEY", raising=False)
        r = api.post(
            "/api/v1/engage/authorize",
            headers=AUTH,
            json={"operator": "alice", "duration_hours": 4},
        )
        assert r.status_code == 403

    def test_authorize_validates_duration(self, api, monkeypatch):
        monkeypatch.setenv("REDGNAT_KILL_KEY", "kk")
        r = api.post(
            "/api/v1/engage/authorize",
            headers={**AUTH, "X-Kill-Key": "kk"},
            json={"operator": "alice", "duration_hours": 100},
        )
        assert r.status_code == 422

    def test_authorize_requires_operator(self, api, monkeypatch):
        monkeypatch.setenv("REDGNAT_KILL_KEY", "kk")
        r = api.post(
            "/api/v1/engage/authorize",
            headers={**AUTH, "X-Kill-Key": "kk"},
            json={"duration_hours": 4},
        )
        assert r.status_code == 422

    def test_authorize_success(self, api, monkeypatch):
        monkeypatch.setenv("REDGNAT_KILL_KEY", "kk")
        token = MagicMock()
        token.token_id = "tok-1"
        token.operator = "alice"
        from datetime import UTC, datetime

        token.expires_at = datetime(2026, 1, 1, tzinfo=UTC)
        token.remaining_seconds = 3600
        gate = MagicMock()
        gate.authorize.return_value = token
        monkeypatch.setattr("redgnat.engagement.gate.EngagementGate", lambda cfg: gate)
        r = api.post(
            "/api/v1/engage/authorize",
            headers={**AUTH, "X-Kill-Key": "kk"},
            json={"operator": "alice", "duration_hours": 4},
        )
        assert r.status_code == 200
        assert r.json()["token_id"] == "tok-1"

    def test_authorize_gate_denied_maps_to_403(self, api, monkeypatch):
        monkeypatch.setenv("REDGNAT_KILL_KEY", "kk")
        gate = MagicMock()
        gate.authorize.side_effect = RuntimeError("Gate 1 failed")
        monkeypatch.setattr("redgnat.engagement.gate.EngagementGate", lambda cfg: gate)
        r = api.post(
            "/api/v1/engage/authorize",
            headers={**AUTH, "X-Kill-Key": "kk"},
            json={"operator": "alice", "duration_hours": 4},
        )
        assert r.status_code == 403

    def test_revoke(self, api, monkeypatch):
        monkeypatch.setenv("REDGNAT_KILL_KEY", "kk")
        gate = MagicMock()
        monkeypatch.setattr("redgnat.engagement.gate.EngagementGate", lambda cfg: gate)
        r = api.request("DELETE", "/api/v1/engage/authorize", headers={**AUTH, "X-Kill-Key": "kk"})
        assert r.status_code == 200
        assert r.json()["revoked"] is True
        gate.revoke_token.assert_called_once()

    def test_revoke_wrong_kill_key(self, api, monkeypatch):
        monkeypatch.setenv("REDGNAT_KILL_KEY", "kk")
        r = api.request(
            "DELETE", "/api/v1/engage/authorize", headers={**AUTH, "X-Kill-Key": "wrong"}
        )
        assert r.status_code == 403


class TestKillSwitchRoutes:
    def test_activate_kill(self, api, monkeypatch):
        monkeypatch.delenv("REDGNAT_KILL_KEY", raising=False)
        ks = MagicMock()
        ks.activate.return_value = {"steps": {"redis": "ok"}}
        monkeypatch.setattr("redgnat.engagement.kill_switch.KillSwitch", lambda cfg: ks)
        r = api.post("/api/v1/engage/kill", headers=AUTH, json={"reason": "drill"})
        assert r.status_code == 200
        ks.activate.assert_called_once()

    def test_reset_kill(self, api, monkeypatch):
        monkeypatch.delenv("REDGNAT_KILL_KEY", raising=False)
        ks = MagicMock()
        monkeypatch.setattr("redgnat.engagement.kill_switch.KillSwitch", lambda cfg: ks)
        r = api.request("DELETE", "/api/v1/engage/kill", headers=AUTH, json={})
        assert r.status_code == 200
        assert r.json()["reset"] is True
