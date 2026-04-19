"""Unit tests for EngagementGate."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from redgnat.engagement.gate import EngagementGate, _UNLOCK_ENV_VAR
from redgnat.engagement.token import EngagementToken


def _mock_config(phase2_enabled: bool = True) -> MagicMock:
    cfg = MagicMock()
    cfg.phase2_enabled = phase2_enabled
    cfg.redis_url = "redis://localhost:6379/0"
    return cfg


def _valid_token() -> EngagementToken:
    return EngagementToken.create(operator="test-op", duration_hours=4.0)


def _expired_token() -> EngagementToken:
    t = EngagementToken.create(operator="test-op", duration_hours=1.0)
    t.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
    return t


class TestEngagementGateCheck:
    def test_gate1_fails_when_phase2_disabled(self):
        gate = EngagementGate(_mock_config(phase2_enabled=False))
        authorized, reason = gate.check()
        assert authorized is False
        assert "Gate 1" in reason
        assert "phase2_enabled" in reason

    def test_gate2_fails_when_env_var_missing(self, monkeypatch):
        monkeypatch.delenv(_UNLOCK_ENV_VAR, raising=False)
        gate = EngagementGate(_mock_config())
        authorized, reason = gate.check()
        assert authorized is False
        assert "Gate 2" in reason
        assert _UNLOCK_ENV_VAR in reason

    def test_gate3_fails_when_no_token(self, monkeypatch):
        monkeypatch.setenv(_UNLOCK_ENV_VAR, "unlocked")
        gate = EngagementGate(_mock_config())
        mock_redis = MagicMock()
        mock_redis.get.return_value = None
        with patch.object(gate, "_redis", return_value=mock_redis):
            authorized, reason = gate.check()
        assert authorized is False
        assert "Gate 3" in reason
        assert "no active engagement token" in reason

    def test_gate3_fails_when_token_expired(self, monkeypatch):
        monkeypatch.setenv(_UNLOCK_ENV_VAR, "unlocked")
        gate = EngagementGate(_mock_config())
        mock_redis = MagicMock()
        import json
        mock_redis.get.return_value = json.dumps(_expired_token().to_dict()).encode()
        with patch.object(gate, "_redis", return_value=mock_redis):
            authorized, reason = gate.check()
        assert authorized is False
        assert "Gate 3" in reason
        assert "expired" in reason

    def test_all_gates_pass(self, monkeypatch):
        monkeypatch.setenv(_UNLOCK_ENV_VAR, "unlocked")
        gate = EngagementGate(_mock_config())
        mock_redis = MagicMock()
        import json
        mock_redis.get.return_value = json.dumps(_valid_token().to_dict()).encode()
        with patch.object(gate, "_redis", return_value=mock_redis):
            authorized, reason = gate.check()
        assert authorized is True
        assert "All gates passed" in reason

    def test_gate3_fails_on_redis_error(self, monkeypatch):
        monkeypatch.setenv(_UNLOCK_ENV_VAR, "unlocked")
        gate = EngagementGate(_mock_config())
        with patch.object(gate, "_redis", side_effect=ConnectionError("no redis")):
            authorized, reason = gate.check()
        assert authorized is False
        assert "Gate 3" in reason


class TestEngagementGateAuthorize:
    def test_authorize_fails_gate1(self):
        gate = EngagementGate(_mock_config(phase2_enabled=False))
        with pytest.raises(RuntimeError, match="phase2_enabled"):
            gate.authorize("alice", 2.0)

    def test_authorize_fails_gate2(self, monkeypatch):
        monkeypatch.delenv(_UNLOCK_ENV_VAR, raising=False)
        gate = EngagementGate(_mock_config())
        with pytest.raises(RuntimeError, match=_UNLOCK_ENV_VAR):
            gate.authorize("alice", 2.0)

    def test_authorize_rejects_duration_over_24h(self, monkeypatch):
        monkeypatch.setenv(_UNLOCK_ENV_VAR, "unlocked")
        gate = EngagementGate(_mock_config())
        mock_redis = MagicMock()
        with patch.object(gate, "_redis", return_value=mock_redis):
            with pytest.raises(ValueError, match="24"):
                gate.authorize("alice", 25.0)

    def test_authorize_stores_token(self, monkeypatch):
        monkeypatch.setenv(_UNLOCK_ENV_VAR, "unlocked")
        gate = EngagementGate(_mock_config())
        mock_redis = MagicMock()
        with patch.object(gate, "_redis", return_value=mock_redis):
            token = gate.authorize("alice", 2.0)
        assert token.operator == "alice"
        mock_redis.setex.assert_called_once()

    def test_revoke_token_calls_delete(self, monkeypatch):
        gate = EngagementGate(_mock_config())
        mock_redis = MagicMock()
        with patch.object(gate, "_redis", return_value=mock_redis):
            gate.revoke_token()
        mock_redis.delete.assert_called_once()


class TestEngagementGateStatus:
    def test_status_shape(self, monkeypatch):
        monkeypatch.delenv(_UNLOCK_ENV_VAR, raising=False)
        gate = EngagementGate(_mock_config(phase2_enabled=False))
        mock_redis = MagicMock()
        mock_redis.get.return_value = None
        with patch.object(gate, "_redis", return_value=mock_redis):
            result = gate.status()
        assert "phase2_authorized" in result
        assert "gates" in result
        assert "kill_switch" in result
        assert result["gates"]["config_flag"] is False
        assert result["gates"]["unlock_env_set"] is False
