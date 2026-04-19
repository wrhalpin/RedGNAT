"""Unit tests for KillSwitch."""
from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from redgnat.engagement.kill_switch import (
    KillSwitch,
    _REDIS_KEY_ACTIVE,
    _REDIS_KEY_OPERATOR,
    _REDIS_KEY_REASON,
    _REDIS_KEY_TS,
)


def _mock_config() -> MagicMock:
    cfg = MagicMock()
    cfg.redis_url = "redis://localhost:6379/0"
    cfg.db_url = "postgresql://localhost/test"
    cfg.gophish_base_url = ""
    cfg.gophish_api_key = ""
    cfg.gnat_config_path = None
    return cfg


def _make_ks(config=None):
    return KillSwitch(config or _mock_config())


class TestKillSwitchIsActive:
    def test_returns_true_when_redis_flag_set(self):
        ks = _make_ks()
        mock_redis = MagicMock()
        mock_redis.get.return_value = b"1"
        with patch.object(ks, "_redis", return_value=mock_redis):
            assert ks.is_active() is True

    def test_returns_false_when_no_flag(self):
        ks = _make_ks()
        mock_redis = MagicMock()
        mock_redis.get.return_value = None
        with patch.object(ks, "_redis", return_value=mock_redis):
            assert ks.is_active() is False

    def test_falls_back_to_postgres_when_redis_unavailable(self):
        ks = _make_ks()
        with patch.object(ks, "_redis", side_effect=ConnectionError("down")):
            with patch.object(ks, "_postgres_is_active", return_value=True) as pg:
                result = ks.is_active()
        assert result is True
        pg.assert_called_once()


class TestKillSwitchActivate:
    def test_sets_redis_keys(self):
        ks = _make_ks()
        mock_redis = MagicMock()
        with patch.object(ks, "_redis", return_value=mock_redis):
            with patch.object(ks, "_postgres_record"):
                with patch.object(ks, "_close_gophish_campaigns", return_value=0):
                    with patch.object(ks, "_notify_gnat"):
                        report = ks.activate(reason="test", operator="alice")

        set_calls = {c[0][0]: c[0][1] for c in mock_redis.set.call_args_list}
        assert set_calls[_REDIS_KEY_ACTIVE] == "1"
        assert set_calls[_REDIS_KEY_REASON] == "test"
        assert set_calls[_REDIS_KEY_OPERATOR] == "alice"

    def test_activate_returns_report_with_steps(self):
        ks = _make_ks()
        mock_redis = MagicMock()
        with patch.object(ks, "_redis", return_value=mock_redis):
            with patch.object(ks, "_postgres_record"):
                with patch.object(ks, "_close_gophish_campaigns", return_value=2):
                    with patch.object(ks, "_notify_gnat"):
                        report = ks.activate(reason="drill", operator="bob")

        assert report["steps"]["redis"] == "ok"
        assert report["steps"]["postgres"] == "ok"
        assert "2" in report["steps"]["gophish"]

    def test_redis_failure_still_records_postgres(self):
        ks = _make_ks()
        with patch.object(ks, "_redis", side_effect=ConnectionError("no redis")):
            with patch.object(ks, "_postgres_record") as pg:
                with patch.object(ks, "_close_gophish_campaigns", return_value=0):
                    with patch.object(ks, "_notify_gnat"):
                        report = ks.activate()
        assert "FAILED" in report["steps"]["redis"]
        pg.assert_called_once()

    def test_gnat_notification_failure_non_fatal(self):
        ks = _make_ks()
        mock_redis = MagicMock()
        with patch.object(ks, "_redis", return_value=mock_redis):
            with patch.object(ks, "_postgres_record"):
                with patch.object(ks, "_close_gophish_campaigns", return_value=0):
                    with patch.object(ks, "_notify_gnat", side_effect=RuntimeError("gnat down")):
                        report = ks.activate()
        assert "error" in report["steps"]["gnat_notify"]
        assert report["steps"]["redis"] == "ok"


class TestKillSwitchReset:
    def test_reset_clears_redis_keys(self):
        ks = _make_ks()
        mock_redis = MagicMock()
        with patch.object(ks, "_redis", return_value=mock_redis):
            with patch.object(ks, "_postgres_clear"):
                ks.reset(operator="carol")

        mock_redis.delete.assert_called_once_with(
            _REDIS_KEY_ACTIVE, _REDIS_KEY_REASON, _REDIS_KEY_OPERATOR, _REDIS_KEY_TS
        )

    def test_reset_calls_postgres_clear(self):
        ks = _make_ks()
        mock_redis = MagicMock()
        with patch.object(ks, "_redis", return_value=mock_redis):
            with patch.object(ks, "_postgres_clear") as pg:
                ks.reset(operator="carol")
        pg.assert_called_once_with(cleared_by="carol")


class TestKillSwitchStatus:
    def test_status_returns_inactive_when_no_flag(self):
        ks = _make_ks()
        mock_redis = MagicMock()
        mock_redis.get.return_value = None
        with patch.object(ks, "_redis", return_value=mock_redis):
            result = ks.status()
        assert result == {"active": False}

    def test_status_returns_active_details(self):
        ks = _make_ks()
        mock_redis = MagicMock()

        def fake_get(key):
            return {
                _REDIS_KEY_ACTIVE: b"1",
                _REDIS_KEY_REASON: b"drill",
                _REDIS_KEY_OPERATOR: b"alice",
                _REDIS_KEY_TS: b"2026-01-01T00:00:00+00:00",
            }.get(key)

        mock_redis.get.side_effect = fake_get
        with patch.object(ks, "_redis", return_value=mock_redis):
            result = ks.status()

        assert result["active"] is True
        assert result["reason"] == "drill"
        assert result["operator"] == "alice"


class TestCloseGoPhishCampaigns:
    def test_skips_when_no_gophish_configured(self):
        ks = _make_ks()
        assert ks._close_gophish_campaigns() == 0

    def test_closes_active_campaigns(self):
        cfg = _mock_config()
        cfg.gophish_base_url = "https://gophish.test"
        cfg.gophish_api_key = "key"
        ks = KillSwitch(cfg)

        mock_client = MagicMock()
        mock_client.list_campaigns.return_value = [
            {"id": 1, "status": "In progress"},
            {"id": 2, "status": "Completed"},
            {"id": 3, "status": "Queued"},
        ]

        with patch("redgnat.techniques.phishing.base.GoPhishClient", return_value=mock_client):
            count = ks._close_gophish_campaigns()

        assert count == 2
        assert mock_client.complete_campaign.call_count == 2
