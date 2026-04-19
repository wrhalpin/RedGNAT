"""Unit tests for EngagementToken."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from redgnat.engagement.token import EngagementToken, _REDIS_KEY


class TestEngagementTokenCreate:
    def test_create_sets_operator_and_duration(self):
        token = EngagementToken.create(operator="alice", duration_hours=4.0)
        assert token.operator == "alice"
        remaining = token.remaining_seconds
        assert 4 * 3600 - 5 <= remaining <= 4 * 3600

    def test_create_generates_unique_ids(self):
        t1 = EngagementToken.create("alice", 1.0)
        t2 = EngagementToken.create("bob", 1.0)
        assert t1.token_id != t2.token_id

    def test_is_valid_fresh_token(self):
        token = EngagementToken.create("alice", 1.0)
        assert token.is_valid is True

    def test_is_valid_expired_token(self):
        token = EngagementToken.create("alice", 1.0)
        token.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert token.is_valid is False

    def test_remaining_seconds_zero_for_expired(self):
        token = EngagementToken.create("alice", 1.0)
        token.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        assert token.remaining_seconds == 0.0


class TestEngagementTokenSerialization:
    def test_round_trip(self):
        original = EngagementToken.create("carol", 2.0)
        restored = EngagementToken.from_dict(original.to_dict())
        assert restored.token_id == original.token_id
        assert restored.operator == original.operator
        assert abs((restored.expires_at - original.expires_at).total_seconds()) < 1


class TestEngagementTokenRedis:
    def _mock_redis(self):
        return MagicMock()

    def test_store_calls_setex(self):
        token = EngagementToken.create("dave", 1.0)
        r = self._mock_redis()
        token.store(r)
        r.setex.assert_called_once()
        key, ttl, payload = r.setex.call_args[0]
        assert key == _REDIS_KEY
        assert ttl > 0
        data = json.loads(payload)
        assert data["operator"] == "dave"

    def test_load_returns_none_when_missing(self):
        r = self._mock_redis()
        r.get.return_value = None
        assert EngagementToken.load(r) is None

    def test_load_returns_token_when_present(self):
        token = EngagementToken.create("eve", 2.0)
        r = self._mock_redis()
        r.get.return_value = json.dumps(token.to_dict()).encode()
        loaded = EngagementToken.load(r)
        assert loaded is not None
        assert loaded.token_id == token.token_id
        assert loaded.operator == "eve"

    def test_load_returns_none_on_corrupt_data(self):
        r = self._mock_redis()
        r.get.return_value = b"not-json"
        assert EngagementToken.load(r) is None

    def test_revoke_deletes_key(self):
        r = self._mock_redis()
        EngagementToken.revoke(r)
        r.delete.assert_called_once_with(_REDIS_KEY)
