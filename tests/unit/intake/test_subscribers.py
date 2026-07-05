# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Subscriber poll() tests with network access mocked at the boundary."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from redgnat.config import RedGNATConfig
from redgnat.intake.gnat_subscriber import GNATSubscriber
from redgnat.intake.sandgnat_subscriber import SandGNATSubscriber


def _cfg(**over):
    ini = "/nonexistent.ini"
    cfg = RedGNATConfig(path=ini)
    return cfg


def _attack_pattern(ext_id):
    return SimpleNamespace(
        external_references=[{"source_name": "mitre-attack", "external_id": ext_id}]
    )


class TestGNATSubscriber:
    def _client(self, campaigns, patterns):
        client = MagicMock()

        def list_objects(kind, **kw):
            if kind == "campaign":
                return campaigns
            return patterns

        client.list_objects.side_effect = list_objects
        return client

    def test_poll_yields_feed(self):
        sub = GNATSubscriber(_cfg())
        campaign = SimpleNamespace(
            id="c1",
            name="Camp",
            confidence=90,
            to_dict=lambda: {"type": "campaign", "id": "c1"},
        )
        client = self._client([campaign], [_attack_pattern("T1046")])
        with patch.object(sub, "_get_client", return_value=client):
            feeds = list(sub.poll())
        assert len(feeds) == 1
        assert feeds[0].attack_pattern_ids == ["T1046"]
        assert feeds[0].source_ref_id == "c1"
        # deterministic feed_id
        assert feeds[0].feed_id

    def test_low_confidence_skipped(self):
        sub = GNATSubscriber(_cfg())
        campaign = SimpleNamespace(id="c1", name="Camp", confidence=10)
        client = self._client([campaign], [_attack_pattern("T1046")])
        with patch.object(sub, "_get_client", return_value=client):
            assert list(sub.poll()) == []

    def test_no_attack_patterns_skipped(self):
        sub = GNATSubscriber(_cfg())
        campaign = SimpleNamespace(id="c1", name="Camp", confidence=90)
        client = self._client([campaign], [])
        with patch.object(sub, "_get_client", return_value=client):
            assert list(sub.poll()) == []

    def test_list_error_returns_empty(self):
        sub = GNATSubscriber(_cfg())
        client = MagicMock()
        client.list_objects.side_effect = RuntimeError("gnat down")
        with patch.object(sub, "_get_client", return_value=client):
            assert list(sub.poll()) == []

    def test_health_check(self):
        sub = GNATSubscriber(_cfg())
        client = MagicMock()
        with patch.object(sub, "_get_client", return_value=client):
            assert sub.health_check() is True
        client.list_objects.side_effect = RuntimeError("x")
        with patch.object(sub, "_get_client", return_value=client):
            assert sub.health_check() is False


class TestSandGNATSubscriber:
    def test_poll_yields_feed(self):
        sub = SandGNATSubscriber(_cfg())
        analyses = [{"analysis_id": "a1", "severity": "high", "sample_name": "evil.exe"}]
        bundle = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1046"}
                    ],
                }
            ]
        }

        def fake_get(path):
            return analyses if path == "/analyses" else bundle

        with patch.object(sub, "_get", side_effect=fake_get):
            feeds = list(sub.poll())
        assert len(feeds) == 1
        assert "T1046" in feeds[0].attack_pattern_ids
        assert feeds[0].confidence == 0.8

    def test_low_severity_skipped(self):
        sub = SandGNATSubscriber(_cfg())
        # default min_severity is 'medium' -> rank 1; 'low' rank 0 skipped
        analyses = [{"analysis_id": "a1", "severity": "low"}]
        with patch.object(sub, "_get", side_effect=lambda p: analyses):
            assert list(sub.poll()) == []

    def test_list_error_returns_empty(self):
        sub = SandGNATSubscriber(_cfg())
        with patch.object(sub, "_get", side_effect=RuntimeError("down")):
            assert list(sub.poll()) == []

    def test_health_check(self):
        sub = SandGNATSubscriber(_cfg())
        with patch.object(sub, "_get", return_value={}):
            assert sub.health_check() is True
        with patch.object(sub, "_get", side_effect=RuntimeError("x")):
            assert sub.health_check() is False
