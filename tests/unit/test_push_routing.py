# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests — Phase 3.1: Gap report push routing based on investigation context."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from redgnat.feedback.gap_reporter import GapReport, GapReporter
from redgnat.orm.models import ResultStatus, TechniqueResult


def _make_gap_result() -> TechniqueResult:
    return TechniqueResult(
        run_id="run-001",
        scenario_id="scen-001",
        feed_id="feed-001",
        technique_id="T1046",
        tactic="discovery",
        status=ResultStatus.SUCCESS,
    )


def _make_report(**kwargs) -> GapReport:
    return GapReport(
        run_id="run-001",
        scenario_id="scen-001",
        gaps=[_make_gap_result()],
        **kwargs,
    )


def _make_config(gnat_api_base_url="", gnat_config_path=None):
    cfg = MagicMock()
    cfg.gnat_api_base_url = gnat_api_base_url
    cfg.gnat_api_key = "test-key"
    cfg.gnat_config_path = gnat_config_path
    return cfg


class TestPushRouting:
    def test_no_investigation_uses_gnat_client(self):
        report = _make_report()
        config = _make_config()
        reporter = GapReporter(config)
        with patch.object(reporter, "_push_via_gnat_client", return_value=True) as mock_gnat, \
             patch.object(reporter, "_push_to_investigation") as mock_inv:
            result = reporter.push_to_gnat(report)
        mock_gnat.assert_called_once()
        mock_inv.assert_not_called()
        assert result is True

    def test_investigation_id_with_api_url_uses_evidence_endpoint(self):
        report = _make_report(investigation_id="IC-2026-0001")
        config = _make_config(gnat_api_base_url="http://gnat.test:8000")
        reporter = GapReporter(config)
        with patch.object(reporter, "_push_to_investigation", return_value=True) as mock_inv, \
             patch.object(reporter, "_push_via_gnat_client") as mock_gnat:
            result = reporter.push_to_gnat(report)
        mock_inv.assert_called_once()
        mock_gnat.assert_not_called()
        assert result is True

    def test_investigation_id_without_api_url_falls_back_to_gnat_client(self):
        """If gnat_api_base_url is not configured, fall back to GNATClient path."""
        report = _make_report(investigation_id="IC-2026-0001")
        config = _make_config(gnat_api_base_url="")  # not configured
        reporter = GapReporter(config)
        with patch.object(reporter, "_push_via_gnat_client", return_value=True) as mock_gnat, \
             patch.object(reporter, "_push_to_investigation") as mock_inv:
            result = reporter.push_to_gnat(report)
        mock_gnat.assert_called_once()
        mock_inv.assert_not_called()

    def test_empty_gaps_returns_true_without_push(self):
        report = GapReport(run_id="run-001", scenario_id="scen-001", gaps=[])
        config = _make_config()
        reporter = GapReporter(config)
        with patch.object(reporter, "_push_via_gnat_client") as mock_gnat, \
             patch.object(reporter, "_push_to_investigation") as mock_inv:
            result = reporter.push_to_gnat(report)
        mock_gnat.assert_not_called()
        mock_inv.assert_not_called()
        assert result is True
