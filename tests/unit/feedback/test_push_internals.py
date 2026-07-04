# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for the gap-reporter push internals (evidence push + 409 reopen)."""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

from redgnat.feedback.gap_reporter import GapReport, GapReporter
from redgnat.orm.models import ResultStatus, TechniqueResult


def _report():
    gap = TechniqueResult(
        run_id="r1", scenario_id="s1", technique_id="T1046",
        tactic="discovery", status=ResultStatus.SUCCESS, findings=[{"open_ports": [80]}],
    )
    return GapReport(
        gap_id="gap-r1", run_id="r1", scenario_id="s1", gaps=[gap],
        investigation_id="IC-1", hypothesis_id="HYP-1", all_results=[gap],
    )


def _reporter():
    cfg = MagicMock()
    cfg.gnat_api_base_url = "http://gnat.test:8000"
    cfg.gnat_api_key = "k"
    cfg.gnat_config_path = None
    return GapReporter(cfg)


class TestPushToInvestigation:
    def test_success(self):
        reporter = _reporter()
        with patch(
            "redgnat.feedback.investigation_context.push_investigation_bundle",
            return_value=(True, None),
        ) as push:
            ok = reporter.push_to_gnat(_report())
        assert ok is True
        # single push, no reopen retry
        assert push.call_count == 1

    def test_409_triggers_reopen_retry(self):
        reporter = _reporter()
        with patch(
            "redgnat.feedback.investigation_context.push_investigation_bundle",
            side_effect=[(False, "conflict"), (True, None)],
        ) as push:
            ok = reporter.push_to_gnat(_report())
        assert ok is True
        assert push.call_count == 2
        # the retry sets reopen=True
        assert push.call_args_list[1].kwargs.get("reopen") is True

    def test_terminal_failure_returns_false(self):
        reporter = _reporter()
        with patch(
            "redgnat.feedback.investigation_context.push_investigation_bundle",
            return_value=(False, "forbidden"),
        ):
            ok = reporter.push_to_gnat(_report())
        assert ok is False


class TestPushViaGnatClient:
    def _non_investigation_report(self):
        rep = _report()
        rep.investigation_id = None
        return rep

    def test_gnat_not_installed_returns_false(self):
        reporter = _reporter()
        reporter.config.gnat_api_base_url = ""  # force GNATClient path
        # gnat is not installed -> ImportError branch
        sys.modules.pop("gnat", None)
        ok = reporter.push_to_gnat(self._non_investigation_report())
        assert ok is False

    def test_gnat_client_success(self):
        reporter = _reporter()
        reporter.config.gnat_api_base_url = ""
        fake_gnat = MagicMock()
        fake_client = MagicMock()
        fake_gnat.GNATClient.return_value = fake_client
        with patch.dict(sys.modules, {"gnat": fake_gnat}):
            ok = reporter.push_to_gnat(self._non_investigation_report())
        assert ok is True
        fake_client.upsert_object.assert_called_once()

    def test_gnat_client_error_returns_false(self):
        reporter = _reporter()
        reporter.config.gnat_api_base_url = ""
        fake_gnat = MagicMock()
        fake_gnat.GNATClient.return_value.upsert_object.side_effect = RuntimeError("boom")
        with patch.dict(sys.modules, {"gnat": fake_gnat}):
            ok = reporter.push_to_gnat(self._non_investigation_report())
        assert ok is False
