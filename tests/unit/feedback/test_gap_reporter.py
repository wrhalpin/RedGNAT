# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Unit tests for GapReporter and GapReport."""
from __future__ import annotations

import pytest

from redgnat.feedback.gap_reporter import GapReport, GapReporter
from redgnat.orm.models import ResultStatus, TechniqueResult


def _make_result(technique_id: str, tactic: str, status: ResultStatus, **kwargs) -> TechniqueResult:
    return TechniqueResult(
        run_id="run-1",
        scenario_id="s-1",
        feed_id="f-1",
        technique_id=technique_id,
        tactic=tactic,
        status=status,
        findings=kwargs.get("findings", []),
    )


class TestGapReport:
    def test_undetected_technique_ids(self):
        gaps = [
            _make_result("T1046", "discovery", ResultStatus.SUCCESS),
            _make_result("T1566.002", "initial-access", ResultStatus.SUCCESS),
        ]
        report = GapReport(run_id="r1", scenario_id="s1", gaps=gaps)
        assert set(report.undetected_technique_ids) == {"T1046", "T1566.002"}

    def test_is_critical_true(self):
        gaps = [_make_result("T1110.003", "credential-access", ResultStatus.SUCCESS)]
        report = GapReport(run_id="r1", scenario_id="s1", gaps=gaps)
        assert report.is_critical is True

    def test_is_critical_false(self):
        gaps = [_make_result("T1046", "discovery", ResultStatus.SUCCESS)]
        report = GapReport(run_id="r1", scenario_id="s1", gaps=gaps)
        assert report.is_critical is False

    def test_to_stix_note_structure(self):
        gaps = [_make_result("T1046", "discovery", ResultStatus.SUCCESS)]
        report = GapReport(run_id="run-abc", scenario_id="s-xyz", gaps=gaps)
        note = report.to_stix_note()
        assert note["type"] == "note"
        assert note["spec_version"] == "2.1"
        assert note["id"].startswith("note--")
        assert "T1046" in note["content"]
        assert note["x_redgnat_gap"]["run_id"] == "run-abc"
        assert note["x_redgnat_gap"]["is_critical"] is False

    def test_to_stix_note_critical_label(self):
        gaps = [_make_result("T1110.003", "credential-access", ResultStatus.SUCCESS)]
        report = GapReport(run_id="r1", scenario_id="s1", gaps=gaps)
        note = report.to_stix_note()
        assert "CRITICAL" in note["content"]

    def test_to_stix_note_intel_ask_included(self):
        gaps = [_make_result("T1110.003", "credential-access", ResultStatus.SUCCESS)]
        report = GapReport(run_id="r1", scenario_id="s1", gaps=gaps)
        note = report.to_stix_note()
        assert "Okta" in note["content"] or "Silverfort" in note["content"]

    def test_summarise_open_ports(self):
        findings = [{"host": "10.0.0.1", "open_ports": [{"port": 22}, {"port": 443}]}]
        gaps = [_make_result("T1046", "discovery", ResultStatus.SUCCESS, findings=findings)]
        report = GapReport(run_id="r1", scenario_id="s1", gaps=gaps)
        note = report.to_stix_note()
        assert "2 open port" in note["content"]

    def test_no_gaps_empty_list(self):
        report = GapReport(run_id="r1", scenario_id="s1", gaps=[])
        assert report.undetected_technique_ids == []
        assert report.is_critical is False


class TestGapReporter:
    def test_build_report_filters_successes(self):
        results = [
            _make_result("T1046", "discovery", ResultStatus.SUCCESS),
            _make_result("T1566.002", "initial-access", ResultStatus.DETECTED),
            _make_result("T1110.003", "credential-access", ResultStatus.BLOCKED),
            _make_result("T1087", "discovery", ResultStatus.SUCCESS),
        ]
        reporter = GapReporter(config=None)
        report = reporter.build_report("run-1", "s-1", results)
        assert len(report.gaps) == 2
        tids = {r.technique_id for r in report.gaps}
        assert tids == {"T1046", "T1087"}

    def test_build_report_no_gaps(self):
        results = [_make_result("T1046", "discovery", ResultStatus.DETECTED)]
        reporter = GapReporter(config=None)
        report = reporter.build_report("run-1", "s-1", results)
        assert report.gaps == []

    def test_push_to_gnat_no_gaps_returns_true(self):
        reporter = GapReporter(config=None)
        report = GapReport(run_id="r1", scenario_id="s1", gaps=[])
        assert reporter.push_to_gnat(report) is True

    def test_push_to_gnat_import_error_returns_false(self):
        reporter = GapReporter(config=object())
        gaps = [_make_result("T1046", "discovery", ResultStatus.SUCCESS)]
        report = GapReport(run_id="r1", scenario_id="s1", gaps=gaps)
        # gnat is not installed in test env — should return False gracefully
        result = reporter.push_to_gnat(report)
        assert result is False
