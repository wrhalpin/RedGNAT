# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests — Phase 2.1: STIX investigation context stamping."""
from __future__ import annotations

import pytest

from redgnat.feedback.investigation_context import apply_investigation_context

INV_ID = "IC-2026-0001"
HYP_ID = "HYP-2026-0001-01"


class TestApplyInvestigationContext:
    def test_three_props_without_hypothesis(self):
        obj: dict = {"type": "note", "id": "note--abc"}
        apply_investigation_context(obj, INV_ID)
        assert obj["x_gnat_investigation_id"] == INV_ID
        assert obj["x_gnat_investigation_origin"] == "redgnat"
        assert obj["x_gnat_investigation_link_type"] == "confirmed"
        assert "x_gnat_hypothesis_id" not in obj

    def test_four_props_with_hypothesis(self):
        obj: dict = {"type": "note", "id": "note--abc"}
        apply_investigation_context(obj, INV_ID, hypothesis_id=HYP_ID)
        assert obj["x_gnat_investigation_id"] == INV_ID
        assert obj["x_gnat_hypothesis_id"] == HYP_ID
        assert obj["x_gnat_investigation_link_type"] == "confirmed"

    def test_link_type_inferred(self):
        obj: dict = {}
        apply_investigation_context(obj, INV_ID, link_type="inferred")
        assert obj["x_gnat_investigation_link_type"] == "inferred"

    def test_returns_same_object(self):
        obj: dict = {"type": "sighting"}
        result = apply_investigation_context(obj, INV_ID)
        assert result is obj

    def test_no_hypothesis_key_when_none(self):
        obj: dict = {}
        apply_investigation_context(obj, INV_ID, hypothesis_id=None)
        assert "x_gnat_hypothesis_id" not in obj


class TestGapReportStixStamping:
    """Gap Note gets stamped when investigation context is present."""

    def _make_report(self, investigation_id=None, hypothesis_id=None):
        from datetime import datetime, timezone
        from unittest.mock import MagicMock

        from redgnat.feedback.gap_reporter import GapReport
        from redgnat.orm.models import ResultStatus, TechniqueResult

        result = TechniqueResult(
            run_id="run-001",
            scenario_id="scen-001",
            feed_id="feed-001",
            technique_id="T1046",
            tactic="discovery",
            status=ResultStatus.SUCCESS,
        )
        return GapReport(
            run_id="run-001",
            scenario_id="scen-001",
            gaps=[result],
            investigation_id=investigation_id,
            hypothesis_id=hypothesis_id,
        )

    def test_note_stamped_with_investigation_id(self):
        report = self._make_report(investigation_id=INV_ID)
        note = report.to_stix_note()
        assert note["x_gnat_investigation_id"] == INV_ID
        assert note["x_gnat_investigation_origin"] == "redgnat"
        assert "x_gnat_hypothesis_id" not in note

    def test_note_stamped_with_hypothesis(self):
        report = self._make_report(investigation_id=INV_ID, hypothesis_id=HYP_ID)
        note = report.to_stix_note()
        assert note["x_gnat_hypothesis_id"] == HYP_ID

    def test_note_not_stamped_without_investigation(self):
        report = self._make_report()
        note = report.to_stix_note()
        assert "x_gnat_investigation_id" not in note
        assert "x_gnat_investigation_origin" not in note
