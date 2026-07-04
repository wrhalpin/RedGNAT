# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Regression tests for Batch E completeness fixes."""
from __future__ import annotations

from redgnat.scenarios.ttp_mapper import TTPMapper
from redgnat.techniques.identity.token_theft import _minutes_apart, _IMPOSSIBLE_TRAVEL_MINUTES


class TestMapperParentFallback:
    def test_subtechnique_name_falls_back_to_parent(self):
        m = TTPMapper()
        # T1110 is in the map; a hypothetical unmapped sub-id resolves via parent
        parent_name = m.technique_name("T1110")
        assert m.technique_name("T1110.999") == parent_name
        assert m.technique_name("T1110.999") != "T1110.999"

    def test_subtechnique_tactic_falls_back_to_parent(self):
        m = TTPMapper()
        assert m.technique_tactic("T1110.999") == m.technique_tactic("T1110")


class TestImpossibleTravelWindow:
    def test_close_events_within_window(self):
        mins = _minutes_apart("2026-01-01T00:00:00Z", "2026-01-01T00:30:00Z")
        assert mins == 30.0
        assert mins <= _IMPOSSIBLE_TRAVEL_MINUTES

    def test_far_apart_events_exceed_window(self):
        mins = _minutes_apart("2026-01-01T00:00:00Z", "2026-01-01T05:00:00Z")
        assert mins == 300.0
        assert mins > _IMPOSSIBLE_TRAVEL_MINUTES

    def test_unparseable_returns_none(self):
        assert _minutes_apart("", "2026-01-01T00:00:00Z") is None
        assert _minutes_apart("bogus", "also-bogus") is None
