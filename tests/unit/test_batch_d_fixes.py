# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Regression tests for Batch D STIX/feedback correctness fixes."""

from __future__ import annotations

from redgnat.emulation.tasks import _parse_probe_depth
from redgnat.feedback.probe_generator import ProbeRequest
from redgnat.orm.base import deterministic_id


class TestDeterministicId:
    def test_same_inputs_same_id(self):
        assert deterministic_id("gnat", "campaign-1") == deterministic_id("gnat", "campaign-1")

    def test_different_inputs_differ(self):
        assert deterministic_id("gnat", "a") != deterministic_id("gnat", "b")

    def test_is_valid_uuid(self):
        import uuid

        assert uuid.UUID(deterministic_id("scenario", "feed-1"))


class TestProbeDepthParsing:
    def test_root_run_is_depth_zero(self):
        assert _parse_probe_depth("manual") == 0
        assert _parse_probe_depth("intel_event") == 0
        assert _parse_probe_depth("") == 0

    def test_probe_depth_extracted(self):
        assert _parse_probe_depth("probe:abc-123:d2") == 2

    def test_malformed_depth_is_zero(self):
        assert _parse_probe_depth("probe:abc:dX") == 0


class TestProbeRequestDepth:
    def test_depth_round_trips(self):
        p = ProbeRequest(technique_id="T1621", depth=2)
        assert ProbeRequest.from_dict(p.to_dict()).depth == 2

    def test_default_depth_zero(self):
        assert ProbeRequest(technique_id="T1046").depth == 0
