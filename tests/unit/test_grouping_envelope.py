# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests — Phase 2.3: STIX Grouping envelope for investigation-scoped runs."""
from __future__ import annotations

import pytest

from redgnat.feedback.investigation_context import build_grouping

RUN_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
INV_ID = "IC-2026-0001"
HYP_ID = "HYP-2026-0001-01"
REFS = [
    f"course-of-action--{RUN_ID}",
    "sighting--11111111-2222-3333-4444-555555555555",
    "note--66666666-7777-8888-9999-aaaaaaaaaaaa",
]


class TestBuildGrouping:
    def test_grouping_type_and_spec(self):
        g = build_grouping(RUN_ID, INV_ID, REFS)
        assert g["type"] == "grouping"
        assert g["spec_version"] == "2.1"

    def test_grouping_id_deterministic(self):
        g = build_grouping(RUN_ID, INV_ID, REFS)
        assert g["id"] == f"grouping--{RUN_ID}"

    def test_grouping_name_contains_run_id(self):
        g = build_grouping(RUN_ID, INV_ID, REFS)
        assert RUN_ID in g["name"]

    def test_object_refs_preserved(self):
        g = build_grouping(RUN_ID, INV_ID, REFS)
        assert g["object_refs"] == REFS

    def test_investigation_props_present(self):
        g = build_grouping(RUN_ID, INV_ID, REFS)
        assert g["x_gnat_investigation_id"] == INV_ID
        assert g["x_gnat_investigation_origin"] == "redgnat"
        assert g["x_gnat_investigation_link_type"] == "confirmed"

    def test_hypothesis_id_included_when_set(self):
        g = build_grouping(RUN_ID, INV_ID, REFS, hypothesis_id=HYP_ID)
        assert g["x_gnat_hypothesis_id"] == HYP_ID

    def test_hypothesis_id_absent_when_not_set(self):
        g = build_grouping(RUN_ID, INV_ID, REFS)
        assert "x_gnat_hypothesis_id" not in g

    def test_context_field(self):
        g = build_grouping(RUN_ID, INV_ID, REFS)
        assert g["context"] == "suspicious-activity"

    def test_created_and_modified_equal(self):
        g = build_grouping(RUN_ID, INV_ID, REFS)
        assert g["created"] == g["modified"]
