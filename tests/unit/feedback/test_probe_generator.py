# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Unit tests for ProbeGenerator (rule-based path only — no LLM required)."""
from __future__ import annotations

import json
import pytest

from redgnat.feedback.gap_reporter import GapReport
from redgnat.feedback.probe_generator import ProbeGenerator, ProbeRequest
from redgnat.orm.models import ResultStatus, TechniqueResult


def _make_gap(technique_id: str, tactic: str) -> TechniqueResult:
    return TechniqueResult(
        run_id="run-1",
        scenario_id="s-1",
        feed_id="f-1",
        technique_id=technique_id,
        tactic=tactic,
        status=ResultStatus.SUCCESS,
    )


def _report(*gaps: TechniqueResult) -> GapReport:
    return GapReport(run_id="run-1", scenario_id="s-1", gaps=list(gaps))


class TestProbeRequest:
    def test_round_trip(self):
        p = ProbeRequest(
            source_gap_id="g-1",
            source_run_id="r-1",
            technique_id="T1046",
            priority="high",
            rationale="test",
        )
        restored = ProbeRequest.from_dict(p.to_dict())
        assert restored.probe_id == p.probe_id
        assert restored.technique_id == "T1046"
        assert restored.priority == "high"

    def test_to_stix_task(self):
        p = ProbeRequest(
            source_gap_id="g-1",
            source_run_id="r-1",
            technique_id="T1110.003",
            priority="critical",
            rationale="spray went undetected",
        )
        task = p.to_stix_task()
        assert task["type"] == "note"
        assert "T1110.003" in task["content"]
        assert task["x_redgnat_probe"]["priority"] == "critical"


class TestProbeGeneratorRuleBased:
    """Tests use the rule-based fallback path (no LLM dependency)."""

    def _gen(self) -> ProbeGenerator:
        # Pass a config-like object that will cause LLM import to fail,
        # triggering the rule-based fallback
        class _FakeConfig:
            gnat_config_path = None
        return ProbeGenerator(_FakeConfig(), max_probes=10)

    def test_no_gaps_returns_empty(self):
        gen = self._gen()
        assert gen.generate(_report()) == []

    def test_network_scan_produces_probes(self):
        gen = self._gen()
        probes = gen.generate(_report(_make_gap("T1046", "discovery")))
        assert len(probes) > 0
        tids = [p.technique_id for p in probes]
        assert "T1595" in tids or "T1087" in tids

    def test_password_spray_produces_critical_probe(self):
        gen = self._gen()
        probes = gen.generate(_report(_make_gap("T1110.003", "credential-access")))
        critical = [p for p in probes if p.priority == "critical"]
        assert len(critical) > 0

    def test_deduplication(self):
        gen = self._gen()
        # Both T1087 and T1069 suggest T1482; should only appear once
        report = _report(
            _make_gap("T1087", "discovery"),
            _make_gap("T1069", "discovery"),
        )
        probes = gen.generate(report)
        tids = [p.technique_id for p in probes]
        assert tids.count("T1482") <= 1

    def test_max_probes_respected(self):
        gen = ProbeGenerator(object(), max_probes=2)
        report = _report(
            _make_gap("T1046", "discovery"),
            _make_gap("T1087", "discovery"),
            _make_gap("T1566.002", "initial-access"),
            _make_gap("T1110.003", "credential-access"),
        )
        probes = gen.generate(report)
        assert len(probes) <= 2

    def test_source_ids_set_correctly(self):
        gen = self._gen()
        report = _report(_make_gap("T1046", "discovery"))
        probes = gen.generate(report)
        for p in probes:
            assert p.source_gap_id == report.gap_id
            assert p.source_run_id == report.run_id

    def test_llm_json_parse_clean(self):
        raw = json.dumps([
            {"technique_id": "T1046", "rationale": "test", "priority": "high", "suggested_params": {}},
        ])
        result = ProbeGenerator._parse_llm_response(raw)
        assert len(result) == 1
        assert result[0]["technique_id"] == "T1046"

    def test_llm_json_parse_strips_fences(self):
        raw = "```json\n[{\"technique_id\": \"T1046\", \"rationale\": \"r\", \"priority\": \"high\", \"suggested_params\": {}}]\n```"
        result = ProbeGenerator._parse_llm_response(raw)
        assert len(result) == 1

    def test_llm_json_parse_invalid_returns_empty(self):
        result = ProbeGenerator._parse_llm_response("not json at all")
        assert result == []
