"""
ProbeGenerator — uses GNAT's LLMClient to analyse gap reports and synthesise
follow-on ProbeRequests that are fed back into RedGNAT's intake pipeline.

This is the AI-driven half of the bidirectional GNAT↔RedGNAT feedback loop:

  GapReport (undetected techniques)
       │
       ▼
  ProbeGenerator.generate(report)
       │  calls gnat.agents.LLMClient (Claude backend)
       │  with gap context + GNAT enrichment hints
       │
       ▼
  list[ProbeRequest]
       │
       ▼
  POST /api/v1/intel/probe-request  (back into RedGNAT intake)

A ProbeRequest is a lightweight instruction to run one or more follow-on
techniques against specific targets, generated from AI analysis of which
defensive gaps are most actionable given the current threat context.
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from redgnat.feedback.gap_reporter import GapReport
from redgnat.scenarios.ttp_mapper import TTPMapper

logger = logging.getLogger(__name__)

_DEFAULT_PROBE_PROMPT = """\
You are a red team analyst reviewing an automated emulation gap report.
The following ATT&CK techniques executed successfully without triggering \
any detection alert in the target environment.

Gap report:
{gap_summary}

For each undetected technique, suggest 1-2 follow-on probe techniques \
that would deepen understanding of the defensive gap or test adjacent \
attack paths. Respond as a JSON array of objects with these fields:
  - "technique_id": ATT&CK ID (e.g. "T1046")
  - "rationale": one sentence explaining why this probe is valuable
  - "priority": "critical", "high", or "medium"
  - "suggested_params": object with any technique-specific parameters \
(e.g. {{"target_cidr": "10.0.0.0/8"}}); use {{}} if none

Return ONLY the JSON array — no markdown, no preamble.
"""


@dataclass
class ProbeRequest:
    """
    A follow-on emulation probe synthesised from a gap report.

    Parameters
    ----------
    probe_id : str
        Unique ID for this probe request.
    source_gap_id : str
        GapReport.gap_id that triggered this probe.
    source_run_id : str
        EmulationRun.run_id that produced the gap.
    technique_id : str
        ATT&CK technique to probe.
    priority : str
        "critical", "high", or "medium".
    rationale : str
        AI-generated explanation of why this probe is valuable.
    suggested_params : dict
        Optional technique parameters suggested by the AI.
    created_at : datetime
    """

    probe_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_gap_id: str = ""
    source_run_id: str = ""
    technique_id: str = ""
    priority: str = "high"
    rationale: str = ""
    suggested_params: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "source_gap_id": self.source_gap_id,
            "source_run_id": self.source_run_id,
            "technique_id": self.technique_id,
            "priority": self.priority,
            "rationale": self.rationale,
            "suggested_params": self.suggested_params,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ProbeRequest":
        obj = cls(
            probe_id=d.get("probe_id", str(uuid.uuid4())),
            source_gap_id=d.get("source_gap_id", ""),
            source_run_id=d.get("source_run_id", ""),
            technique_id=d.get("technique_id", ""),
            priority=d.get("priority", "high"),
            rationale=d.get("rationale", ""),
            suggested_params=d.get("suggested_params", {}),
        )
        raw_ts = d.get("created_at")
        if raw_ts:
            obj.created_at = datetime.fromisoformat(raw_ts)
        return obj

    def to_stix_task(self) -> dict[str, Any]:
        """Serialise as a minimal STIX 2.1 Task-like Note for GNAT ingestion."""
        return {
            "type": "note",
            "spec_version": "2.1",
            "id": f"note--{self.probe_id}",
            "created": self.created_at.isoformat(),
            "modified": self.created_at.isoformat(),
            "abstract": f"RedGNAT probe request: {self.technique_id} [{self.priority}]",
            "content": (
                f"Follow-on probe for gap {self.source_gap_id}.\n"
                f"Technique: {self.technique_id}\n"
                f"Priority: {self.priority}\n"
                f"Rationale: {self.rationale}\n"
                + (f"Params: {json.dumps(self.suggested_params)}" if self.suggested_params else "")
            ),
            "authors": ["redgnat-probe-generator"],
            "object_refs": [f"course-of-action--{self.source_run_id}"],
            "labels": ["redgnat-probe", "intelligence-requirement"],
            "x_redgnat_probe": {
                "probe_id": self.probe_id,
                "source_gap_id": self.source_gap_id,
                "technique_id": self.technique_id,
                "priority": self.priority,
                "suggested_params": self.suggested_params,
            },
        }


class ProbeGenerator:
    """
    Generates follow-on ProbeRequests from a GapReport using GNAT's LLMClient.

    Parameters
    ----------
    config : RedGNATConfig
        Must have ``gnat_config_path`` set for GNATClient + LLMClient access.
    model : str
        LLM model identifier passed to ``gnat.agents.LLMClient``.
        Defaults to ``"claude-3-5-sonnet-20241022"`` — the same default GNAT uses.
    max_probes : int
        Maximum ProbeRequests to return per gap report (guards against runaway
        scheduling when there are many gaps).
    """

    def __init__(
        self,
        config: Any,
        model: str = "claude-3-5-sonnet-20241022",
        max_probes: int = 10,
    ) -> None:
        self.config = config
        self.model = model
        self.max_probes = max_probes
        self._mapper = TTPMapper()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def generate(self, report: GapReport) -> list[ProbeRequest]:
        """
        Analyse a GapReport and return prioritised ProbeRequests.

        Falls back to rule-based generation if the LLM is unavailable.
        """
        if not report.gaps:
            logger.debug("ProbeGenerator: no gaps in report %s, skipping", report.gap_id)
            return []

        try:
            probes = self._generate_via_llm(report)
        except Exception as exc:
            logger.warning(
                "ProbeGenerator: LLM unavailable (%s), falling back to rule-based generation",
                exc,
            )
            probes = self._generate_rule_based(report)

        probes = probes[: self.max_probes]
        logger.info(
            "ProbeGenerator: generated %d probe(s) from gap report %s",
            len(probes),
            report.gap_id,
        )
        return probes

    # ------------------------------------------------------------------
    # LLM-driven path
    # ------------------------------------------------------------------

    def _generate_via_llm(self, report: GapReport) -> list[ProbeRequest]:
        from gnat.agents import LLMClient  # type: ignore[import]

        gap_summary = self._build_gap_summary(report)
        prompt = _DEFAULT_PROBE_PROMPT.format(gap_summary=gap_summary)

        llm = LLMClient(
            config_path=self.config.gnat_config_path,
            model=self.model,
        )
        raw = llm.complete(prompt)  # type: ignore[attr-defined]
        suggestions = self._parse_llm_response(raw)
        return self._suggestions_to_probes(suggestions, report)

    def _build_gap_summary(self, report: GapReport) -> str:
        lines = [f"Run: {report.run_id}", f"Scenario: {report.scenario_id}", ""]
        for r in report.gaps:
            info = self._mapper.get(r.technique_id)
            name = info.name if info else r.technique_id
            tactic = info.tactic if info else r.tactic
            lines.append(f"- {r.technique_id} ({name}, tactic={tactic}): executed without detection")
        return "\n".join(lines)

    @staticmethod
    def _parse_llm_response(raw: str) -> list[dict[str, Any]]:
        raw = raw.strip()
        # Strip markdown code fences if the model added them despite instructions
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[-1]
            raw = raw.rsplit("```", 1)[0]
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return parsed
        except json.JSONDecodeError:
            logger.warning("ProbeGenerator: could not parse LLM response as JSON")
        return []

    def _suggestions_to_probes(
        self,
        suggestions: list[dict[str, Any]],
        report: GapReport,
    ) -> list[ProbeRequest]:
        probes: list[ProbeRequest] = []
        seen: set[str] = set()
        for s in suggestions:
            tid = s.get("technique_id", "").strip()
            if not tid or tid in seen:
                continue
            seen.add(tid)
            priority = s.get("priority", "high")
            if priority not in {"critical", "high", "medium"}:
                priority = "high"
            probes.append(
                ProbeRequest(
                    source_gap_id=report.gap_id,
                    source_run_id=report.run_id,
                    technique_id=tid,
                    priority=priority,
                    rationale=s.get("rationale", ""),
                    suggested_params=s.get("suggested_params", {}),
                )
            )
        return probes

    # ------------------------------------------------------------------
    # Rule-based fallback (no LLM dependency)
    # ------------------------------------------------------------------

    def _generate_rule_based(self, report: GapReport) -> list[ProbeRequest]:
        """
        Static follow-on probes by technique family — used when LLM is unavailable.
        """
        probes: list[ProbeRequest] = []
        seen: set[str] = set()

        for r in report.gaps:
            followons = _RULE_BASED_FOLLOWONS.get(
                r.technique_id,
                _RULE_BASED_FOLLOWONS.get(r.technique_id.split(".")[0], []),
            )
            for entry in followons:
                tid = entry["technique_id"]
                if tid in seen:
                    continue
                seen.add(tid)
                probes.append(
                    ProbeRequest(
                        source_gap_id=report.gap_id,
                        source_run_id=report.run_id,
                        technique_id=tid,
                        priority=entry.get("priority", "high"),
                        rationale=entry.get("rationale", ""),
                        suggested_params=entry.get("suggested_params", {}),
                    )
                )

        return probes


# ---------------------------------------------------------------------------
# Static follow-on probe table — used by the rule-based fallback
# ---------------------------------------------------------------------------
_RULE_BASED_FOLLOWONS: dict[str, list[dict[str, Any]]] = {
    "T1046": [
        {
            "technique_id": "T1595",
            "priority": "high",
            "rationale": "Undetected port scan suggests external attack surface is also enumerable; validate perimeter exposure.",
        },
        {
            "technique_id": "T1087",
            "priority": "medium",
            "rationale": "Open services may expose AD endpoints; enumerate accounts via discovered LDAP/RPC services.",
        },
    ],
    "T1595": [
        {
            "technique_id": "T1046",
            "priority": "high",
            "rationale": "External recon succeeded; follow up with internal port scan to map lateral paths.",
        },
    ],
    "T1087": [
        {
            "technique_id": "T1069",
            "priority": "high",
            "rationale": "Account enumeration undetected; enumerate group memberships to identify privilege escalation paths.",
        },
        {
            "technique_id": "T1110",
            "priority": "critical",
            "rationale": "Account list obtained without detection; password spray against discovered accounts is now low-risk for attacker.",
        },
    ],
    "T1069": [
        {
            "technique_id": "T1482",
            "priority": "high",
            "rationale": "Group enumeration undetected; map domain trusts to identify lateral movement across trust boundaries.",
        },
    ],
    "T1482": [
        {
            "technique_id": "T1087",
            "priority": "medium",
            "rationale": "Trust enumeration undetected; enumerate accounts in trusted domains.",
        },
    ],
    "T1566": [
        {
            "technique_id": "T1621",
            "priority": "critical",
            "rationale": "Phishing undetected; follow up with MFA fatigue on accounts that clicked to test second-factor bypass.",
        },
    ],
    "T1566.001": [
        {
            "technique_id": "T1566.002",
            "priority": "high",
            "rationale": "Attachment phishing undetected; test link-based variant to confirm broad phishing coverage gap.",
        },
    ],
    "T1566.002": [
        {
            "technique_id": "T1528",
            "priority": "high",
            "rationale": "Link click undetected; test OAuth consent phishing to determine if token theft path is also open.",
        },
    ],
    "T1110": [
        {
            "technique_id": "T1621",
            "priority": "critical",
            "rationale": "Password spray undetected; MFA fatigue is the natural follow-on if spray produces valid creds.",
        },
        {
            "technique_id": "T1539",
            "priority": "high",
            "rationale": "Credential testing undetected; audit session token policies to determine persistence opportunity.",
        },
    ],
    "T1110.003": [
        {
            "technique_id": "T1621",
            "priority": "critical",
            "rationale": "Password spray undetected; MFA fatigue is the natural follow-on if spray yields valid credentials.",
        },
        {
            "technique_id": "T1110.004",
            "priority": "high",
            "rationale": "Password spray undetected; credential stuffing (known-breach pairs) is lower-noise variant to validate.",
        },
    ],
    "T1110.004": [
        {
            "technique_id": "T1621",
            "priority": "critical",
            "rationale": "Credential stuffing undetected; MFA fatigue is likely next attacker step if valid accounts found.",
        },
    ],
    "T1621": [
        {
            "technique_id": "T1539",
            "priority": "high",
            "rationale": "MFA fatigue undetected; assess whether session token theft would also bypass second factor.",
        },
    ],
    "T1528": [
        {
            "technique_id": "T1539",
            "priority": "high",
            "rationale": "OAuth abuse undetected; test whether stolen tokens have long-lived session persistence.",
        },
    ],
    "T1526": [
        {
            "technique_id": "T1087",
            "priority": "medium",
            "rationale": "Cloud resource enumeration undetected; enumerate identities in cloud directory for privilege paths.",
        },
    ],
}
