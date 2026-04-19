# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
CART Report Generator.

Produces PDF and DOCX red team engagement reports from EmulationRun results.
Wraps GNAT's gnat.reports module for document generation and adds CART-specific
sections: ATT&CK coverage heatmap, gap analysis, and per-technique drill-down.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from redgnat.orm.models import EmulationRun, EmulationScenario, ResultStatus, TechniqueResult
from redgnat.scenarios.ttp_mapper import TTPMapper

logger = logging.getLogger(__name__)


class CARTReport:
    """
    Generates a structured red team report from one or more EmulationRun results.

    Parameters
    ----------
    scenario : EmulationScenario
        The scenario that was executed.
    run : EmulationRun
        The run record.
    results : list[TechniqueResult]
        All technique results from the run.
    """

    def __init__(
        self,
        scenario: EmulationScenario,
        run: EmulationRun,
        results: list[TechniqueResult],
    ) -> None:
        self.scenario = scenario
        self.run = run
        self.results = results
        self._mapper = TTPMapper()

    # ------------------------------------------------------------------
    # Executive Summary
    # ------------------------------------------------------------------
    def executive_summary(self) -> dict[str, Any]:
        total = len(self.results)
        by_status = {}
        for r in self.results:
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1

        successes = by_status.get(ResultStatus.SUCCESS.value, 0)
        detected = by_status.get(ResultStatus.DETECTED.value, 0)
        blocked = by_status.get(ResultStatus.BLOCKED.value, 0)
        errors = by_status.get(ResultStatus.ERROR.value, 0)

        coverage_pct = (detected + blocked) / max(total, 1) * 100

        return {
            "scenario_name": self.scenario.name,
            "run_id": self.run.run_id,
            "report_generated_at": datetime.now(timezone.utc).isoformat(),
            "execution_summary": {
                "techniques_executed": total,
                "successful_emulations": successes,
                "detected_by_controls": detected,
                "blocked_by_controls": blocked,
                "errors": errors,
            },
            "coverage_score": round(coverage_pct, 1),
            "risk_rating": self._risk_rating(successes, total),
            "key_findings": self._key_findings(),
            "recommendations": self._top_recommendations(),
        }

    def _risk_rating(self, successes: int, total: int) -> str:
        if total == 0:
            return "Unknown"
        ratio = successes / total
        if ratio >= 0.7:
            return "Critical"
        elif ratio >= 0.5:
            return "High"
        elif ratio >= 0.3:
            return "Medium"
        else:
            return "Low"

    def _key_findings(self) -> list[str]:
        findings = []
        for r in self.results:
            if r.status == ResultStatus.SUCCESS and r.findings:
                for f in r.findings[:2]:
                    if isinstance(f, dict):
                        info = self._mapper.get(r.technique_id)
                        name = info.name if info else r.technique_id
                        finding_text = self._summarize_finding(r.technique_id, f)
                        if finding_text:
                            findings.append(f"[{r.technique_id}] {name}: {finding_text}")
        return findings[:10]

    def _summarize_finding(self, technique_id: str, finding: dict) -> str:
        if technique_id == "T1046":
            hosts = finding.get("open_ports", [])
            return f"{finding.get('host')} has {len(hosts)} open ports"
        elif technique_id in {"T1087.002", "T1069.002"}:
            cat = finding.get("category", "")
            count = finding.get("count", 0)
            return f"{count} {cat} found"
        elif technique_id.startswith("T1566"):
            cr = finding.get("click_rate", finding.get("open_rate", 0))
            return f"Click/open rate: {cr:.1%}"
        elif technique_id in {"T1110.003", "T1110.004"}:
            successes = finding.get("successful_authentications", 0)
            return f"{successes} successful authentication(s)" if successes else ""
        elif technique_id == "T1621":
            approved = finding.get("approved", False)
            return "User APPROVED MFA push!" if approved else "No approvals"
        return str(finding.get("count", ""))

    def _top_recommendations(self) -> list[str]:
        recs: list[str] = []
        for r in self.results:
            if r.status == ResultStatus.SUCCESS and r.findings:
                recs.extend(self._recommendations_for(r))
        seen: set[str] = set()
        unique = [r for r in recs if not (r in seen or seen.add(r))]
        return unique[:8]

    def _recommendations_for(self, result: TechniqueResult) -> list[str]:
        recs = []
        tid = result.technique_id
        if tid == "T1046":
            recs.append("Review firewall rules — reduce network exposure surface")
        elif tid == "T1087.002":
            recs.append("Restrict LDAP enumeration — block anonymous LDAP queries")
        elif tid in {"T1087.004", "T1069.003"}:
            recs.append("Enable Entra ID app consent controls and restrict LDAP query permissions")
        elif tid == "T1566.002":
            recs.append("Deploy advanced email filtering and anti-phishing simulation training")
        elif tid == "T1566.001":
            recs.append("Enable attachment sandboxing and user phishing awareness training")
        elif tid == "T1110.003":
            recs.append("Enforce account lockout policy and deploy Smart Lockout / SSPR")
        elif tid == "T1110.004":
            recs.append("Enable breach credential detection (HIBP integration / Entra ID Protection)")
        elif tid == "T1621":
            recs.append("Deploy FIDO2/hardware-key MFA to eliminate push fatigue attack surface")
        elif tid == "T1528":
            recs.append("Restrict OAuth app consent to admins; audit existing app permissions")
        elif tid == "T1539":
            recs.append("Enable Continuous Access Evaluation and reduce token lifetimes")
        return recs

    # ------------------------------------------------------------------
    # ATT&CK Coverage Map
    # ------------------------------------------------------------------
    def attack_coverage_map(self) -> dict[str, Any]:
        """
        Return a tactic → technique → status mapping for ATT&CK matrix rendering.
        """
        coverage: dict[str, dict[str, str]] = {}
        for r in self.results:
            info = self._mapper.get(r.technique_id)
            tactic = info.tactic if info else "unknown"
            coverage.setdefault(tactic, {})[r.technique_id] = r.status.value

        return {
            "tactics": coverage,
            "legend": {
                ResultStatus.SUCCESS.value: "Technique executed without triggering detection",
                ResultStatus.DETECTED.value: "Controls detected / blocked the technique",
                ResultStatus.BLOCKED.value: "Scope controls prevented execution",
                ResultStatus.ERROR.value: "Technique failed due to configuration error",
                ResultStatus.DRY_RUN.value: "Dry-run mode — not executed",
            },
        }

    # ------------------------------------------------------------------
    # Per-technique drill-down
    # ------------------------------------------------------------------
    def technique_detail(self, technique_id: str) -> dict[str, Any] | None:
        result = next((r for r in self.results if r.technique_id == technique_id), None)
        if result is None:
            return None

        info = self._mapper.get(technique_id)
        return {
            "technique_id": technique_id,
            "name": info.name if info else technique_id,
            "tactic": info.tactic if info else "unknown",
            "description": info.description if info else "",
            "status": result.status.value,
            "executed_at": result.executed_at.isoformat(),
            "findings": result.findings,
            "error": result.error,
            "stix_sighting": result.to_stix_sighting(),
        }

    def full_report_dict(self) -> dict[str, Any]:
        """Return the complete report as a JSON-serialisable dict."""
        return {
            "executive_summary": self.executive_summary(),
            "attack_coverage_map": self.attack_coverage_map(),
            "technique_details": [
                self.technique_detail(r.technique_id)
                for r in self.results
            ],
            "raw_results": [r.to_dict() for r in self.results],
        }

    def render_pdf(self, output_path: str) -> None:
        """
        Render report as PDF using GNAT's report engine.

        Requires: pip install 'gnat[reports]'
        """
        try:
            from gnat.reports import ReportBuilder  # type: ignore[import]
        except ImportError:
            logger.warning("GNAT reports not available — pip install 'gnat[reports]'")
            return

        builder = ReportBuilder()
        report_data = self.full_report_dict()
        builder.build_pdf(
            title=f"CART Emulation Report: {self.scenario.name}",
            sections=report_data,
            output_path=output_path,
        )
        logger.info("PDF report written to %s", output_path)

    def render_docx(self, output_path: str) -> None:
        """
        Render report as DOCX using GNAT's report engine.

        Requires: pip install 'gnat[reports]'
        """
        try:
            from gnat.reports import ReportBuilder  # type: ignore[import]
        except ImportError:
            logger.warning("GNAT reports not available — pip install 'gnat[reports]'")
            return

        builder = ReportBuilder()
        builder.build_docx(
            title=f"CART Emulation Report: {self.scenario.name}",
            sections=self.full_report_dict(),
            output_path=output_path,
        )
        logger.info("DOCX report written to %s", output_path)
