# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Gap Reporter — converts emulation gaps into STIX intelligence requirements for GNAT.

A "gap" is any technique that executed with ResultStatus.SUCCESS — meaning the
technique completed without triggering a detection alert. These are the most
actionable findings: the defender doesn't know they happened.

GapReporter converts gaps into STIX Note objects and pushes them back to GNAT
via the GNATClient. GNAT operators and AI agents then use these notes to:
- Task additional intel collection (what do we know about this TTP's detection?)
- Enrich findings via GNAT's 158+ connectors (Shodan, Semperis, Silverfort, etc.)
- Drive HuntGNAT rule gap analysis
- Feed the probe generator for follow-on testing
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from redgnat.orm.models import ResultStatus, TechniqueResult
from redgnat.scenarios.ttp_mapper import TTPMapper

logger = logging.getLogger(__name__)


@dataclass
class GapReport:
    """
    Structured report of undetected techniques from an emulation run.

    Parameters
    ----------
    gap_id : str
        Unique ID for this report.
    run_id : str
        Source EmulationRun.
    scenario_id : str
        Source EmulationScenario.
    gaps : list[TechniqueResult]
        Results with status SUCCESS (= undetected by defenses).
    created_at : datetime
    """

    gap_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    run_id: str = ""
    scenario_id: str = ""
    gaps: list[TechniqueResult] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def undetected_technique_ids(self) -> list[str]:
        """ATT&CK technique IDs for all undetected techniques in this report."""
        return [r.technique_id for r in self.gaps]

    @property
    def is_critical(self) -> bool:
        """True if any credential-access or initial-access technique was undetected."""
        critical_tactics = {"credential-access", "initial-access"}
        return any(r.tactic in critical_tactics for r in self.gaps)

    def to_stix_note(self) -> dict[str, Any]:
        """
        Serialise as a STIX 2.1 Note object for GNAT ingestion.

        The note content describes each gap and what intel GNAT should collect
        to understand why the technique wasn't detected.
        """
        mapper = TTPMapper()
        gap_lines = []
        for r in self.gaps:
            info = mapper.get(r.technique_id)
            name = info.name if info else r.technique_id
            finding_summary = self._summarise_findings(r)
            intel_ask = _INTEL_ASKS.get(r.technique_id, _INTEL_ASKS.get(r.technique_id.split(".")[0], ""))
            gap_lines.append(
                f"- [{r.technique_id}] {name}: executed without detection. "
                f"{finding_summary}"
                + (f" Intel needed: {intel_ask}" if intel_ask else "")
            )

        note_content = (
            f"RedGNAT CART gap report — run {self.run_id}\n"
            f"Scenario: {self.scenario_id}\n"
            f"Undetected techniques ({len(self.gaps)}):\n"
            + "\n".join(gap_lines)
            + f"\n\nRisk: {'CRITICAL' if self.is_critical else 'HIGH'} — "
            "these techniques completed without triggering any detection alert."
        )

        return {
            "type": "note",
            "spec_version": "2.1",
            "id": f"note--{self.gap_id}",
            "created": self.created_at.isoformat(),
            "modified": self.created_at.isoformat(),
            "abstract": f"RedGNAT gap report: {len(self.gaps)} undetected techniques",
            "content": note_content,
            "authors": ["redgnat-cart"],
            "object_refs": [f"course-of-action--{self.run_id}"],
            "labels": ["redgnat-gap", "intelligence-requirement"],
            "x_redgnat_gap": {
                "run_id": self.run_id,
                "scenario_id": self.scenario_id,
                "undetected_technique_ids": self.undetected_technique_ids,
                "is_critical": self.is_critical,
                "gap_id": self.gap_id,
            },
        }

    @staticmethod
    def _summarise_findings(result: TechniqueResult) -> str:
        if not result.findings:
            return ""
        f = result.findings[0]
        if isinstance(f, dict):
            if "open_ports" in f:
                n = len(f.get("open_ports", []))
                return f"Found {n} open port(s) on {f.get('host', '?')}."
            if "successful_authentications" in f:
                n = f.get("successful_authentications", 0)
                return f"{n} credential(s) authenticated successfully." if n else ""
            if "links_clicked" in f:
                rate = f.get("click_rate", 0)
                return f"Click rate: {rate:.1%}."
        return ""


# Intelligence requirements by technique — what GNAT should collect when a gap is found
_INTEL_ASKS: dict[str, str] = {
    "T1046": (
        "Enrich exposed hosts via Shodan/Censys connectors. "
        "Check for CVEs on detected services via CISA KEV / VulnCheck."
    ),
    "T1595": "Enumerate external attack surface via Cortex Xpanse / runZero.",
    "T1087": (
        "Check AD enumeration detection in Semperis DSP. "
        "Review LDAP query audit logs in Sentinel/Splunk."
    ),
    "T1069": "Review group membership audit events in SIEM. Check Semperis DSP IoE coverage.",
    "T1482": "Enumerate domain trust detection coverage in Semperis DSP / Defender Identity.",
    "T1526": "Check cloud resource enumeration alerts in Prisma Cloud / AWS GuardDuty.",
    "T1566": (
        "Pull phishing campaign data from Cofense Intelligence / Proofpoint TAP. "
        "Verify email gateway sandbox coverage."
    ),
    "T1566.001": "Check attachment sandbox coverage in Proofpoint TAP / Mimecast.",
    "T1566.002": "Review link-follow detection in Proofpoint / Cisco Umbrella.",
    "T1110": (
        "Check Okta / Entra ID Protection risk signal configuration. "
        "Verify account lockout threshold policy via Semperis DSP."
    ),
    "T1110.003": (
        "Pull Okta smart lockout policy via Okta connector. "
        "Check Entra ID sign-in risk policy in Sentinel. "
        "Verify password spray detection rule in Silverfort."
    ),
    "T1110.004": (
        "Check if Entra ID 'Leaked Credentials' risk policy is active. "
        "Verify HIBP breach detection via HaveIBeenPwned connector."
    ),
    "T1621": (
        "Verify FIDO2/phishing-resistant MFA enrollment rate via Entra ID / Okta connectors. "
        "Check MFA fatigue detection in Silverfort / Entra ID Protection."
    ),
    "T1528": (
        "Audit OAuth app consent permissions via Entra ID connector. "
        "Check for MCAS/Defender Cloud Apps anomaly detection on new consents."
    ),
    "T1539": (
        "Review session token lifetime policies in Entra ID / Okta. "
        "Check CAE (Continuous Access Evaluation) coverage in Entra ID connector."
    ),
}


class GapReporter:
    """
    Builds GapReports from run results and pushes them to GNAT.

    Parameters
    ----------
    config : RedGNATConfig
        Must have gnat_config_path set for GNATClient push-back.
    """

    def __init__(self, config: Any) -> None:
        self.config = config

    def build_report(
        self,
        run_id: str,
        scenario_id: str,
        results: list[TechniqueResult],
    ) -> GapReport:
        """Build a GapReport from a completed run's results."""
        gaps = [r for r in results if r.status == ResultStatus.SUCCESS]
        return GapReport(run_id=run_id, scenario_id=scenario_id, gaps=gaps)

    def push_to_gnat(self, report: GapReport) -> bool:
        """
        Push the gap report to GNAT as a STIX Note via GNATClient.

        Returns True if push succeeded, False otherwise.
        """
        if not report.gaps:
            logger.debug("GapReporter: no gaps to report for run %s", report.run_id)
            return True

        stix_note = report.to_stix_note()

        try:
            from gnat import GNATClient  # type: ignore[import]

            client = GNATClient(config_path=self.config.gnat_config_path)
            client.upsert_object(stix_note)  # type: ignore[attr-defined]
            logger.info(
                "GapReporter: pushed gap report %s to GNAT (%d gaps, critical=%s)",
                report.gap_id,
                len(report.gaps),
                report.is_critical,
            )
            return True
        except ImportError:
            logger.warning("GapReporter: GNAT not installed, cannot push gap report")
            return False
        except Exception as exc:
            logger.error("GapReporter: failed to push gap report to GNAT: %s", exc)
            return False

    def push_to_api(self, report: GapReport, redgnat_base_url: str, api_key: str) -> bool:
        """
        Store the gap note locally via the RedGNAT STIX API so GNAT can pull it.
        The RedGNAT connector's GET /api/v1/stix/gaps endpoint serves these.
        """
        import json
        import urllib.request

        stix_note = report.to_stix_note()
        data = json.dumps(stix_note).encode()
        req = urllib.request.Request(
            f"{redgnat_base_url.rstrip('/')}/api/v1/stix/gaps",
            data=data,
            method="POST",
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                return resp.status == 200
        except Exception as exc:
            logger.error("GapReporter: failed to store gap note via API: %s", exc)
            return False
