"""
SandGNAT intel subscriber.

Polls the SandGNAT export API for completed malware analyses and converts
behavioral STIX bundles into IntelFeed records for RedGNAT's scenario builder.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Iterator

from redgnat.config import RedGNATConfig
from redgnat.intake.base import IntelSubscriber
from redgnat.orm.models import IntelFeed, IntelSource

logger = logging.getLogger(__name__)

# SandGNAT severity levels in ascending order
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ATT&CK technique IDs that are commonly associated with malware behaviors
# and are relevant for emulation (discovery/persistence/lateral movement)
_EMULATABLE_TECHNIQUES = {
    # Discovery
    "T1046", "T1082", "T1083", "T1016", "T1049", "T1033", "T1007",
    "T1069", "T1087", "T1135", "T1018", "T1482",
    # Initial Access
    "T1566.001", "T1566.002", "T1190", "T1078",
    # Credential Access
    "T1110.003", "T1110.004", "T1621", "T1528", "T1539", "T1555",
    # Lateral Movement
    "T1021.001", "T1021.002", "T1021.006",
    # Collection
    "T1560", "T1074",
}


class SandGNATSubscriber(IntelSubscriber):
    """
    Polls the SandGNAT export API for new completed analyses.

    For each analysis above the configured severity threshold, the subscriber
    inspects the STIX bundle for attack-pattern objects, filters to emulatable
    techniques, and yields an IntelFeed record.

    Parameters
    ----------
    config : RedGNATConfig
        Must have ``sandgnat_base_url`` and ``sandgnat_api_key`` set.
    """

    def __init__(self, config: RedGNATConfig) -> None:
        super().__init__(config)
        self._base_url = config.sandgnat_base_url.rstrip("/")
        self._api_key = config.sandgnat_api_key
        self._min_severity = _SEVERITY_ORDER.get(config.sandgnat_min_severity, 1)

    def health_check(self) -> bool:
        try:
            self._get("/healthz")
            return True
        except Exception as exc:
            logger.warning("SandGNAT health check failed: %s", exc)
            return False

    def poll(self) -> Iterator[IntelFeed]:
        try:
            analyses = self._get("/analyses")
        except Exception as exc:
            logger.error("Failed to list SandGNAT analyses: %s", exc)
            return

        for analysis in analyses:
            try:
                yield from self._process_analysis(analysis)
            except Exception as exc:
                logger.warning(
                    "Skipping analysis %s: %s",
                    analysis.get("analysis_id", "?"),
                    exc,
                )

    def _process_analysis(self, analysis: dict) -> Iterator[IntelFeed]:
        analysis_id: str = analysis.get("analysis_id", "")
        severity: str = analysis.get("severity", "low").lower()
        sev_rank = _SEVERITY_ORDER.get(severity, 0)

        if sev_rank < self._min_severity:
            logger.debug(
                "Skipping SandGNAT analysis %s (severity %s below threshold)",
                analysis_id,
                severity,
            )
            return

        # Fetch full STIX bundle
        try:
            bundle = self._get(f"/analyses/{analysis_id}/bundle")
        except Exception as exc:
            logger.warning("Could not fetch bundle for analysis %s: %s", analysis_id, exc)
            return

        # Extract emulatable ATT&CK technique IDs from the bundle
        attack_pattern_ids = self._extract_attack_ids(bundle)

        if not attack_pattern_ids:
            logger.debug(
                "SandGNAT analysis %s has no emulatable ATT&CK techniques — skipping",
                analysis_id,
            )
            return

        # Map severity to confidence score
        confidence_map = {"low": 0.3, "medium": 0.6, "high": 0.8, "critical": 1.0}
        confidence = confidence_map.get(severity, 0.5)

        sample_name: str = analysis.get("sample_name", "unknown")

        yield IntelFeed(
            source=IntelSource.SANDGNAT,
            source_ref_id=analysis_id,
            stix_bundle=bundle,
            campaign_name=f"SandGNAT: {sample_name} ({severity.upper()})",
            attack_pattern_ids=attack_pattern_ids,
            confidence=confidence,
        )

    @staticmethod
    def _extract_attack_ids(bundle: dict) -> list[str]:
        """Return emulatable ATT&CK IDs found in the STIX bundle."""
        ids: list[str] = []
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            for ref in obj.get("external_references", []):
                ext_id = ref.get("external_id", "")
                if ext_id in _EMULATABLE_TECHNIQUES:
                    ids.append(ext_id)
        return list(dict.fromkeys(ids))  # deduplicate, preserve order

    # ------------------------------------------------------------------
    # HTTP helpers (urllib3-style using stdlib urllib to avoid extra deps)
    # ------------------------------------------------------------------
    def _get(self, path: str) -> dict | list:
        url = f"{self._base_url}{path}"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {self._api_key}", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return json.loads(resp.read().decode())
