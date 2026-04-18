"""
GNAT intel subscriber.

Polls a GNATClient for new Campaign and AttackPattern STIX objects and
converts them into IntelFeed records for RedGNAT's scenario builder.
"""
from __future__ import annotations

import logging
from typing import Iterator

from redgnat.config import RedGNATConfig
from redgnat.intake.base import IntelSubscriber
from redgnat.orm.models import IntelFeed, IntelSource

logger = logging.getLogger(__name__)

# STIX AttackPattern external_reference sources that indicate ATT&CK IDs
_ATTACK_SOURCES = {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}


class GNATSubscriber(IntelSubscriber):
    """
    Polls GNATClient for campaigns with associated ATT&CK techniques.

    The subscriber:
    1. Calls ``GNATClient.list_objects("campaign")`` to get recent campaigns
    2. For each campaign, fetches related ``attack-pattern`` objects
    3. Extracts ATT&CK technique IDs from external references
    4. Filters by ``config.gnat_min_confidence``
    5. Yields one IntelFeed per campaign

    Parameters
    ----------
    config : RedGNATConfig
        Must have ``gnat_config_path`` set for GNATClient initialisation.
    """

    def __init__(self, config: RedGNATConfig) -> None:
        super().__init__(config)
        self._gnat_client: object | None = None

    def _get_client(self) -> object:
        if self._gnat_client is None:
            try:
                from gnat import GNATClient  # type: ignore[import]

                self._gnat_client = GNATClient(
                    config_path=self.config.gnat_config_path
                )
            except ImportError as exc:
                raise RuntimeError(
                    "GNAT library not installed. Run: pip install 'gnat>=1.5.0'"
                ) from exc
        return self._gnat_client

    def health_check(self) -> bool:
        try:
            client = self._get_client()
            # GNATClient exposes a health_check on each connector; we use
            # a lightweight list call limited to 1 object as a proxy.
            client.list_objects("campaign", limit=1)  # type: ignore[attr-defined]
            return True
        except Exception as exc:
            logger.warning("GNAT health check failed: %s", exc)
            return False

    def poll(self) -> Iterator[IntelFeed]:
        client = self._get_client()

        try:
            campaigns = client.list_objects("campaign")  # type: ignore[attr-defined]
        except Exception as exc:
            logger.error("Failed to list GNAT campaigns: %s", exc)
            return

        for campaign in campaigns:
            try:
                yield from self._process_campaign(client, campaign)
            except Exception as exc:
                logger.warning(
                    "Skipping campaign %s due to error: %s",
                    getattr(campaign, "id", "?"),
                    exc,
                )

    def _process_campaign(self, client: object, campaign: object) -> Iterator[IntelFeed]:
        campaign_id: str = getattr(campaign, "id", "")
        campaign_name: str = getattr(campaign, "name", "Unknown Campaign")
        confidence: float = float(getattr(campaign, "confidence", 0)) / 100.0

        if confidence < self.config.gnat_min_confidence:
            logger.debug(
                "Skipping campaign %s (confidence %.2f < %.2f)",
                campaign_name,
                confidence,
                self.config.gnat_min_confidence,
            )
            return

        # Fetch associated attack patterns
        attack_pattern_ids: list[str] = []
        try:
            related = client.list_objects(  # type: ignore[attr-defined]
                "attack-pattern", campaign_id=campaign_id
            )
            for ap in related:
                tid = self._extract_attack_id(ap)
                if tid:
                    attack_pattern_ids.append(tid)
        except Exception as exc:
            logger.warning("Could not fetch attack patterns for %s: %s", campaign_id, exc)

        if not attack_pattern_ids:
            logger.debug("Campaign %s has no mapped ATT&CK techniques — skipping", campaign_name)
            return

        # Serialise the campaign STIX object for storage
        stix_bundle: dict = {}
        try:
            if hasattr(campaign, "to_stix_bundle"):
                stix_bundle = campaign.to_stix_bundle()
            elif hasattr(campaign, "to_dict"):
                stix_bundle = {"type": "bundle", "objects": [campaign.to_dict()]}
        except Exception:
            stix_bundle = {"type": "bundle", "objects": []}

        yield IntelFeed(
            source=IntelSource.GNAT,
            source_ref_id=campaign_id,
            stix_bundle=stix_bundle,
            campaign_name=campaign_name,
            attack_pattern_ids=attack_pattern_ids,
            confidence=confidence,
        )

    @staticmethod
    def _extract_attack_id(attack_pattern: object) -> str | None:
        """Extract ATT&CK technique ID from a STIX AttackPattern object."""
        ext_refs = getattr(attack_pattern, "external_references", []) or []
        for ref in ext_refs:
            source = getattr(ref, "source_name", "") or ref.get("source_name", "")
            ext_id = getattr(ref, "external_id", "") or ref.get("external_id", "")
            if source in _ATTACK_SOURCES and ext_id.startswith("T"):
                return ext_id
        return None
