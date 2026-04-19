# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Intel normalizer — converts IntelFeed records into EmulationScenarios.

The normalizer is the bridge between raw threat intelligence and actionable
emulation plans. It maps ATT&CK technique IDs found in intel to registered
RedGNAT technique modules and builds an EmulationScenario with an ordered
technique execution plan.
"""
from __future__ import annotations

import logging

from redgnat.config import RedGNATConfig
from redgnat.orm.models import EmulationScenario, IntelFeed, ScenarioStatus

logger = logging.getLogger(__name__)


class IntelNormalizer:
    """
    Converts IntelFeed objects into EmulationScenarios.

    Parameters
    ----------
    config : RedGNATConfig
        Used to apply global scope defaults to new scenarios.
    """

    # Tactic execution order mirrors ATT&CK kill-chain progression
    _TACTIC_ORDER = [
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "exfiltration",
        "impact",
    ]

    def __init__(self, config: RedGNATConfig) -> None:
        self.config = config

    def to_scenario(self, feed: IntelFeed) -> EmulationScenario | None:
        """
        Build an EmulationScenario from an IntelFeed.

        Returns None if no registered techniques match the feed's ATT&CK IDs.

        Parameters
        ----------
        feed : IntelFeed
            Ingested intel record with attack_pattern_ids populated.

        Returns
        -------
        EmulationScenario | None
        """
        from redgnat.techniques.registry import TECHNIQUE_REGISTRY
        from redgnat.scenarios.ttp_mapper import TTPMapper

        mapper = TTPMapper()

        # Resolve ATT&CK IDs from the feed against registered techniques
        matched_technique_ids: list[str] = []
        for atk_id in feed.attack_pattern_ids:
            # Normalise subtechnique separator (T1566.002 or T1566/002)
            normalised = atk_id.replace("/", ".")
            if normalised in TECHNIQUE_REGISTRY:
                matched_technique_ids.append(normalised)
            else:
                # Try parent technique (T1566.002 → T1566)
                parent = normalised.split(".")[0]
                if parent in TECHNIQUE_REGISTRY:
                    matched_technique_ids.append(parent)

        # Deduplicate while preserving insertion order
        seen: set[str] = set()
        unique_ids: list[str] = []
        for tid in matched_technique_ids:
            if tid not in seen:
                seen.add(tid)
                unique_ids.append(tid)

        if not unique_ids:
            logger.debug(
                "No registered techniques match feed %s (ATT&CK IDs: %s)",
                feed.feed_id,
                feed.attack_pattern_ids,
            )
            return None

        # Sort by tactic order for logical kill-chain progression
        sorted_ids = self._sort_by_tactic(unique_ids, mapper)

        description = (
            f"Automated emulation scenario derived from {feed.source.value} intel feed. "
            f"Source ref: {feed.source_ref_id}. "
            f"Techniques: {', '.join(sorted_ids)}."
        )

        return EmulationScenario(
            name=feed.campaign_name or f"Auto: {feed.source_ref_id[:8]}",
            description=description,
            feed_id=feed.feed_id,
            technique_ids=sorted_ids,
            status=ScenarioStatus.ACTIVE,
        )

    def _sort_by_tactic(self, technique_ids: list[str], mapper: "TTPMapper") -> list[str]:
        """Sort technique IDs by ATT&CK kill-chain tactic order."""

        def tactic_rank(tid: str) -> int:
            tactic = mapper.technique_tactic(tid)
            try:
                return self._TACTIC_ORDER.index(tactic)
            except ValueError:
                return 99

        return sorted(technique_ids, key=tactic_rank)
