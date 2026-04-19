# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Unit tests for IntelNormalizer."""
from __future__ import annotations

import pytest

from redgnat.config import RedGNATConfig
from redgnat.intake.normalizer import IntelNormalizer
from redgnat.orm.models import IntelFeed, IntelSource, ScenarioStatus


@pytest.fixture
def normalizer(minimal_config: str) -> IntelNormalizer:
    cfg = RedGNATConfig(minimal_config)
    return IntelNormalizer(cfg)


@pytest.fixture
def feed_with_techniques() -> IntelFeed:
    return IntelFeed(
        source=IntelSource.GNAT,
        source_ref_id="campaign--abc123",
        stix_bundle={},
        campaign_name="Test Campaign",
        attack_pattern_ids=["T1046", "T1566.002", "T1110.003"],
        confidence=0.8,
    )


@pytest.fixture
def feed_with_no_matching_techniques() -> IntelFeed:
    return IntelFeed(
        source=IntelSource.GNAT,
        source_ref_id="campaign--xyz999",
        stix_bundle={},
        campaign_name="Unknown Campaign",
        attack_pattern_ids=["T9999"],  # not registered
        confidence=0.9,
    )


def test_normalizer_produces_scenario(normalizer: IntelNormalizer, feed_with_techniques: IntelFeed):
    scenario = normalizer.to_scenario(feed_with_techniques)
    assert scenario is not None
    assert scenario.name == "Test Campaign"
    assert len(scenario.technique_ids) > 0


def test_normalizer_filters_unregistered(
    normalizer: IntelNormalizer, feed_with_no_matching_techniques: IntelFeed
):
    scenario = normalizer.to_scenario(feed_with_no_matching_techniques)
    assert scenario is None


def test_normalizer_sets_status_active(
    normalizer: IntelNormalizer, feed_with_techniques: IntelFeed
):
    scenario = normalizer.to_scenario(feed_with_techniques)
    assert scenario is not None
    assert scenario.status == ScenarioStatus.ACTIVE


def test_normalizer_preserves_feed_id(
    normalizer: IntelNormalizer, feed_with_techniques: IntelFeed
):
    scenario = normalizer.to_scenario(feed_with_techniques)
    assert scenario is not None
    assert scenario.feed_id == feed_with_techniques.feed_id


def test_normalizer_deduplicates_techniques(normalizer: IntelNormalizer):
    feed = IntelFeed(
        source=IntelSource.GNAT,
        source_ref_id="campaign--dedup",
        stix_bundle={},
        attack_pattern_ids=["T1046", "T1046", "T1046"],
        confidence=0.9,
    )
    scenario = normalizer.to_scenario(feed)
    assert scenario is not None
    assert scenario.technique_ids.count("T1046") == 1


def test_normalizer_tactic_ordering(normalizer: IntelNormalizer):
    feed = IntelFeed(
        source=IntelSource.GNAT,
        source_ref_id="campaign--order",
        stix_bundle={},
        attack_pattern_ids=["T1110.003", "T1566.002", "T1046"],
        confidence=0.9,
    )
    scenario = normalizer.to_scenario(feed)
    assert scenario is not None
    # Reconnaissance/initial-access should come before credential-access
    ids = scenario.technique_ids
    recon_idx = next((i for i, t in enumerate(ids) if t in {"T1046", "T1566.002"}), 999)
    cred_idx = next((i for i, t in enumerate(ids) if t == "T1110.003"), 0)
    assert recon_idx < cred_idx
