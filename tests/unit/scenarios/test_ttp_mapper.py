"""Unit tests for TTPMapper."""
from __future__ import annotations

import pytest

from redgnat.scenarios.ttp_mapper import TTPMapper


@pytest.fixture
def mapper() -> TTPMapper:
    return TTPMapper()


def test_get_known_technique(mapper: TTPMapper):
    info = mapper.get("T1046")
    assert info is not None
    assert info.technique_id == "T1046"
    assert info.tactic == "discovery"
    assert info.name


def test_get_unknown_returns_none(mapper: TTPMapper):
    assert mapper.get("T9999.999") is None


def test_technique_tactic_known(mapper: TTPMapper):
    assert mapper.technique_tactic("T1566.002") == "initial-access"


def test_technique_tactic_unknown(mapper: TTPMapper):
    assert mapper.technique_tactic("T9999") == "unknown"


def test_technique_tactic_parent_fallback(mapper: TTPMapper):
    # T1110.003 → parent T1110 is also in the map
    tactic = mapper.technique_tactic("T1110.003")
    assert tactic == "credential-access"


def test_all_technique_ids_nonempty(mapper: TTPMapper):
    ids = mapper.all_technique_ids()
    assert len(ids) > 10


def test_technique_name(mapper: TTPMapper):
    name = mapper.technique_name("T1046")
    assert name == "Network Service Discovery"


def test_technique_name_unknown(mapper: TTPMapper):
    name = mapper.technique_name("T9999")
    assert name == "T9999"
