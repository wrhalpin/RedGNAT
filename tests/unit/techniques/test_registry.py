"""Unit tests for the technique registry."""
from __future__ import annotations

import pytest

from redgnat.techniques.registry import TECHNIQUE_REGISTRY, get_technique, list_technique_ids
from redgnat.techniques.base import Technique


def test_registry_not_empty():
    assert len(TECHNIQUE_REGISTRY) > 0


def test_all_registered_are_technique_subclasses():
    for tid, cls in TECHNIQUE_REGISTRY.items():
        assert issubclass(cls, Technique), f"{tid}: {cls} is not a Technique subclass"


def test_all_have_emulation_only():
    for tid, cls in TECHNIQUE_REGISTRY.items():
        assert cls.emulation_only is True, f"{tid}: emulation_only must be True"


def test_all_have_technique_id():
    for tid, cls in TECHNIQUE_REGISTRY.items():
        assert hasattr(cls, "technique_id"), f"{tid}: missing technique_id"
        assert cls.technique_id, f"{tid}: technique_id must not be empty"


def test_all_have_tactic():
    for tid, cls in TECHNIQUE_REGISTRY.items():
        assert hasattr(cls, "tactic"), f"{tid}: missing tactic"
        assert cls.tactic, f"{tid}: tactic must not be empty"


def test_get_technique_returns_class():
    cls = get_technique("T1046")
    assert cls is not None
    assert issubclass(cls, Technique)


def test_get_technique_unknown_returns_none():
    assert get_technique("T9999") is None


def test_list_technique_ids_is_sorted():
    ids = list_technique_ids()
    assert ids == sorted(ids)


def test_expected_techniques_registered():
    expected = {
        "T1046", "T1087.002", "T1069.002", "T1482",
        "T1566.001", "T1566.002", "T1566",
        "T1110.003", "T1110.004", "T1621", "T1528", "T1539",
    }
    registered = set(TECHNIQUE_REGISTRY.keys())
    missing = expected - registered
    assert not missing, f"Expected techniques not registered: {missing}"
