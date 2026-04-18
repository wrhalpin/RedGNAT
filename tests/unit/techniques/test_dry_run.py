"""
Verify that ALL techniques return DRY_RUN status when scope.dry_run=True.
This is a safety regression test — it must always pass.
"""
from __future__ import annotations

import pytest

from redgnat.orm.models import ResultStatus
from redgnat.techniques.base import Scope, TechniqueContext
from redgnat.techniques.registry import TECHNIQUE_REGISTRY


def make_dry_run_ctx(technique_id: str) -> TechniqueContext:
    return TechniqueContext(
        run_id="dry-run-test",
        scenario_id="dry-scenario",
        feed_id="dry-feed",
        scope=Scope(
            target_ranges=["192.168.1.0/24"],
            target_domains=["example.com"],
            target_accounts=["test@example.com"],
            max_rate_per_minute=60,
            dry_run=True,
        ),
        params={
            # MFA fatigue requires explicit confirmation even in dry-run
            "confirm_mfa_fatigue_test": True,
            "password": "TestPass123!",
        },
    )


@pytest.mark.parametrize("technique_id,cls", TECHNIQUE_REGISTRY.items())
def test_dry_run_returns_dry_run_status(technique_id: str, cls):
    """Every registered technique must return DRY_RUN when scope.dry_run=True."""
    technique = cls()
    ctx = make_dry_run_ctx(technique_id)
    result = technique.execute(ctx)
    assert result.status == ResultStatus.DRY_RUN, (
        f"Technique {technique_id} ({cls.__name__}) did not return DRY_RUN "
        f"when scope.dry_run=True. Got: {result.status}. "
        "This is a safety violation — fix the technique to check scope.dry_run first."
    )
