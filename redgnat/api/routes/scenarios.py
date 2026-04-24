# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Scenario management routes — GET/POST /scenarios."""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Body, HTTPException

logger = logging.getLogger(__name__)
router = APIRouter(tags=["scenarios"])


def _get_client() -> Any:
    from redgnat.client import RedGNATClient
    return RedGNATClient()


@router.get("/scenarios")
async def list_scenarios() -> list[dict]:
    """List all emulation scenarios."""
    client = _get_client()
    return [s.to_dict() for s in client.list_scenarios()]


@router.get("/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str) -> dict:
    """Return a single EmulationScenario by ID."""
    client = _get_client()
    scenario = client.get_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail=f"Scenario {scenario_id!r} not found")
    return scenario.to_dict()


@router.post("/scenarios/{scenario_id}/run")
async def trigger_run(scenario_id: str, body: dict = Body(default={})) -> dict:
    """
    Enqueue or synchronously execute a scenario run.

    Optional investigation-context body fields:

        investigation_id       — GNAT investigation ID to validate.
        hypothesis_id          — Specific GNAT Hypothesis to scope this run to.
        investigation_tenant_id — GNAT tenant for multi-tenant deployments.

    When ``hypothesis_id`` is provided, RedGNAT calls GNAT to verify it belongs
    to the investigation. If validation fails a 400 is returned. If GNAT is
    unreachable the run is accepted with ``investigation_validation_pending=true``.
    """
    client = _get_client()
    triggered_by = body.get("triggered_by", "manual")
    async_ = body.get("async", True)

    investigation_id: str | None = body.get("investigation_id") or None
    hypothesis_id: str | None = body.get("hypothesis_id") or None
    investigation_tenant_id: str | None = body.get("investigation_tenant_id") or None
    validation_pending = False

    if hypothesis_id and investigation_id:
        base_url = client.config.gnat_api_base_url
        api_key = client.config.gnat_api_key
        if base_url:
            from redgnat.feedback.investigation_context import validate_hypothesis

            valid, message = validate_hypothesis(
                base_url, api_key, investigation_id, hypothesis_id
            )
            if valid is False:
                raise HTTPException(status_code=400, detail=message)
            if valid is None:
                logger.warning(
                    "trigger_run: hypothesis validation pending for run "
                    "(investigation=%s, hypothesis=%s): %s",
                    investigation_id,
                    hypothesis_id,
                    message,
                )
                validation_pending = True
        else:
            logger.debug(
                "trigger_run: gnat.api_base_url not configured — "
                "skipping hypothesis validation for investigation %s",
                investigation_id,
            )

    try:
        run = client.run_scenario(
            scenario_id,
            triggered_by=triggered_by,
            async_=async_,
            investigation_id=investigation_id,
            hypothesis_id=hypothesis_id,
            investigation_tenant_id=investigation_tenant_id,
            investigation_validation_pending=validation_pending,
        )
        return run.to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
