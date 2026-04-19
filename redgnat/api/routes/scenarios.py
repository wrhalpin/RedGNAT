"""Scenario management routes — GET/POST /scenarios."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, HTTPException

router = APIRouter(tags=["scenarios"])


def _get_client() -> Any:
    from redgnat.client import RedGNATClient
    return RedGNATClient()


@router.get("/scenarios")
async def list_scenarios() -> list[dict]:
    client = _get_client()
    return [s.to_dict() for s in client.list_scenarios()]


@router.get("/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str) -> dict:
    client = _get_client()
    scenario = client.get_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail=f"Scenario {scenario_id!r} not found")
    return scenario.to_dict()


@router.post("/scenarios/{scenario_id}/run")
async def trigger_run(scenario_id: str, body: dict = Body(default={})) -> dict:
    client = _get_client()
    triggered_by = body.get("triggered_by", "manual")
    async_ = body.get("async", True)
    try:
        run = client.run_scenario(
            scenario_id, triggered_by=triggered_by, async_=async_
        )
        return run.to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
