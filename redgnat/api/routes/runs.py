"""Run query routes — GET /runs, GET /runs/{run_id}."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

router = APIRouter(tags=["runs"])


def _get_client() -> Any:
    from redgnat.client import RedGNATClient
    return RedGNATClient()


@router.get("/runs")
async def list_runs(scenario_id: str | None = Query(None)) -> list[dict]:
    client = _get_client()
    return [r.to_dict() for r in client.list_runs(scenario_id=scenario_id)]


@router.get("/runs/{run_id}")
async def get_run(run_id: str) -> dict:
    client = _get_client()
    run = client.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")
    return run.to_dict()


@router.get("/runs/{run_id}/results")
async def get_run_results(run_id: str) -> list[dict]:
    client = _get_client()
    store = client._get_store()
    results = store.list_results(run_id)
    return [r.to_dict() for r in results]


@router.get("/runs/{run_id}/report")
async def get_run_report(run_id: str) -> dict:
    from redgnat.reports.cart_report import CARTReport

    client = _get_client()
    store = client._get_store()

    run = client.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")

    scenario = client.get_scenario(run.scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Parent scenario not found")

    results = store.list_results(run_id)
    report = CARTReport(scenario, run, results)
    return report.full_report_dict()
