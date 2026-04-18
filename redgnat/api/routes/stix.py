"""STIX export routes — consumed by the GNAT RedGNATConnector plugin."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["stix"])


def _get_client() -> Any:
    from redgnat.client import RedGNATClient
    return RedGNATClient()


@router.get("/stix/results")
async def list_stix_results() -> list[dict]:
    """
    Return all emulation run results as STIX 2.1 CourseOfAction objects.
    Consumed by the GNAT RedGNATConnector plugin.
    """
    client = _get_client()
    store = client._get_store()
    runs = client.list_runs()
    coa_objects = []
    for run in runs:
        scenario = client.get_scenario(run.scenario_id)
        if not scenario:
            continue
        results = store.list_results(run.run_id)
        coa_objects.append(_run_to_stix_coa(run, scenario, results))
    return coa_objects


@router.get("/stix/results/{run_id}")
async def get_stix_result(run_id: str) -> dict:
    client = _get_client()
    run = client.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")
    scenario = client.get_scenario(run.scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Parent scenario not found")
    store = client._get_store()
    results = store.list_results(run_id)
    return _run_to_stix_coa(run, scenario, results)


@router.get("/stix/sightings")
async def list_stix_sightings() -> list[dict]:
    """Return all TechniqueResults as STIX 2.1 Sighting objects."""
    client = _get_client()
    store = client._get_store()
    sightings = []
    for run in client.list_runs():
        for result in store.list_results(run.run_id):
            sightings.append(result.to_stix_sighting())
    return sightings


def _run_to_stix_coa(run: Any, scenario: Any, results: list[Any]) -> dict:
    from datetime import datetime, timezone

    status_counts = {}
    for r in results:
        status_counts[r.status.value] = status_counts.get(r.status.value, 0) + 1

    return {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": f"course-of-action--{run.run_id}",
        "created": (run.started_at or datetime.now(timezone.utc)).isoformat(),
        "modified": (run.completed_at or datetime.now(timezone.utc)).isoformat(),
        "name": f"CART Run: {scenario.name}",
        "description": (
            f"Automated red team emulation run. "
            f"Techniques: {len(results)}. "
            f"Status breakdown: {status_counts}"
        ),
        "x_redgnat_metadata": {
            "run_id": run.run_id,
            "scenario_id": run.scenario_id,
            "feed_id": scenario.feed_id,
            "status": run.status.value,
            "triggered_by": run.triggered_by,
            "technique_results": status_counts,
        },
    }
